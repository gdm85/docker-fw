/*
 * docker-fw v0.1.0 - a complementary tool for Docker to manage custom
 *                    firewall rules between/towards Docker containers
 * Copyright (C) 2014 gdm85 - https://github.com/gdm85/docker-fw/

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

package main

import (
	"errors"
	"fmt"
	"github.com/gdm85/go-dockerclient"
	"sort"
	"strings"
)

type Node struct {
	Self *docker.Container
	// all nodes that hierarchically come afterwards
	Leaves  SortableNodeArray
	Visited bool
}

type SortableNodeArray []*Node

func (s SortableNodeArray) Len() int {
	return len(s)
}

func (s SortableNodeArray) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SortableNodeArray) Less(i, j int) bool {
	// first check if there is a parent/leaf relationship
	if s[i].Leaves.Contains(s[j]) {
		return false
	}
	if s[j].Leaves.Contains(s[i]) {
		return true
	}

	//NOTE: if Docker allows two-ways links, the above won't sort!

	// when no relationship is estabilished, then just sort by number of other relationships
	// will be undetermined in case of 0
	return len(s[i].Leaves) < len(s[j].Leaves)
}

func (s SortableNodeArray) Contains(n *Node) bool {
	for _, v := range s {
		if v == n {
			return true
		}
	}
	return false
}

func arrayContains(haystack []*docker.Container, needle *docker.Container) bool {
	for _, b := range haystack {
		// we are not comparing the pointer itself because a dynamic update to stored container reference is potentially possible
		if b.ID == needle.ID {
			return true
		}
	}
	return false
}

func sortBeforeStart(result *Node, nodes []*Node) (*Node, error) {
	for _, node := range nodes {
		// skip already-started nodes, possible when a node is used by multiple nodes
		if node.Visited {
			continue
		}
		node.Visited = true
		result.Leaves = append(result.Leaves, node)

		// recurse dependencies
		_, err := sortBeforeStart(result, node.Leaves)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func wrapperDockerPause(container *docker.Container) error {
	err := Docker.PauseContainer(container.ID)
	if err != nil {
		return err
	}

	// this will enforce container to be online
	err = ccl.RefreshContainer(container.ID, true)

	return err
}

// this fix is necessary for an undocumented bug: you cannot feed back to API what you got it from regarding Links
func fixHostConfig(name string, orig *docker.HostConfig) {
	// normalize
	if orig.RestartPolicy.Name == "" {
		orig.RestartPolicy = docker.NeverRestart()
	}

	newLinks := []string{}

	// now add links
	for _, link := range orig.Links {
		parts := strings.SplitN(link, ":", 2)
		// remove prefix from second part and leading slash from first part
		if parts[0][0] != '/' || parts[1][0] != '/' {
			// something has changed in API, likely inconsistency fixed upstream
			panic("unexpected format of links")
		}
		parts[0] = parts[0][1:]
		parts[1] = parts[1][(len(name) + 1):]
		newLinks = append(newLinks, fmt.Sprintf("%s:%s", parts[0], parts[1]))
	}

	// replace new links
	orig.Links = newLinks
}

func wrapperDockerStart(container *docker.Container, ignoredStartPaused bool) error {
	hostConfig, err := fetchSavedHostConfig(container.ID)
	if err != nil {
		return err
	}

	if hostConfig == nil {
		return errors.New("No saved HostConfig found")
	}

	fixHostConfig(container.Name, hostConfig)

	// use last known host configuration
	err = Docker.StartContainer(container.ID, hostConfig)
	if err != nil {
		return err
	}

	// this will enforce container to be online
	err = ccl.RefreshContainer(container.ID, true)

	return err
}

// 1) build a graph of container dependencies
// 2) start them from lowest to highest dependency count
// 3) for each container start, pause them (if asked to)
// 4) when all containers have been started, run the 'replay' action for them
func StartContainers(containerIds []string, startPaused, pullDeps, dryRun bool) error {
	// first normalize all container ids to the proper 'ID' property given through inspect
	// this is necessary because we won't allow to start dependant containers if not specified
	var containers []*docker.Container
	normalizedIds := []string{}
	for _, cid := range containerIds {
		container, err := ccl.LookupContainer(cid)
		if err != nil {
			return err
		}

		containers = append(containers, container)
		normalizedIds = append(normalizedIds, container.ID)
	}

	// traverse the containers list identifying leaf|parent relationships
	graph := make(map[string]*Node, 0)
	for _, container := range containers {

		// prepare container node itself
		node, ok := graph[container.ID]
		if !ok {
			node = &Node{
				Self: container,
			}
			graph[container.ID] = node
		}

		for _, link := range container.HostConfig.Links {
			parts := strings.SplitN(link, ":", 2)

			// identify the target container
			linkTarget := parts[0][1:]
			targetContainer, err := ccl.LookupContainer(linkTarget)
			if err != nil {
				return err
			}

			// allow to pull in other containers only if specifically allowed to
			if !pullDeps {
				if !arrayContains(containers, targetContainer) {
					return errors.New(fmt.Sprintf("container '%s' is not specified in list and no --pull-deps specified", targetContainer.Name[1:]))
				}
			}

			targetNode, ok := graph[targetContainer.ID]
			if !ok {
				targetNode = &Node{
					Self: targetContainer,
				}

				graph[targetContainer.ID] = targetNode
			}

			// now create association
			targetNode.Leaves = append(targetNode.Leaves, node)
		}
	}

	// convert the map to a flat array
	var nodes SortableNodeArray
	for _, v := range graph {
		nodes = append(nodes, v)
	}

	// sort by dependencies/links number
	// order is: from least used to most used
	sort.Sort(nodes)

	var result Node
	_, err := sortBeforeStart(&result, nodes)
	if err != nil {
		return err
	}

	for i := len(result.Leaves) - 1; i >= 0; i-- {
		nonUpToDateNode := result.Leaves[i]
		if dryRun {
			fmt.Printf("%s\n", nonUpToDateNode.Self.Name[1:])
			continue
		}

		// always get latest version, since state might have changed
		container, err := ccl.LookupContainer(nonUpToDateNode.Self.ID)
		if err != nil {
			return err
		}

		// start container
		if !container.State.Running {
			err := wrapperDockerStart(container, startPaused)
			if err != nil {
				return err
			}

			// always get latest version, since state might have changed
			container, err = ccl.LookupContainer(nonUpToDateNode.Self.ID)
			if err != nil {
				return err
			}
		}

		if startPaused {
			if !container.State.Paused {
				//NOTE: container might already have been paused in command above
				err := wrapperDockerPause(container)
				if err != nil {
					return err
				}
			}
		}
	}

	// attempt to save again network rules
	// NOTE: will fail if there is any change detected
	err = BackupHostConfig(normalizedIds, true)
	if err != nil {
		return err
	}

	///
	/// split start from rules application due to glitch/bug (see https://github.com/docker/docker/issues/10188)
	///

	if !dryRun {
		for i := len(result.Leaves) - 1; i >= 0; i-- {
			node := result.Leaves[i]

			// always run the 'replay' action
			err := ReplayRules([]string{node.Self.ID})
			if err != nil {
				return err
			}
		}
	}

	return err
}
