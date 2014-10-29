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
	"github.com/fsouza/go-dockerclient"
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

func fixHostConfig(name string, orig *docker.HostConfig) *docker.HostConfig {
	newConfig := docker.HostConfig{
		Binds:           orig.Binds,
		CapAdd:          orig.CapAdd,
		CapDrop:         orig.CapDrop,
		ContainerIDFile: orig.ContainerIDFile,
		LxcConf:         orig.LxcConf,
		Privileged:      orig.Privileged,
		PortBindings:    orig.PortBindings,
		PublishAllPorts: orig.PublishAllPorts,
		Dns:             orig.Dns,
		DnsSearch:       orig.DnsSearch,
		ExtraHosts:      orig.ExtraHosts,
		VolumesFrom:     orig.VolumesFrom,
		NetworkMode:     orig.NetworkMode,
		RestartPolicy:   orig.RestartPolicy,
	}

	// normalize
	if newConfig.RestartPolicy.Name == "" {
		newConfig.RestartPolicy = docker.NeverRestart()
	}

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
		newConfig.Links = append(newConfig.Links, fmt.Sprintf("%s:%s", parts[0], parts[1]))
	}

	return &newConfig
}

// 1) build a graph of container dependencies
// 2) start them from lowest to highest dependency count
// 3) for each container start, pause them (if asked to)
// 4) for each container start, run the 'replay' action too
func StartContainers(containerIds []string, paused, pullDeps bool) error {
	// first normalize all container ids to the proper 'ID' property given through inspect
	// this is necessary because we won't allow to start dependant containers if not specified
	var containers []*docker.Container
	for _, cid := range containerIds {
		container, err := ccl.LookupInert(cid)
		if err != nil {
			return err
		}

		containers = append(containers, container)
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
			targetContainer, err := ccl.LookupInert(linkTarget)
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

	dryRun := false

	for i := len(result.Leaves) - 1; i >= 0; i-- {
		node := result.Leaves[i]
		if dryRun {
			fmt.Printf("%s\n", node.Self.Name[1:])
			continue
		}
		changedState := false
		// start container
		if !node.Self.State.Running {
			hostConfig := fixHostConfig(node.Self.Name, node.Self.HostConfig)

			// use last known host configuration
			err := Docker.StartContainer(node.Self.ID, hostConfig)
			if err != nil {
				return err
			}
			changedState = true
		}

		if paused {
			if !node.Self.State.Paused {
				err := Docker.PauseContainer(node.Self.ID)
				if err != nil {
					return err
				}
			}
			changedState = true
		}

		if changedState {
			// enforce here container to be online
			err := ccl.RefreshContainer(node.Self.ID, true)
			if err != nil {
				return err
			}
		}

		// always run the 'replay' action
		err := ReplayRules([]string{node.Self.ID})
		if err != nil {
			return err
		}
	}

	return err
}
