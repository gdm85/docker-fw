/*
 * docker-fw v0.1.0 - a complementary tool for Docker to manage custom
 * 					  firewall rules between/towards Docker containers
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
	ParentOf SortableNodeArray
	Started  bool
}

type SortableNodeArray []*Node

func (s SortableNodeArray) Len() int {
	return len(s)
}

func (s SortableNodeArray) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// inverted sort order, to sort for biggest to smallest
func (s SortableNodeArray) Less(i, j int) bool {
	return !s.realLess(i, j)
}

func (s SortableNodeArray) realLess(i, j int) bool {
	// first check if there is a parent/child relationship
	// children leave room for parents
	// a container that is used by another is a parent
	if s[i].ParentOf.Contains(s[j]) {
		return false
	}
	if s[j].ParentOf.Contains(s[i]) {
		return true
	}

	//NOTE: if Docker allows two-ways links, the above won't sort!

	// when no relationship is estabilished, then just sort by number of other relationships
	// will be undetermined in case of 0
	return len(s[i].ParentOf) < len(s[j].ParentOf)
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

func recurseStart(nodes []*Node, paused bool) error {
	// proceed to start all nodes
	for _, node := range nodes {
		// skip already-started nodes, possible when a node is used by multiple nodes
		if node.Started {
			continue
		}

		changedState := false
		// start container
		if !node.Self.State.Running {
			err := Docker.StartContainer(node.Self.ID, nil)
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

		// mark as started and disable further access
		node.Self = nil
		node.Started = true

		// recurse into children
		err = recurseStart(node.ParentOf, paused)
		if err != nil {
			return err
		}
	}
	return nil
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

	// traverse the containers list identifying children|parent relationships
	graph := make(map[string]*Node, 0)
	for _, container := range containers {

		for _, link := range container.HostConfig.Links {
			parts := strings.SplitN(link, ":", 2)

			// prepare container node itself
			node, ok := graph[container.ID]
			if !ok {
				node = &Node{
					Self: container,
				}

				graph[container.ID] = node
			}

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

			targetNode, ok := graph[linkTarget]
			if !ok {
				targetNode = &Node{
					Self: targetContainer,
				}

				graph[linkTarget] = targetNode
			}

			// now create the reverse 1-way association
			targetNode.ParentOf = append(targetNode.ParentOf, node)
		}
	}

	// convert the map to a flat array
	var nodes SortableNodeArray
	for _, v := range graph {
		nodes = append(nodes, v)
	}

	// sort by dependencies/links number
	sort.Sort(nodes)

	err := recurseStart(nodes, paused)

	return err
}
