/*
 * docker-fw v0.2.0 - a complementary tool for Docker to manage custom
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
	"strings"
)

func arrayContains(haystack []*docker.Container, needle *docker.Container) bool {
	for _, b := range haystack {
		// we are not comparing the pointer itself because a dynamic update to stored container reference is potentially possible
		if b.ID == needle.ID {
			return true
		}
	}
	return false
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

	// build the sortable graph of nodes and their link dependencies
	lookup := map[string]*Node{}
	for _, container := range containers {

		// prepare container node itself
		node, ok := lookup[container.ID]
		if !ok {
			node = NewNode(container)
			lookup[container.ID] = node
		}

		for _, link := range container.HostConfig.Links {
			parts := strings.SplitN(link, ":", 2)

			// identify the target container
			linkName := parts[0][1:]
			linkContainer, err := ccl.LookupContainer(linkName)
			if err != nil {
				return err
			}

			// error if a container is missing from selection and no --pull-deps was specified
			if !pullDeps {
				if !arrayContains(containers, linkContainer) {
					return errors.New(fmt.Sprintf("container '%s' is not specified in list and no --pull-deps specified", linkName))
				}
			}

			linkNode, ok := lookup[linkContainer.ID]
			if !ok {
				linkNode = NewNode(linkContainer)

				lookup[linkContainer.ID] = linkNode
			}

			// now create association
			linkNode.LinkTo(node)
		}

		// now also check dependencies created by volumes
		for _, volumesProvider := range container.HostConfig.VolumesFrom {

			// identify the provider container
			volsContainer, err := ccl.LookupContainer(volumesProvider)
			if err != nil {
				return err
			}

			// error if a container is missing from selection and no --pull-deps was specified
			if !pullDeps {
				if !arrayContains(containers, volsContainer) {
					return errors.New(fmt.Sprintf("container '%s' (volumes provider) is not specified in list and no --pull-deps specified", volsContainer.Name[1:]))
				}
			}

			volsNode, ok := lookup[volsContainer.ID]
			if !ok {
				volsNode = NewNode(volsContainer)

				lookup[volsContainer.ID] = volsNode
			}

			// now create association
			volsNode.LinkTo(node)
		}
	}

	// convert the map to a flat array
	var allNodes SortableNodeArray
	for _, v := range lookup {
		allNodes = append(allNodes, v)
	}

	// apply topological sort
	allNodes = allNodes.TopSort()

	if dryRun {
		for _, node := range allNodes {
			fmt.Println(node.Name)
		}

		return nil
	}

	for _, node := range allNodes {
		// always get latest version, since state might have changed
		container, err := ccl.LookupContainer(node.ID)
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
			container, err = ccl.LookupContainer(node.ID)
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
	// NOTE: will fail if any change is detected
	err := BackupHostConfig(normalizedIds, true, true)
	if err != nil {
		return err
	}

	///
	/// split start from rules application due to glitch/bug (see https://github.com/docker/docker/issues/10188)
	///

	// always run the 'replay' action
	err = ReplayRules(normalizedIds)
	if err != nil {
		return err
	}

	return err
}