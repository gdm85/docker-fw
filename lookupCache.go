/*
 * docker-fw v0.2.2 - a complementary tool for Docker to manage custom
 * 					  firewall rules between/towards Docker containers
 * Copyright (C) 2014-2015 gdm85 - https://github.com/gdm85/docker-fw/

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

type CachedContainerLookup struct {
	containers map[string]*docker.Container

	// lookup by network address
	networkAddress map[string]*docker.Container

	// used only once to pre-fill cache with all existing containers
	loadedAll bool
}

func (ccl *CachedContainerLookup) GetAllContainers() []*docker.Container {
	lookupByPtr := map[*docker.Container]bool{}
	for _, container := range ccl.containers {
		// overwrite without fear, as no multiple container pointers are at any time being used
		// and this prevents duplicates here
		lookupByPtr[container] = true
	}

	// get the values
	containers := []*docker.Container{}
	for p, _ := range lookupByPtr {
		containers = append(containers, p)
	}

	return containers
}

func (ccl *CachedContainerLookup) lookupInternal(cid string, mustBeOnline bool) (*docker.Container, error) {
	if len(cid) == 0 {
		panic("empty container id passed to lookupInternal")
	}

	if container, ok := ccl.containers[cid]; !ok {
		if ccl.loadedAll {
			return nil, errors.New("container not found in fully preloaded cache: " + cid)
		}

		err := ccl.fullRefreshContainer(cid, mustBeOnline)
		if err != nil {
			return nil, err
		}
	} else {
		// always perform check if container is online, also when returning a cached result
		if mustBeOnline {
			if container.NetworkSettings.IPAddress == "" {
				return nil, errors.New(fmt.Sprintf("Container %s does not have a valid IPv4 address", container.ID))
			}
		}
	}

	return ccl.containers[cid], nil
}

func (ccl *CachedContainerLookup) fullRefreshContainer(id string, mustBeOnline bool) error {
	// pull new inspect data from API
	container, err := Docker.InspectContainer(id)
	if err != nil {
		return err
	}

	ccl.containers[container.ID] = container

	// add also non-standard alias or name
	if id != container.ID && id != container.Name {
		ccl.containers[id] = container
	}

	if mustBeOnline {
		containerIpv4 := container.NetworkSettings.IPAddress
		if containerIpv4 == "" {
			return errors.New(fmt.Sprintf("Container %s does not have a valid IPv4 address", id))
		}

		//NOTE: status will necessarily be desynchronized from what container is doing meanwhile program runs
		// thus program should update 'networkAddress' lookup in case of status manipulation actions (e.g. 'start')
		ccl.networkAddress[containerIpv4] = container
	}
	ccl.containers[container.Name[1:]] = container

	return nil
}

func (ccl *CachedContainerLookup) RefreshContainer(cid string, mustBeOnline bool) error {
	// update the entry (forced, no cache applies)
	err := ccl.fullRefreshContainer(cid, mustBeOnline)
	if err != nil {
		return err
	}

	// find all containers that are referenced with a different version of the id
	var toReMap []string
	for id, container := range ccl.containers {
		// this is a special alias e.g. shorter id or whatever else resolves to the container through API
		if container.ID == id {
			toReMap = append(toReMap, id)
			continue
		}
	}

	// remap using the most updated version that was retrieved
	for _, customId := range toReMap {
		ccl.containers[customId] = ccl.containers[ccl.containers[customId].ID]
	}

	return nil
}

func (ccl *CachedContainerLookup) LoadAllContainers() error {
	if ccl.loadedAll {
		return nil
	}

	containers, err := Docker.ListContainers(docker.ListContainersOptions{All: true})
	if err != nil {
		return err
	}

	// map all containers by their ID & name
	// will overwrite previous entries
	for _, containerSummary := range containers {
		err := ccl.fullRefreshContainer(containerSummary.ID, false)
		if err != nil {
			return err
		}
	}

	// find all containers that are referenced with a different version of the id
	var toReMap []string
	for id, container := range ccl.containers {
		// this is a special alias e.g. shorter id or whatever else resolves to the container through API
		if id != container.ID && id != container.Name[1:] {
			toReMap = append(toReMap, id)
			continue
		}
	}

	// remap using the most updated version that was retrieved
	for _, customId := range toReMap {
		ccl.containers[customId] = ccl.containers[ccl.containers[customId].ID]
	}

	// prevent loading any other entry for the whole program execution
	ccl.loadedAll = true

	return nil
}

func (ccl *CachedContainerLookup) LookupOnlineContainer(cid string) (*docker.Container, error) {
	return ccl.lookupInternal(cid, true)
}

// same as Lookup(), but does not check that container is up and running
func (ccl *CachedContainerLookup) LookupContainer(cid string) (*docker.Container, error) {
	return ccl.lookupInternal(cid, false)
}

// returns name of the aliased container
func unAlias(container *docker.Container, alias string) (string, error) {
	if alias == "." {
		return container.Name[1:], nil
	}
	aliasedContainer, err := ccl.LookupContainer(alias)
	if err != nil {
		return "", err
	}
	return aliasedContainer.Name[1:], nil
}

func (ccl *CachedContainerLookup) FindContainerByNetworkAddress(ipv4 string) (*docker.Container, error) {
	if !ccl.loadedAll {
		panic("Cannot lookup by network address if all entries have not been loaded")
	}

	container, ok := ccl.networkAddress[ipv4]
	if !ok {
		return nil, errors.New("address does not point to any container: " + ipv4)
	}

	return container, nil
}

func applySelfReduction(foundContainer *docker.Container, self *docker.Container) string {
	if foundContainer == self {
		return "."
	}
	return foundContainer.Name[1:]
}

// first return value is ipv4
// second return value is alias
// as aliases, names are preferred over IDs
func (ccl *CachedContainerLookup) ParseAddress(addressOrAlias string, self *docker.Container, parseContainerNames bool) (string, string, error) {
	switch addressOrAlias {
	case ".":
		return self.NetworkSettings.IPAddress + "/32", addressOrAlias, nil
	case "/":
		return DOCKER_HOST, addressOrAlias, nil
	default:
		// match an IPv4 with optional subnet
		res := matchIpv4.FindStringSubmatch(addressOrAlias)
		if len(res) != 0 {
			ipv4 := addressOrAlias
			if res[4] == "" {
				// add default subnet
				ipv4 += "/32"
			}

			// disallow specifying IPs in Docker subnet (unless specifically allowed)
			if isDockerIPv4(ipv4) && strings.HasSuffix(ipv4, "/32") {
				if !parseContainerNames {
					return "", "", errors.New("trying to use Docker IPv4, use an alias instead")
				}

				// load all containers - will use a cache
				err := ccl.LoadAllContainers()
				if err != nil {
					return "", "", err
				}

				container, err := ccl.FindContainerByNetworkAddress(ipv4[:strings.Index(ipv4, "/")])
				if err != nil {
					return "", "", err
				}

				// return the identified container name
				return ipv4, applySelfReduction(container, self), nil
			}

			// an ipv4 notation address, either single IPv4 or a subnet, not from a Docker container
			return ipv4, "", nil
		} else {
			// not an ipv4, try to match to a container name/id
			container, err := ccl.LookupOnlineContainer(addressOrAlias)
			if err != nil {
				return "", "", err
			}

			// resolved container id ipv4 and id itself
			return container.NetworkSettings.IPAddress + "/32", applySelfReduction(container, self), nil
		}
	}
	panic("unexpected exit point")
}
