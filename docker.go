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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gdm85/go-dockerclient"
	"io/ioutil"
	"os"
	"sort"
)

var Docker *docker.Client

func init() {
	var err error
	Docker, err = docker.NewClient("unix:///var/run/docker.sock")
	if err != nil {
		panic(err)
	}
}

func getBackupHostConfigFileName(cid string) string {
	return fmt.Sprintf("/var/lib/docker/containers/%s/backupHostConfig.json", cid)
}

func areEquivalentArrays(a, b []string) bool {
	if a == nil && a == nil {
		return true
	}

	if len(a) != len(b) {
		return false
	}

	sort.Strings(a)
	sort.Strings(b)

	// compare each element
	l := len(a)
	for i := 0; i < l; i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func arePortBindingsEqual(a, b map[docker.Port][]docker.PortBinding) bool {
	if a == nil && b == nil {
		return true
	}

	if len(a) != len(b) {
		return false
	}

	// retrieve keys & convert each binding to a string, for ease of comparison
	aKeys := []string{}
	aValues := map[string][]string{}
	for key, value := range a {
		aKeys = append(aKeys, string(key))

		serialized := []string{}
		for _, binding := range value {
			serialized = append(serialized, binding.HostIP+":"+binding.HostPort)
		}

		aValues[string(key)] = serialized
	}

	bKeys := []string{}
	bValues := map[string][]string{}
	for key, value := range b {
		bKeys = append(bKeys, string(key))

		serialized := []string{}
		for _, binding := range value {
			serialized = append(serialized, binding.HostIP+":"+binding.HostPort)
		}

		bValues[string(key)] = serialized
	}

	// keys must match
	if !areEquivalentArrays(aKeys, bKeys) {
		return false
	}

	// then traverse through the common keys to check if values match
	for key, _ := range a {
		if !areEquivalentArrays(aValues[string(key)], bValues[string(key)]) {
			return false
		}
	}

	return true
}

func asGoodAs(orig *docker.HostConfig, current *docker.HostConfig) bool {
	return orig.NetworkMode == current.NetworkMode &&
		areEquivalentArrays(orig.Links, current.Links) &&
		areEquivalentArrays(orig.DNS, current.DNS) &&
		areEquivalentArrays(orig.DNSSearch, current.DNSSearch) &&
		areEquivalentArrays(orig.ExtraHosts, current.ExtraHosts) &&
		areEquivalentArrays(orig.VolumesFrom, current.VolumesFrom) &&
		areEquivalentArrays(orig.Binds, current.Binds) &&
		areEquivalentArrays(orig.CapAdd, current.CapAdd) &&
		areEquivalentArrays(orig.CapDrop, current.CapDrop) &&
		orig.PublishAllPorts == current.PublishAllPorts &&
		orig.RestartPolicy.Name == current.RestartPolicy.Name &&
		orig.Privileged == current.Privileged &&
		orig.PublishAllPorts == current.PublishAllPorts &&
		arePortBindingsEqual(orig.PortBindings, current.PortBindings)
}

//NOTE: containre must be running for this to work
func BackupHostConfig(containerIds []string, failOnChange bool) error {
	for _, userCid := range containerIds {
		container, err := ccl.LookupOnlineContainer(userCid)
		if err != nil {
			return err
		}

		if !container.State.Running {
			return errors.New(fmt.Sprintf("Container %s does is not running", container.ID))
		}

		// validate that nothing relevant has changed
		if failOnChange {
			origHostConfig, err := fetchSavedHostConfig(container.ID)
			if err != nil {
				return err
			}

			if origHostConfig != nil {
				// proceed to validate that nothing relevant changed since last execution time
				//NOTE: this might not be a good check anymore, depending on the feature set changes

				if !asGoodAs(origHostConfig, container.HostConfig) {
					return errors.New(fmt.Sprintf("Container %s has inconsistently changed host configuration", container.ID))
				}
			}
		}

		err = saveHostConfig(container.ID, container.HostConfig)
		if err != nil {
			return err
		}
	}

	return nil
}

func saveHostConfig(cid string, hostConfig *docker.HostConfig) error {
	bytes, err := json.Marshal(hostConfig)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(getBackupHostConfigFileName(cid), bytes, 0666)
	return err
}

func fetchSavedHostConfigAsBytes(id string) ([]byte, error) {
	fileName := getBackupHostConfigFileName(id)

	_, err := os.Stat(fileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		// nothing found, and no error either
		return nil, nil
	}

	// read only when existing
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func fetchSavedHostConfig(id string) (*docker.HostConfig, error) {
	hostConfig := docker.HostConfig{}
	bytes, err := fetchSavedHostConfigAsBytes(id)
	if err != nil {
		return nil, err
	}

	// nothing found
	if bytes == nil {
		return nil, nil
	}

	err = json.Unmarshal(bytes, &hostConfig)
	if err != nil {
		return nil, err
	}

	return &hostConfig, nil
}
