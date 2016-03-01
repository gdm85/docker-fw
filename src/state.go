/*
 * docker-fw v0.2.4 - a complementary tool for Docker to manage custom
 * 					  firewall rules between/towards Docker containers
 * Copyright (C) 2014~2016 gdm85 - https://github.com/gdm85/docker-fw/

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
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/fsouza/go-dockerclient"
)

func getBackupHostConfigFileName(cid string) string {
	return fmt.Sprintf("/var/lib/docker/containers/%s/backupHostConfig.json", cid)
}

//NOTE: container must be running in order for this to be working
func BackupHostConfig(containerIds []string, mergeNetworkSettings, failOnChange bool) error {
	for _, userCid := range containerIds {
		container, err := ccl.LookupOnlineContainer(userCid)
		if err != nil {
			return err
		}

		if !container.State.Running {
			return errors.New(fmt.Sprintf("Container %s is not running", container.Name[1:]))
		}

		// validate that nothing relevant has changed
		if failOnChange {
			origHostConfig, err := fetchSavedHostConfig(container.ID)
			if err != nil {
				return err
			}

			if origHostConfig != nil {
				// normalize
				if origHostConfig.RestartPolicy.Name == "" {
					origHostConfig.RestartPolicy = docker.NeverRestart()
				}

				// proceed to validate that nothing relevant changed since last execution time
				//NOTE: this might easily be an insufficient test when new options are added upstream
				if !asGoodAs(origHostConfig, container.HostConfig) {
					return errors.New(fmt.Sprintf("Container %s has inconsistently changed host configuration", container.Name[1:]))
				}
			}
		}

		err = backupHostConfig(container, mergeNetworkSettings)
		if err != nil {
			return err
		}
	}

	return nil
}

func backupHostConfig(container *docker.Container, mergeNetworkSettings bool) error {
	var origPortBindings map[docker.Port][]docker.PortBinding
	if mergeNetworkSettings {
		origPortBindings = container.HostConfig.PortBindings

		container.HostConfig.PortBindings = container.NetworkSettings.Ports
	}

	bytes, err := json.Marshal(container.HostConfig)
	if mergeNetworkSettings {
		container.HostConfig.PortBindings = origPortBindings
	}
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(getBackupHostConfigFileName(container.ID), bytes, 0666)
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
		log.Printf("Could not unmarshal host config '%s'", string(bytes))
		return nil, err
	}

	return &hostConfig, nil
}

// read existing rules (if any)
func LoadRules(container *docker.Container) (*IptablesRulesCollection, error) {
	c := IptablesRulesCollection{cid: container.ID}

	_, err := os.Stat(c.fileName())
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		// file does not exist, no problem, allow fallback to 'return nil'

	} else {
		// read only when existing
		bytes, err := ioutil.ReadFile(c.fileName())
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(bytes, &c)
		if err != nil {
			log.Printf("Could not unmarshal iptables rules '%s'", string(bytes))
			return nil, err
		}
	}

	return &c, nil
}

func getCustomHostsFileName(c *docker.Container) string {
	return fmt.Sprintf("/var/lib/docker/containers/%s/customHosts.json", c.ID)
}

func LoadCustomHosts(container *docker.Container) ([]string, error) {
	_, err := os.Stat(getCustomHostsFileName(container))
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		// file does not exist, no problem
		return []string{}, nil
	}
	// read only when existing
	bytes, err := ioutil.ReadFile(getCustomHostsFileName(container))
	if err != nil {
		return nil, err
	}

	ch := []string{}
	err = json.Unmarshal(bytes, &ch)
	if err != nil {
		log.Printf("Could not unmarshal custom hosts '%s'", string(bytes))
		return nil, err
	}
	return ch, nil
}

func saveCustomHosts(c *docker.Container, ch []string) error {
	bytes, err := json.Marshal(&ch)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(getCustomHostsFileName(c), bytes, 0666)
	return err
}

func inArray(a []string, needle string) bool {
	for _, e := range a {
		if e == needle {
			return true
		}
	}
	return false
}

func updateCustomHosts(target, b string) error {
	container, err := ccl.LookupOnlineContainer(target)
	if err != nil {
		return err
	}
	ch, err := LoadCustomHosts(container)
	if err != nil {
		return err
	}

	bContainer, err := ccl.LookupOnlineContainer(b)
	if err != nil {
		return err
	}

	found := inArray(ch, bContainer.Name[1:])

	if !found {
		ch = append(ch, bContainer.Name[1:])
	}

	// in any case, update the live hosts file of target
	err = updateHosts(container, ch)
	if err != nil {
		return err
	}

	// save only if it was not already there
	if !found {
		err = saveCustomHosts(container, ch)
		if err != nil {
			return err
		}
	}

	return nil
}

func reapplyCustomHosts(target string) error {
	container, err := ccl.LookupOnlineContainer(target)
	if err != nil {
		return err
	}
	ch, err := LoadCustomHosts(container)
	if err != nil {
		return err
	}

	if len(ch) == 0 {
		return nil
	}

	// update the live hosts file of target
	err = updateHosts(container, ch)
	if err != nil {
		return err
	}

	return nil
}

func restorePaused(c *docker.Container, paused bool, origErr error) error {
	if paused {
		err := Docker.PauseContainer(c.ID)
		if err != nil {
			return fmt.Errorf("%s\nadditionally, an error while re-pausing container: %s", origErr, err)
		}
	}
	return origErr
}

func updateHosts(c *docker.Container, ch []string) error {
	// In order to exec successfully within the container, we must unpause it if it were paused
	// although nsenter has not such limitation, for some reason it is enforced by Docker,
	// thus here docker-fw complies by first unpausing the container and then re-pausing it.
	// The net result is that - whatsoever your experiments tell you - you should never relay on two-ways containers
	// being reachable during any of your initialization in CMD/ENTRYPOINT commands.
	// This could be better handled by directly modifying the hosts file even before container is started,
	// but it would be using undocumented features.
	wasPaused := false
	if c.State.Paused {
		err := Docker.UnpauseContainer(c.ID)
		if err != nil {
			return err
		}
		wasPaused = true
	}

	result, err := containerExec(c.ID, []string{"cat", "/etc/hosts"})
	if err != nil {
		return restorePaused(c, wasPaused, err)
	}

	if result.ExitCode != 0 {
		err := errors.New(fmt.Sprintf("Could not read /etc/hosts in container '%s': %s", c.Name[1:], result.Stderr))
		return restorePaused(c, wasPaused, err)
	}

	// read existing hosts
	hasHostsChanges := false
	rewrittenLines := []string{}
	okContainers := []string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)

		if len(line) == 0 || line[0] == '#' {
			rewrittenLines = append(rewrittenLines, line)
			continue
		}

		// get all fields, although most of them will have only 2
		fields := strings.Fields(line)

		// scan for matches with specified custom hosts
		removeFields := []string{}
		for _, cid := range ch {
			container, err := ccl.LookupOnlineContainer(cid)
			if err != nil {
				return restorePaused(c, wasPaused, err)
			}
			for _, field := range fields[1:] {
				if field == container.Name[1:] {
					if fields[0] != container.NetworkSettings.IPAddress {
						// needs an update, IPv4 changed
						removeFields = append(removeFields, field)
						break
					} else {
						// if a container is not in this array it will always trigger addition of a new /etc/hosts line
						if !inArray(okContainers, field) {
							okContainers = append(okContainers, field)
						}
					}
				}
			}
		}

		if len(removeFields) > 0 {
			// filter out all fields to be removed
			newFields := []string{fields[0]}
			for _, field := range fields[1:] {
				if !inArray(removeFields, field) {
					newFields = append(newFields, field)
				}
			}

			// if there is only 1 field (IP), discard, otherwise add the new line
			// containers without a match will be added later anyway
			if len(newFields) == 1 {
				continue
			}

			fmt.Printf("docker-fw: add-two-ways: updated hosts line for (%s) in container '%s'\n", strings.Join(removeFields, ", "), c.Name[1:])
			rewrittenLines = append(rewrittenLines, strings.Join(newFields, "\t"))
			hasHostsChanges = true
		} else {
			// preserve original line, since no change happened
			rewrittenLines = append(rewrittenLines, line)
		}
	}

	// add new hosts lines
	for _, host := range ch {
		container, err := ccl.LookupOnlineContainer(host)
		if err != nil {
			return restorePaused(c, wasPaused, err)
		}
		if !inArray(okContainers, container.Name[1:]) {
			rewrittenLines = append(rewrittenLines, fmt.Sprintf("%s\t%s", container.NetworkSettings.IPAddress, container.Name[1:]))
			fmt.Printf("docker-fw: add-two-ways: added hosts line for '%s' in container '%s'\n", container.Name[1:], c.Name[1:])
			hasHostsChanges = true
		}
	}

	// write new hosts file (as needed)
	if hasHostsChanges {
		err := containerInject(c.ID, "/etc/hosts", strings.Join(rewrittenLines, "\n")+"\n")
		if err != nil {
			return restorePaused(c, wasPaused, err)
		}
	}

	return restorePaused(c, wasPaused, nil)
}
