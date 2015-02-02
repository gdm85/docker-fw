package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gdm85/go-dockerclient"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func getBackupHostConfigFileName(cid string) string {
	return fmt.Sprintf("/var/lib/docker/containers/%s/backupHostConfig.json", cid)
}

//NOTE: containre must be running for this to work
func BackupHostConfig(containerIds []string, mergeNetworkSettings, failOnChange bool) error {
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
				// normalize
				if origHostConfig.RestartPolicy.Name == "" {
					origHostConfig.RestartPolicy = docker.NeverRestart()
				}

				// proceed to validate that nothing relevant changed since last execution time
				//NOTE: this might easily be an insufficient test if new options are added

				if !asGoodAs(origHostConfig, container.HostConfig) {
					return errors.New(fmt.Sprintf("Container %s has inconsistently changed host configuration", container.ID))
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

func updateHosts(c *docker.Container, ch []string) error {
	result, err := containerExec(c.ID, []string{"cat", "/etc/hosts"})
	if err != nil {
		return err
	}

	if result.ExitCode != 0 {
		return errors.New(fmt.Sprintf("Could not read /etc/hosts in container '%s': %s", c.Name[1:], result.Stderr))
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
				return err
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
			return err
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
			return err
		}
	}

	return nil
}
