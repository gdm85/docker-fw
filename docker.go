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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gdm85/go-dockerclient"
	"io/ioutil"
	"os"
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

//NOTE: containre must be running for this to work
func BackupHostConfig(containerIds []string, failOnChange bool) error {
	for _, cid := range containerIds {
		container, err := ccl.LookupOnlineContainer(cid)
		if err != nil {
			return err
		}

		if !container.State.Running {
			return errors.New(fmt.Sprintf("Container %s does is not running", cid))
		}

		// validate that nothing has changed
		// (this is a testing feature)
		if failOnChange {
			origHostConfigBytes, err := fetchSavedHostConfigAsBytes(cid)
			if err != nil {
				return err
			}

			if origHostConfigBytes != nil {
				// proceed to validate that nothing changed since last execution time
				currentHostConfigBytes, err := json.Marshal(container.HostConfig)
				if err != nil {
					return err
				}

				if bytes.Compare(currentHostConfigBytes, origHostConfigBytes) != 0 {
					return errors.New("HostConfig changed after start")
				}
			}
		}

		err = saveHostConfig(cid, container.HostConfig)
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
