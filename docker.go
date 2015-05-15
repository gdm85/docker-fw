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
	"bytes"
	"errors"
	"fmt"
	"github.com/fsouza/go-dockerclient"
	"sort"
	"strings"
)

type ExecResult struct {
	Stdout, Stderr string
	ExitCode       int
}

var Docker *docker.Client

func init() {
	var err error
	Docker, err = docker.NewClient("unix:///var/run/docker.sock")
	if err != nil {
		panic(err)
	}
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

func containerExec(cid string, cmd []string) (*ExecResult, error) {
	config := docker.CreateExecOptions{
		Container:    cid,
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Cmd:          cmd,
	}
	execObj, err := Docker.CreateExec(config)
	if err != nil {
		return nil, err
	}

	//	Docker.SkipServerVersionCheck = true
	var stdout, stderr bytes.Buffer
	opts := docker.StartExecOptions{
		OutputStream: &stdout,
		ErrorStream:  &stderr,
		Detach:       false,
	}

	// start execution & join
	err = Docker.StartExec(execObj.ID, opts)
	if err != nil {
		return nil, err
	}

	// inspect to retrieve exit code
	inspect, err := Docker.InspectExec(execObj.ID)
	if err != nil {
		return nil, err
	}

	return &ExecResult{
		ExitCode: inspect.ExitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}

func containerInject(cid, path, content string) error {
	// first truncate the existing hosts file
	// 'truncate', like 'cat', are part of coreutils and expected to be found within container
	result, err := containerExec(cid, []string{"truncate", "--size=0", "/etc/hosts"})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return errors.New(fmt.Sprintf("failed to truncate hosts inside container: %s", result.Stderr))
	}

	// proceed to append new data
	config := docker.CreateExecOptions{
		Container:    cid,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Cmd:          []string{"sh", "-c", "cat >> " + path},
	}
	execObj, err := Docker.CreateExec(config)
	if err != nil {
		return err
	}

	//	Docker.SkipServerVersionCheck = true
	var stdout, stderr bytes.Buffer
	opts := docker.StartExecOptions{
		InputStream:  strings.NewReader(content),
		OutputStream: &stdout,
		ErrorStream:  &stderr,
		Detach:       false,
	}

	// start execution
	err = Docker.StartExec(execObj.ID, opts)
	if err != nil {
		return err
	}

	// inspect to retrieve exit code
	inspect, err := Docker.InspectExec(execObj.ID)
	if err != nil {
		return err
	}

	if inspect.ExitCode != 0 {
		return errors.New(fmt.Sprintf("failed to cat inside container: %s", stderr.String()))
	}

	return nil
}
