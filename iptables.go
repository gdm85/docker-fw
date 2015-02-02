/*
 * docker-fw v0.2.1 - a complementary tool for Docker to manage custom
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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gdm85/go-dockerclient"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

const (
	IPTABLES_BINARY = "/sbin/iptables"
	DOCKER_HOST     = "172.17.42.1/32"
	DOCKER_CHAIN    = "DOCKER"
)

type IptablesRule struct {
	Source           string
	SourceAlias      string // optional
	SourcePort       uint16 // optional
	Destination      string
	DestinationAlias string // optional
	DestinationPort  uint16 // optional
	Protocol         string
	Filter           string // optional
}

type ActiveIptablesRule struct {
	IptablesRule
	Chain  string
	JumpTo string
}

type IptablesRulesCollection struct {
	cid   string
	Rules []*ActiveIptablesRule
}

var matchIpv4 *regexp.Regexp
var ccl *CachedContainerLookup

func (r *ActiveIptablesRule) Position() int {
	if r.Chain == "FORWARD" {
		return 2
	} else if r.Chain == "INPUT" {
		return 1
	} else {
		panic("Cannot determine position for chain " + r.Chain)
	}
}

func init() {
	// test that iptables works
	exitCode, err := iptablesRun(true, "--version")
	if err != nil {
		panic(fmt.Sprintf("iptables: %s", err))
	}
	if exitCode != 0 {
		panic("iptables: not available")
	}

	matchIpv4, err = regexp.Compile("^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(/[0-9]{1,2})?$")
	if err != nil {
		panic(err)
	}

	// initialize cache used for all operations
	ccl = &CachedContainerLookup{containers: map[string]*docker.Container{}, networkAddress: map[string]*docker.Container{}}
}

func isDockerIPv4(ipv4 string) bool {
	return strings.HasPrefix(ipv4, "172.")
}

func iptablesRun(quiet bool, commandLine string) (int, error) {
	var err error

	commandLine = IPTABLES_BINARY + " " + commandLine
	cmd := exec.Command("sh", "-c", commandLine)
	cmd.Env = os.Environ()
	cmd.Dir, err = os.Getwd()
	if err != nil {
		return 1, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 1, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 1, err
	}
	output := ""

	err = cmd.Start()
	if err != nil {
		return 1, err
	}

	var bytes []byte
	if bytes, err = ioutil.ReadAll(stdout); err != nil {
		return 1, err
	}
	output += string(bytes)

	if bytes, err = ioutil.ReadAll(stderr); err != nil {
		return 1, err
	}
	output += string(bytes)

	var exitCode int
	if err := cmd.Wait(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			} else {
				panic("cannot read exit status")
			}
		} else {
			panic(err)
		}
	}

	// display errors when exit code != 0
	if !quiet {
		if exitCode != 0 {
			log.Printf("%s\n%s", commandLine, output)
		}
	}

	return exitCode, nil
}

func InitializeFirewall() error {
	// check if daemon is running
	err := Docker.Ping()
	if err != nil {
		return err
	}

	// this Docker-added rule must be disposed, see https://github.com/docker/docker/issues/6034#issuecomment-58742268
	rule := "FORWARD -o docker0 -j " + DOCKER_CHAIN
	if RuleExists(rule) {
		err := internalDelete(rule, false)
		if err != nil {
			return err
		}

		// insert new rule for internal docker traffic on top
		err = internalInsert(1, "FORWARD -i docker0 -o docker0 -j DOCKER")
		if err != nil {
			return err
		}
	} else {
		return errors.New("Could not find docker-added rule")
	}

	//TODO: check that our inserted rule is still on top
	// possibly extend this check everywhere iptables is touched

	return nil
}

func NewIptablesRule(cid string, source string, sourcePort uint16, dest string, destPort uint16, proto, filter string, reverseLookupContainerIPv4 bool) (*IptablesRule, error) {
	container, err := ccl.LookupOnlineContainer(cid)
	if err != nil {
		return nil, err
	}

	rule := IptablesRule{}

	rule.Source, rule.SourceAlias, err = ccl.ParseAddress(source, container, reverseLookupContainerIPv4)
	if err != nil {
		return nil, err
	}

	rule.Destination, rule.DestinationAlias, err = ccl.ParseAddress(dest, container, reverseLookupContainerIPv4)
	if err != nil {
		return nil, err
	}

	// enforce a valid flow specification
	if rule.Source == rule.Destination {
		return nil, errors.New("Cannot add rule with same source and destination")
	}

	if rule.SourceAlias != "." && rule.DestinationAlias != "." {
		return nil, errors.New("Either source or destination must be the container itself")
	}

	rule.SourcePort = sourcePort
	rule.DestinationPort = destPort
	rule.Protocol = proto
	rule.Filter = filter

	return &rule, nil
}

// corresponding to a subcommand
// function to allow incoming traffic for a specific container
func AllowExternal(cid string, whitelist4 []string) error {
	container, err := ccl.LookupOnlineContainer(cid)
	if err != nil {
		return err
	}

	containerIpv4 := container.NetworkSettings.IPAddress + "/32"

	for _, port := range container.NetworkSettings.PortMappingAPI() {
		// skip this port, it has not been published
		if port.PrivatePort == 0 {
			continue
		}

		if port.Type != "tcp" && port.Type != "udp" {
			return errors.New(fmt.Sprintf("Unrecognized protocol '%s' for port %d of container %s", port.Type, port.PrivatePort, cid))
		}
		if port.IP != "0.0.0.0" {
			return errors.New(fmt.Sprintf("Unrecognized host ip '%s' for binding of port %d (container %s)", port.IP, port.PrivatePort, cid))
		}

		// create a rule for each whitelisted external IPv4
		for _, wIpv4 := range whitelist4 {
			wIpv4 = strings.Trim(wIpv4, " ")

			// always make IPv4 specific, unless a subnet is specified
			if !strings.Contains(wIpv4, "/") {
				wIpv4 += "/32"
			}

			rule := IptablesRule{
				Source: wIpv4, Destination: containerIpv4, Protocol: port.Type, DestinationPort: uint16(port.PrivatePort),
				DestinationAlias: cid,
				Filter:           "! -i docker0 -o docker0",
			}

			err := addFirewallRule(container, &rule)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// format in docker-fw style
func (rule *IptablesRule) FormatAsFwAction() string {
	s := fmt.Sprintf("-s %s -d %s -p %s", rule.SourceAliasOrAddress(), rule.DestinationAliasOrAddress(), rule.Protocol)
	if rule.Filter != "" {
		s += fmt.Sprintf(" --filter '%s'", rule.Filter)
	}
	if rule.DestinationPort != 0 {
		s += fmt.Sprintf(" --dport %d", rule.DestinationPort)
	}
	if rule.SourcePort != 0 {
		s += fmt.Sprintf(" --sport %d", rule.SourcePort)
	}

	return s
}

func (rule *IptablesRule) Format() string {
	s := fmt.Sprintf("-s %s -d %s %s -p %s -m %s", rule.Source, rule.Destination, rule.Filter, rule.Protocol, rule.Protocol)
	if rule.DestinationPort != 0 {
		s += fmt.Sprintf(" --dport %d", rule.DestinationPort)
	}
	if rule.SourcePort != 0 {
		s += fmt.Sprintf(" --sport %d", rule.SourcePort)
	}

	return s
}

func (rule *ActiveIptablesRule) Format() string {
	return fmt.Sprintf("%s %s -j %s", rule.Chain, rule.IptablesRule.Format(), rule.JumpTo)
}

// guess the action that was used to create this rule
// NOTE: rules create through 'allow' will not return back an 'allow' action
func (rule *ActiveIptablesRule) ExtrapolateAction() string {
	if rule.Chain == "INPUT" && rule.JumpTo == "ACCEPT" {
		return "add-input"
	}
	if rule.Chain == DOCKER_CHAIN && rule.JumpTo == "ACCEPT" {
		return "add-internal"
	}
	if rule.Chain == "FORWARD" && rule.JumpTo == DOCKER_CHAIN {
		return "add"
	}
	panic("not yet implemented: proper de-serialization of rule " + rule.Format())
}

func (rule *ActiveIptablesRule) FormatAsFwCommand(target string) string {
	return fmt.Sprintf("%s %s %s", rule.ExtrapolateAction(), target, rule.IptablesRule.FormatAsFwAction())
}

func (rule *IptablesRule) SourceAliasOrAddress() string {
	if rule.SourceAlias != "" {
		return rule.SourceAlias
	}

	return rule.Source
}

func (rule *IptablesRule) DestinationAliasOrAddress() string {
	if rule.DestinationAlias != "" {
		return rule.DestinationAlias
	}

	return rule.Destination
}

// used for comparison of rules
func (rule *IptablesRule) Aliases() string {
	s := ""
	if rule.DestinationAlias != "" {
		s += fmt.Sprintf("%s=%s\n", rule.DestinationAlias, rule.Destination)
	}
	if rule.SourceAlias != "" {
		s += fmt.Sprintf("%s=%s\n", rule.SourceAlias, rule.Source)
	}
	return s
}

// corresponding to a subcommand ('add')
func AddFirewallRule(cid string, iptRule *IptablesRule) error {
	container, err := ccl.LookupOnlineContainer(cid)
	if err != nil {
		return err
	}

	return addFirewallRule(container, iptRule)
}

func addFirewallRule(container *docker.Container, iptRule *IptablesRule) error {
	addedRule := ActiveIptablesRule{Chain: "FORWARD", JumpTo: DOCKER_CHAIN}
	addedRule.IptablesRule = *iptRule

	// insert always on top
	// NOTE: the catchall "-o docker0 -j DOCKER" must *not* exist in table
	err := internalInsert(addedRule.Position(), addedRule.Format())
	if err != nil {
		return err
	}

	return recordRule(container, &addedRule)
}

// corresponding to a subcommand (add-input)
func AddInputRule(cid string, iptRule *IptablesRule) error {
	container, err := ccl.LookupOnlineContainer(cid)
	if err != nil {
		return err
	}

	addedRule := ActiveIptablesRule{Chain: "INPUT", JumpTo: "ACCEPT"}
	addedRule.IptablesRule = *iptRule

	err = internalInsert(addedRule.Position(), addedRule.Format())
	if err != nil {
		return err
	}

	return recordRule(container, &addedRule)
}

// corresponding to action add-two-ways
func AddTwoWays(cid string, iptRule *IptablesRule) error {
	// create or update the two-ways hook for source
	if iptRule.SourceAlias == "" {
		return errors.New("Source must be a container id/name")
	}
	err := updateCustomHosts(iptRule.SourceAlias, cid)
	if err != nil {
		return err
	}

	err = AddInternalRule(cid, iptRule)
	if err != nil {
		return err
	}
	return nil
}

// corresponding to a subcommand (add-internal)
func AddInternalRule(cid string, iptRule *IptablesRule) error {
	container, err := ccl.LookupOnlineContainer(cid)
	if err != nil {
		return err
	}

	addedRule := ActiveIptablesRule{Chain: DOCKER_CHAIN, JumpTo: "ACCEPT"}
	addedRule.IptablesRule = *iptRule

	err = internalAppend(cid, addedRule.Format())
	if err != nil {
		return err
	}

	return recordRule(container, &addedRule)
}

func (c *IptablesRulesCollection) Append(iptRule *ActiveIptablesRule) {
	c.Rules = append(c.Rules, iptRule)
}

func (c *IptablesRulesCollection) fileName() string {
	return fmt.Sprintf("/var/lib/docker/containers/%s/extraRules.json", c.cid)
}

func (c *IptablesRulesCollection) Remove() error {
	return os.Remove(c.fileName())
}

func (c *IptablesRulesCollection) Save() error {
	bytes, err := json.Marshal(&c)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(c.fileName(), bytes, 0666)
	return err
}

func DropRules(containerIds []string) error {
	for _, cid := range containerIds {
		container, err := ccl.LookupContainer(cid)
		if err != nil {
			return err
		}

		c, err := LoadRules(container)
		if err != nil {
			return err
		}

		//NOTE: will not delete a JSON representing an empty array
		if len(c.Rules) == 0 {
			return nil
		}

		for _, r := range c.Rules {
			// attempt to delete, do not make a permanent failure
			_ = internalDelete(r.Format(), true)
		}

		err = c.Remove()
		if err != nil {
			return err
		}
	}
	return nil
}

// store iptables rule in a JSON descriptor
func recordRule(container *docker.Container, iptRule *ActiveIptablesRule) error {
	c, err := LoadRules(container)
	if err != nil {
		return err
	}

	// check if rule is already there
	for _, r := range c.Rules {
		if r.Format() == iptRule.Format() && r.Aliases() == iptRule.Aliases() {
			// already tracked, skip
			fmt.Printf("docker-fw: rule '%s' already tracked\n", r.Format())
			return nil
		}
	}

	// add the new rule
	c.Append(iptRule)

	return c.Save()
}

// check if rule exists
func RuleExists(rule string) bool {
	exitCode, err := iptablesRun(true, "--wait -C "+rule)
	if err != nil {
		panic(fmt.Sprintf("iptables: %s", err))
	}
	return exitCode == 0
}

func internalAppend(containerId, rule string) error {
	if RuleExists(rule) {
		fmt.Printf("docker-fw: iptables(%s): rule '%s' already exists, not appending\n", containerId, rule)
		return nil
	}

	parts := strings.SplitN(rule, " ", 2)
	// now append rule
	exitCode, err := iptablesRun(false, fmt.Sprintf("--wait -A %s %s", parts[0], parts[1]))
	if err != nil {
		panic(fmt.Sprintf("iptables(%s): %s", containerId, err))
	}
	if exitCode != 0 {
		return errors.New(fmt.Sprintf("iptables(%s): cannot append rule '%s'", containerId, rule))
	}

	return nil
}

func internalInsert(pos int, rule string) error {
	if RuleExists(rule) {
		fmt.Printf("docker-fw: iptables: rule '%s' already exists, not inserting\n", rule)
		return nil
	}

	parts := strings.SplitN(rule, " ", 2)
	// now insert rule
	exitCode, err := iptablesRun(false, fmt.Sprintf("--wait -I %s %d %s", parts[0], pos, parts[1]))
	if err != nil {
		panic(fmt.Sprintf("iptables: %s", err))
	}
	if exitCode != 0 {
		return errors.New("cannot insert iptables rule")
	}

	return nil
}

func internalDelete(rule string, quiet bool) error {
	// now insert rule
	exitCode, err := iptablesRun(quiet, "--wait -D "+rule)
	if err != nil {
		// unexpected failure while running external command
		panic(fmt.Sprintf("os.Exec(): %s", err))
	}
	if exitCode != 0 {
		return errors.New("cannot delete iptables rule")
	}

	return nil
}

// execute again all rules stored for specified container
func ReplayRules(containerIds []string, dryRun bool) (int, error) {
	hasChanges := false
	for _, cidx := range containerIds {
		container, err := ccl.LookupOnlineContainer(cidx)
		if err != nil {
			return 1, err
		}

		c, err := LoadRules(container)
		if err != nil {
			return 2, err
		}

		changed := false
		for _, r := range c.Rules {
			oldRule := r.Format()

			// de-alias source
			if r.SourceAlias != "" {
				ipv4, _, err := ccl.ParseAddress(r.SourceAlias, container, false)
				if err != nil {
					return 3, err
				}

				if r.Source != ipv4 {
					changed = true
					r.Source = ipv4
				}
			}

			// de-alias destination
			if r.DestinationAlias != "" {
				ipv4, _, err := ccl.ParseAddress(r.DestinationAlias, container, false)
				if err != nil {
					return 4, err
				}

				if r.Destination != ipv4 {
					changed = true
					r.Destination = ipv4
				}
			}

			// create the rule that it is necessary to have
			rule := r.Format()

			// skip deleting/re-adding if rule is not any different than previous
			if rule != oldRule {
				// first, (attempt to) remove old rule
				if dryRun {
					if RuleExists(oldRule) {
						fmt.Printf("docker-fw: iptables(%s): would delete rule '%s'\n", container.Name[1:], oldRule)
						hasChanges = true
					}
				} else {
					_ = internalDelete(oldRule, true)
				}
			}

			// check if new rule is already there

			if !RuleExists(rule) {
				//fmt.Printf("iptables(%s): rule '%s' does not exist\n", container.Name[1:], rule)

				// insert or append, depending on destination chain
				if r.Chain == DOCKER_CHAIN {
					if dryRun {
						fmt.Printf("docker-fw: iptables(%s): would append rule '%s'\n", container.Name, rule)
						hasChanges = true
					} else {
						err := internalAppend(container.Name, rule)
						if err != nil {
							return 5, err
						}
					}
				} else {
					if dryRun {
						fmt.Printf("docker-fw: iptables(%s): would insert rule '%s'\n", container.Name, rule)
						hasChanges = true
					} else {
						err := internalInsert(r.Position(), rule)
						if err != nil {
							return 6, err
						}
					}
				}
			}
		}

		// used for dry-run exit code, report non-zero if anything would change
		if changed {
			hasChanges = true
		}

		// if there was any change, store them again
		if !dryRun && changed {
			err := c.Save()
			if err != nil {
				return 7, err
			}
		}
	}

	if dryRun {
		if hasChanges {
			return 1, nil
		}
	}

	// exit with 0 since all operations were successful
	return 0, nil
}

func ListRules(containerIds []string) error {
	containers := []*docker.Container{}
	if len(containerIds) == 0 {
		err := ccl.LoadAllContainers()
		if err != nil {
			return err
		}

		containers = ccl.GetAllContainers()
	} else {
		for _, cid := range containerIds {
			container, err := ccl.LookupContainer(cid)
			if err != nil {
				return err
			}

			containers = append(containers, container)
		}
	}

	// loop through each container and display the ready-to-use add* action
	for _, container := range containers {
		collection, err := LoadRules(container)
		if err != nil {
			return err
		}

		if len(collection.Rules) == 0 {
			continue
		}

		for _, rule := range collection.Rules {
			// apply visual fix for rules that where stored with IDs instead of names
			if rule.SourceAlias != "" {
				rule.SourceAlias = ccl.containers[rule.SourceAlias].Name[1:]
			}
			if rule.DestinationAlias != "" {
				rule.DestinationAlias = ccl.containers[rule.DestinationAlias].Name[1:]
			}

			fmt.Printf("%s\n", rule.FormatAsFwCommand(container.Name[1:]))
		}
	}

	return nil
}
