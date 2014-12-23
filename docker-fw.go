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
	"bufio"
	"code.google.com/p/getopt"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

const (
	VERSION   = "0.1.1"
	ADDR_SPEC = "Can be either an IPv4 address, a subnet, one of the special aliases ('.' = container IPv4, '/' = docker host IPv4) or a container id. If an IPv4 address is specified and no subnet, '/32' will be added. Default is '.'"
	// directly from Docker
	validContainerNameChars = `[a-zA-Z0-9][a-zA-Z0-9_.-]`
)

type Action struct {
	Action, ContainerId                                                                                         string
	SourceArg, SourcePortArg, DestArg, DestPortArg, ProtoArg, FilterArg, FromArg, ReverseLookupContainerIPv4Arg getopt.Option
	CommandSet                                                                                                  *getopt.Set

	source, dest, proto, filter string
	reverseLookupContainerIPv4  bool
	sourcePort, destPort        uint16
}

var (
	containerIdMatch = regexp.MustCompile(`^/?` + validContainerNameChars + `+$`)
)

func NewAction(action string, allowParseNames bool) *Action {
	var a Action
	a.CommandSet = getopt.New()
	a.CommandSet.SetProgram("docker-fw (init|start|allow|add|add-input|add-internal|replay|drop) containerId")
	a.CommandSet.SetParameters("\n\nSyntax for all add actions:\n\tdocker-fw (add|add-input|add-internal) ...")
	a.Action = action

	// define all command line options
	a.SourceArg = a.CommandSet.StringVarLong(&a.source, "source", 's', "source-specification*", ".")
	a.SourcePortArg = a.CommandSet.Uint16VarLong(&a.sourcePort, "sport", 0, "Source port, optional", "port")
	a.DestArg = a.CommandSet.StringVarLong(&a.dest, "dest", 'd', "destination-specification*", ".")
	a.DestPortArg = a.CommandSet.Uint16VarLong(&a.destPort, "dport", 0, "Destination port, mandatory only for 'add-input' and 'add-internal' actions", "port")
	a.ProtoArg = a.CommandSet.EnumVarLong(&a.proto, "protocol", 'p', []string{"tcp", "udp"}, "The protocol of the packet to check")
	a.FilterArg = a.CommandSet.StringVarLong(&a.filter, "filter", 0, "extra iptables conditions")
	if allowParseNames {
		a.ReverseLookupContainerIPv4Arg = a.CommandSet.BoolVarLong(&a.reverseLookupContainerIPv4, "rev-lookup", 0, "allow specifying addresses in 172.* subnet and map them back to container names")
	}

	// explicitly set all option defaults
	a.proto = "tcp"
	a.source = "."
	a.dest = "."
	a.sourcePort = 0
	a.destPort = 0
	a.filter = ""

	return &a
}

func (a *Action) CreateRule() (*IptablesRule, error) {
	return NewIptablesRule(a.ContainerId, a.source, a.sourcePort, a.dest, a.destPort, a.proto, a.filter, a.reverseLookupContainerIPv4)
}

func (a *Action) Validate() error {
	// make source argument mandatory for better readability
	// although it could safely default to '.' (due to the check that src != dest),
	// it is better to have it explicit for readability
	if !a.SourceArg.Seen() {
		return errors.New("--source is mandatory")
	}
	if a.Action == "add-input" || a.Action == "add-internal" {
		if !a.DestPortArg.Seen() {
			return errors.New("--dport is mandatory")
		}
	}

	//NOTE: enforcement of different source/destination happens in NewIptablesRule()

	if a.SourcePortArg.Seen() && a.sourcePort == 0 {
		return errors.New("Invalid source port specified")
	}

	if a.DestPortArg.Seen() && a.destPort == 0 {
		return errors.New("Invalid destination port specified")
	}

	if len(a.dest) == 0 {
		return errors.New("Invalid destination specification")
	}

	if len(a.source) == 0 {
		return errors.New("Invalid source specification")
	}

	return nil
}

func (a *Action) Parse(args []string) error {
	return a.CommandSet.Getopt(args, nil)
}

func (a *Action) Usage() {
	fmt.Printf(`docker-fw version %s, Copyright (C) gdm85 https://github.com/gdm85/docker-fw/
docker-fw comes with ABSOLUTELY NO WARRANTY; for details see LICENSE
This is free software, and you are welcome to redistribute it
under certain conditions`, VERSION)
	a.CommandSet.PrintUsage(os.Stdout)
	fmt.Printf("\n* = %s\n", ADDR_SPEC)
	fmt.Printf("\nSyntax for 'allow' action:\n\tdocker-fw allow address1 [address2] [address3] [...] [addressN]\nA list of IPv4 addresses is accepted\n\n")
	fmt.Printf("Syntax for 'drop' action:\n\tdocker-fw drop container1 [container2] [container3] [...] [containerN]\nA list of container IDs/names is accepted\n\n")
	fmt.Printf("Syntax for 'replay' action:\n\tdocker-fw replay container1 [container2] [container3] [...] [containerN]\nA list of container IDs/names is accepted\n\n")
	fmt.Printf("Syntax for 'start' action:\n\tdocker-fw replay [--paused] [--pull-deps] container1 [container2] [container3] [...] [containerN]\n")
	fmt.Printf("A list of container IDs/names is accepted; option '--paused' allows to start containers in paused status, option '--pull-deps' allows to pull dependencies in selection\n")
}

func (a *Action) Run() error {
	err := a.Validate()
	if err != nil {
		return err
	}

	rule, err := a.CreateRule()
	if err != nil {
		return err
	}

	if a.Action == "add" {
		if isDockerIPv4(rule.Source) && isDockerIPv4(rule.Destination) {
			return errors.New("Trying to add an external firewall rule for internal Docker traffic")
		}

		err = AddFirewallRule(a.ContainerId, rule)
	} else if a.Action == "add-input" {
		err = AddInputRule(a.ContainerId, rule)
	} else if a.Action == "add-internal" {
		err = AddInternalRule(a.ContainerId, rule)
	} else {
		// only add actions are supported when importing from file
		panic("cannot execute this action: " + a.Action)
	}
	return err
}

func main() {
	// all possible command line arguments
	var from string
	cliArgs := NewAction("parsing", true)
	fromArg := cliArgs.CommandSet.StringVarLong(&from, "from", 0, "", "file|-")

	// if no arguments specified, show help and exit with failure
	if len(os.Args) == 1 || (len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help")) {
		cliArgs.Usage()
		os.Exit(1)
		return
	}

	// parse first positional argument
	cliArgs.Action = os.Args[1]

	switch cliArgs.Action {
	case "init":
		if len(os.Args) != 2 {
			log.Fatal("init action takes no command line arguments")
			os.Exit(1)
			return
		}

		err := InitializeFirewall()
		if err != nil {
			log.Fatalf("%s: %s", cliArgs.Action, err)
			return
		}

		// success
		os.Exit(0)
		return
	case "allow":
		if len(os.Args) < 3 {
			log.Fatalf("%s: no container id specified", cliArgs.Action)
			os.Exit(1)
			return
		}
		if len(os.Args) < 4 {
			log.Fatalf("%s: no whitelist addresses specified", cliArgs.Action)
			os.Exit(1)
			return
		}
		// pick container id
		cliArgs.ContainerId = os.Args[2]

		if !containerIdMatch.MatchString(cliArgs.ContainerId) {
			log.Fatalf("not a valid container id: %s", cliArgs.ContainerId)
			return
		}

		err := AllowExternal(cliArgs.ContainerId, os.Args[3:])
		// parse error
		if err != nil {
			log.Printf("%s: %s", cliArgs.Action, err)
			os.Exit(2)
			return
		}
		os.Exit(0)
		return
	case "start":
		if len(os.Args) < 3 {
			log.Fatalf("%s: no container ids specified", cliArgs.Action)
			os.Exit(1)
			return
		}
		containerIds := []string{}
		paused := false
		pullDeps := false
		for _, arg := range os.Args[2:] {
			// is the famous '--paused' option?
			if strings.HasPrefix(arg, "--") {
				switch arg {
				case "--paused":
					paused = true
					break
				case "--pull-deps":
					pullDeps = true
					break
				default:
					log.Fatalf("%s: unknown option: %s", cliArgs.Action, arg)
					return
				}

				continue
			}

			// pick container id
			if !containerIdMatch.MatchString(arg) {
				log.Fatalf("not a valid container id: %s", arg)
				return
			}
			containerIds = append(containerIds, arg)
		}

		err := StartContainers(containerIds, paused, pullDeps)
		// parse error
		if err != nil {
			log.Printf("%s: %s", cliArgs.Action, err)
			os.Exit(2)
			return
		}
		os.Exit(0)
		return
	case "replay":
	case "drop":
		if len(os.Args) < 3 {
			log.Fatalf("%s: no container ids specified", cliArgs.Action)
			os.Exit(1)
			return
		}
		containerIds := []string{}
		for _, arg := range os.Args[2:] {
			// pick container id
			if !containerIdMatch.MatchString(arg) {
				log.Fatalf("not a valid container id: %s", arg)
				return
			}
			containerIds = append(containerIds, arg)
		}

		var err error
		switch cliArgs.Action {
		case "replay":
			err = ReplayRules(containerIds)
			break
		case "drop":
			err = DropRules(containerIds)
			break
		default:
			panic("invalid exit point")
		}
		// parse error
		if err != nil {
			log.Printf("%s: %s", cliArgs.Action, err)
			os.Exit(2)
			return
		}
		os.Exit(0)
		return

	case "add-internal", "add", "add-input":
		if len(os.Args) < 3 {
			log.Fatalf("%s: no container id specified", cliArgs.Action)
			os.Exit(1)
			return
		}

		// pick container id
		cliArgs.ContainerId = os.Args[2]

		if !containerIdMatch.MatchString(cliArgs.ContainerId) {
			log.Fatalf("not a valid container id: %s", cliArgs.ContainerId)
			return
		}
		break
	default:
		log.Fatalf("Unknown action: %s", cliArgs.Action)
		return
	}

	// parse all except those already manually parsed
	newArgs := []string{os.Args[0]}
	newArgs = append(newArgs, os.Args[3:]...)
	if err := cliArgs.Parse(newArgs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		cliArgs.Usage()
		os.Exit(1)
		return
	}

	// when a source for a list of actions is specified, no further parameters can be specified
	if fromArg.Seen() {

		if cliArgs.SourceArg.Seen() || cliArgs.SourcePortArg.Seen() || cliArgs.DestArg.Seen() || cliArgs.DestPortArg.Seen() || cliArgs.ProtoArg.Seen() || cliArgs.FilterArg.Seen() {
			log.Fatal("When using --from, only '--rev-lookup' is allowed")
			return
		}

		// read all commands line by line from stdin
		if from == "-" {
			scanner := bufio.NewScanner(os.Stdin)
			lineNo := 0
			for scanner.Scan() {
				lineNo++

				// create a new 'commandLine' for each input line,
				// but always use same action for all lines
				commandLine := NewAction(cliArgs.Action, false)
				// set executable name
				newArgs := []string{os.Args[0]}
				newArgs = append(newArgs, strings.Split(scanner.Text(), " ")...)
				if err := commandLine.Parse(newArgs); err != nil {
					fmt.Fprintln(os.Stderr, "%s: error at line %d: %s", commandLine.Action, lineNo, err)
					os.Exit(1)
					return
				}

				err := commandLine.Run()
				if err != nil {
					log.Fatalf("%s: %s", commandLine.Action, err)
					return
				}
			}

			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
			os.Exit(1)
		}
		return
	}

	err := cliArgs.Run()
	if err != nil {
		log.Fatalf("%s: %s", cliArgs.Action, err)
		return
	}

	// success
	os.Exit(0)
}
