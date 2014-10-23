Docker-fw
=========

docker-fw is a complementary tool for [Docker](https://docker.com/) to manage internal firewall rules between Docker containers or rules from other subnets targeting them; it features persistence to allow users restoring such firewall rules, whatever level of complexity they get.

In order to use docker-fw, you need all of the following:
- your firewall must be using the ``*filter FORWARD`` chain with a default policy of REJECT/DROP (or an equivalent bottom rule)
- a custom Docker with [PR #7003](https://github.com/docker/docker/pull/7003) (information on this page will be updated accordingly if/when the pull request is merged)

Want to contribute? Submit a [pull request](https://github.com/gdm85/docker-fw/pulls) or [create an issue](https://github.com/gdm85/docker-fw/issues/new).

Use-case example
================

You can make the best out of docker-fw and Docker if you use the ``--restart=always`` option for your containers, that allows persistence of networking configuration across reboots.

In theory you could use docker-fw to completely manage your internal docker0 bridge traffic between containers, but docker-fw will play nicely along with ``--icc=false`` and ``--iptables=true`` options of Docker daemon.

License
=======

[Author](https://github.com/gdm85) is not officially involved with Docker development, thus this is not an official tool either.

docker-fw is licensed under GNU GPL version 2, see [LICENSE](LICENSE).

Actions
========

docker-fw supports a few subcommands, called 'actions'.

Init
----

Removes the iptables rule added by docker daemon at startup `-o docker0 -j DOCKER` from ``*filter FORWARD`` chain.
It will fail if docker daemon is not running or if such rule is not found.

	docker-fw init

Add and add-internal
---

'add' is used to add a firewall specification for a container (any network external to Docker circuit, e.g. 10.0.0.1 or public internet addresses), while 'add-internal' targets internal Docker traffic rules.
If a valid container id/name is specified, then its IPv4 will be always aliased by docker-fw. Some special values exist for address specification:
- `.` to reference the container for which rules are being added
- `/` to reference the Docker host (usually 172.17.42.1)

**NOTE**: referencing the Docker host `/` is mostly intended for the 'add-internal' action; since it is considered a poor practice to create firewall rules to allow traffic that target the docker host

	docker-fw add container-id --source=(1.2.3.4|.|container-id) [--rev-lookup] [--sport=xxxx] [--dest=(1.2.3.4|.|container-id)] [--dport=xxxx] [--protocol=(tcp|udp)] [--filter="-i docker0 -o docker0"]
	docker add-internal container-id --source=(1.2.3.4|.|container-id|/) [--rev-lookup] [--sport=xxxx] --dest=(1.2.3.4|.|container-id|/) --dport=xxxx [--protocol=(tcp|udp)] [--filter="-i docker0 -o docker0"]

Some rules to use 'add' or 'add-internal':
- address specifications (source/destination) can also be in IPv4 subnet notation
- specifying --dport is mandatory for 'add-internal' action.
- protocol default is 'tcp'.
- at least source or destination must be equivalent to '.' (container for which rule is being specified), but cannot be both. If no destination is specified, '.' is assumed.
- specification of extra iptables filter is optional, and empty by default
- using --rev-lookup allows to specify a container IPv4 address, that otherwise would be an error (name/id form is preferred)

These commands can also parse and add multiple rules from a file or stdin (using '-' as filename):

	docker-fw add --from=(filename|-)
	docker-fw add-internal --from=(filename|-)

When using --from, any other parameter (except --rev-lookup) is disallowed.

Replay
------

Replay all firewall rules; will not add them again if existing on current iptables and will update the IPv4 addresses referenced in source/destination by looking up the aliases (if any specified).

	docker-fw replay container1 [container2] [container3] [...] [containerN]

Drop
----

Drop all firewall rules for specified container; iptables rules are deleted and the json file that contains them is deleted from the container directory.

	docker-fw drop container1 [container2] [container3] [...] [containerN]

Allow
-----

Allow specified source address (external) as an 'add' command for each of the available published ports of the container.

	docker-fw allow container-id ip-address-1 [ip-address-2] [ip-address-3] [...] [ip-address-N]
	
This command is explicitly meant to allow access from external networks to the container's network address.

Start
-----

	docker-fw start [--paused] [--pull-deps] container1 [container2] [container3] [...] [containerN]

It does the following:
 - sort input list of containers second their dependencies
 - start each of them sequentially (paused if --paused is specified)
 - execute the equivalent of 'replay' action for each container as it is started

The option --paused allows to start containers in paused status (for example in case user doesn't want to allow any activity until all firewall restore operations are completed).
The option --pull-deps will automatically make dependant (by link relationship) containers part of the selection.
If a container is already started or paused, its state is not changed.

Internals
=========

docker-fw uses [Docker API](https://docs.docker.com/reference/api/docker_remote_api/) through [go-dockerclient](https://github.com/fsouza/go-dockerclient), and command-line based iptables access (I know, [libiptc](http://tldp.org/HOWTO/Querying-libiptc-HOWTO/) would be best).

Container information is retrieved via API when needed and cached for the duration of the execution of docker-fw.
Any id/name valid for the Docker API can be used with docker-fw.
