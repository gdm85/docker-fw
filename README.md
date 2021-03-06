Docker-fw
=========

docker-fw is a complementary tool for [Docker](https://docker.com/) to manage their iptables firewall rules; it features persistence of rules and dynamic port assignments, in case host or container are restarted.

docker-fw expects your firewall to be using the ``*filter FORWARD`` chain with a default policy of REJECT/DROP (or an equivalent rule at bottom); this is default behavior starting from Docker version 1.5.

docker-fw does not work with Docker daemon ``--restart`` options because docker-fw would not be called automatically on container start. However, you can customize initialization of containers on host boot script via ``/etc/rc.local``, for example to loop through existing containers and initialize their firewall rules using ``docker-fw start``.

It is also possible to use this utility completely manage your internal docker0 bridge traffic between containers, as it will play nicely along with ``--icc=false`` and ``--iptables=true`` Docker daemon options.

Willing to contribute? Please submit a [pull request](https://github.com/gdm85/docker-fw/pulls) or [create an issue](https://github.com/gdm85/docker-fw/issues/new).

Iptables workflow explanation
=============================

This is how docker-fw expects network flow to happen (e.g. iptables explained in human terms) under a strict whitelisting firewall:

1. no link between FORWARD and DOCKER chains for all traffic from any source (rule ``FORWARD -o docker0 -j DOCKER`` added by Docker and removed by ``docker-fw init``)
2. all internal traffic on FORWARD chain is linked to DOCKER chain (``FORWARD -i docker0 -o docker0 -j DOCKER`` as 1st rule)
3. existing connections keep being forwarded (rule ``FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`` added by Docker is not touched)
4. outgoing connections from all containers are kept being forwarded (``FORWARD -i docker0 ! -o docker0 -j ACCEPT`` added by Docker is not touched)
5. a DROP rule is appeneded on FORWARD table as exiting rule
6. custom firewall rules are added before such DROP rule (usually with an insert) and/or to the DOCKER chain itself

See also [example-iptables.txt](example-iptables.txt).

License
=======

[Author](https://github.com/gdm85) is not officially involved with Docker development, thus this is not an official tool either.

docker-fw is licensed under GNU GPL version 2, see [LICENSE](LICENSE).

Building
========

Running the ``make`` command should suffice. The Makefile will use a locally-generated `GOPATH` without populating it with any package; all source code
dependencies are submodules under `vendor/`.

Actions
========

Init
----

Removes the iptables rule added by docker daemon at startup `-o docker0 -j DOCKER` from ``*filter FORWARD`` chain.
It will fail if docker daemon is not running or if rule does not exist.

	docker-fw init

Add actions
-----------

'add' is used to add a firewall specification for a container (any network external to Docker circuit, e.g. 192.168.178.0/24 or a public internet address) and targets the FORWARD chain, while 'add-internal'/'add-two-ways' target the INPUT chain.
If a valid container id/name is specified, then its IPv4 will be always aliased by docker-fw. Some special values exist for address specification:
- `.` to reference the container for which rules are being added
- `/` to reference the Docker host (usually 172.17.42.1)

**NOTE**: referencing the Docker host `/` is mostly intended for the 'add-internal' action; since it is considered a poor practice to create firewall rules to allow traffic that target the docker host

	docker-fw add container-id --source=(1.2.3.4|.|container-id) [--rev-lookup] [--sport=xxxx] [--dest=(1.2.3.4|.|container-id)] [--dport=xxxx] [--protocol=(tcp|udp)] [--filter="-i docker0 -o docker0"]
	docker-fw (add-internal|add-two-ways) container-id --source=(1.2.3.4|.|container-id|/) [--rev-lookup] [--sport=xxxx] --dest=(1.2.3.4|.|container-id|/) --dport=xxxx [--protocol=(tcp|udp)] [--filter="-i docker0 -o docker0"]

Some rules to use 'add', 'add-two-ways', 'add-internal' and 'add-input':
- address specifications (source/destination) can also be in IPv4 subnet notation
- specifying ``--dport`` is mandatory for 'add-internal' action.
- protocol default is 'tcp'.
- at least source or destination must be equivalent to '.' (container for which rule is being specified), but cannot be both. If no destination is specified, '.' is assumed.
- specification of extra iptables filter is optional, and empty by default
- using ``--rev-lookup`` allows to specify a container IPv4 address, that otherwise would be an error (name/id form is preferred)

'add-two-ways' requires that source is a container and performs two tasks:
- execute add-internal with the specified rule
- always make sure that the source container will have a /etc/hosts rule for the source container
- the internal rules and the custom hosts will be restored when using ``docker-fw start`` for the container

These commands can also parse and add multiple rules from a file or stdin (using '-' as filename):

	docker-fw add --from=(filename|-)
	docker-fw add-internal --from=(filename|-)
	docker-fw add-input --from=(filename|-)

When using ``--from``, any other parameter (except ``--rev-lookup``) is disallowed.

Two-ways linking
----------------

An example of how to apply two-ways linking (assumes ``--icc=false`` on your Docker daemon):
```
export IMAGE=ubuntu
docker run --detach --name=promoted $IMAGE sleep 1000
docker run --detach --expose=1025 --link promoted:promoted --name=endpoint $IMAGE sleep 1000

## enable iptables + hosts via docker-fw
docker-fw add-two-ways endpoint --source promoted --dport 1025

## test (it's advised to use 2 terminals for these commands)
docker exec endpoint nc -l 1025 &

docker exec promoted sh -c "echo 'Hello from promoted container' | nc endpoint 1025"
```

Save-hostconfig
---------------

Save host configuration of a running and correctly network-enabled container.
Such configuration will be used when starting the container through docker-fw.
It always happens by default after a successful start.

See also https://github.com/docker/docker/issues/8723

	docker-fw save-hostconfig container1 [container2] [container3] [...] [containerN]

Replay
------

Replay all firewall rules; will not add them again if existing on current iptables and will update the IPv4 addresses referenced in source/destination by looking up the aliases (if any specified).
Use ``--dry-run`` to display which stateful changes would be applied, and report exit code zero only if there would be none.

	docker-fw replay [--dry-run] container1 [container2] [container3] [...] [containerN]

Ls
--

List all existing firewall rules for specified container(s); if no container is specified, all containers' rules will be displayed.

	docker-fw ls [container1] [container2] [container3] [...] [containerN]

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

	docker-fw start [--dry-run] [--paused] [--pull-deps] container1 [container2] [container3] [...] [containerN]

It does the following:
 - sort input list of containers second their dependencies
 - start each of them sequentially (paused when ``--paused`` is specified)
 - execute the equivalent of 'replay' action for each container as it is started

The option ``--paused`` allows to start containers in paused status (for example in case user doesn't want to allow any activity until all firewall restore operations are completed).
The option ``--pull-deps`` will automatically make dependant (by link relationship) containers part of the selection.
If a container is already started or paused, its state is not changed.
By specifying ``--dry-run`` containers will be displayed in the order they would be started, but their state will not be changed.

### Dependencies
Please note that Docker currently (1.8) lacks a correct dependency [DAG](https://en.wikipedia.org/wiki/Directed_acyclic_graph) when starting containers, thus it does not start them in correct order (unless you use ``--restart=true`` has a hack); unfortunately, nothing is mentioned in [documentation there](https://docs.docker.com/articles/host_integration/) regarding this issue, which is solved as explained above by docker-fw start action (even if you don't use any of the other docker-fw features).

See also:
* https://github.com/docker/docker/issues/8821
* https://github.com/docker/docker/issues/11777

Internals
=========

docker-fw uses [Docker API](https://docs.docker.com/reference/api/docker_remote_api/) through [go-dockerclient](https://github.com/fsouza/go-dockerclient), and command-line based iptables access; [libiptc](http://tldp.org/HOWTO/Querying-libiptc-HOWTO/) is not being used because its API is not published (and it would be a tad too complex, see also [go-libiptc](https://github.com/gdm85/go-libiptc)).

Container information is retrieved via API when needed and cached for the duration of the execution of docker-fw.
Any id/name valid for the Docker API can be used with docker-fw.

Known issues
============

* Has some hardcoded features/settings inherited from Docker defaults (e.g. 172.x.x.x subnet)
* Not thoroughly tested, and no unit tests coverage
* Stores its ``.json`` descriptors in Docker's own containers metadata directory

All of the above can be addressed with some effort, and probably will (in due time); as always, patches welcome!

Troubleshooting
===============

If you see an error like this when running ``docker-fw init``:
```
2015/01/24 21:01:20 init: Could not find docker-added rule
```

You have two issues:
* you didn't [RTFM](https://en.wikipedia.org/wiki/RTFM) :)
* you are using Docker older than version 1.5 (it didn't have [this PR](https://github.com/docker/docker/pull/7003) merged in its codebase)
