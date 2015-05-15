#!/bin/bash
## build script for docker-fw
##
#

export GOPATH=~/goroot
go get "github.com/fsouza/go-dockerclient" && \
go get "code.google.com/p/getopt" || exit $?

## build without debug information
go build -ldflags "-w -s"
