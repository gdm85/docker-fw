
.DEFAULT_GOAL := all

.PHONY := all deps

all: deps bin/docker-fw

deps:
	go get "github.com/fsouza/go-dockerclient"
	go get "github.com/pborman/getopt"

## build without debug information
bin/docker-fw: *.go
	mkdir -p bin
	GOBIN=bin go install -ldflags "-w -s"
