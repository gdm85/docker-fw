bin/docker-fw:
	mkdir -p bin .gopath
	if [ ! -L .gopath/src ]; then ln -s "$(CURDIR)/vendor" .gopath/src; fi
	cd src && GOBIN="$(CURDIR)/bin/" GOPATH="$(CURDIR)/.gopath" go install && mv ../bin/src ../bin/docker-fw

all: bin/docker-fw errcheck test

errcheck:
	mkdir -p bin .gopath
	if [ ! -L .gopath/src ]; then ln -s "$(CURDIR)/vendor" .gopath/src; fi
	cd src && GOPATH="$(CURDIR)/.gopath" errcheck

test:
	mkdir -p bin .gopath
	if [ ! -L .gopath/src ]; then ln -s "$(CURDIR)/vendor" .gopath/src; fi
	cd src && GOPATH="$(CURDIR)/.gopath" go test -v

.PHONY: all deps test errcheck bin/docker-fw
