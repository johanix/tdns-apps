PROG:=tdns-traffic

GOOS ?= $(shell uname -s | tr A-Z a-z)
GO:= CGO_ENABLED=0 go
include ../../utils/Makefile.common

.PHONY: clean install

# The sample config goes to /etc/tdns/, next to where the real one lives, so it
# is found without hunting. Its name ends in .sample.yaml, so installing it can
# never clobber an operator's actual config.
install:
	mkdir -p /etc/tdns
	install -c -s ${PROG} /usr/local/bin/
	install -c -m 644 ${PROG}.sample.yaml /etc/tdns/

clean:
	rm -f ${PROG} ${PROG}.netbsd version.go
