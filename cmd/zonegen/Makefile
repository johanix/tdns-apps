PROG:=tdns-zonegen

GOOS ?= $(shell uname -s | tr A-Z a-z)
GO:= go
include ../../utils/Makefile.common

.PHONY: clean install pkg

# The sample config goes to /etc/tdns/, next to where the real one lives, so
# it is found without hunting. Its name ends in .sample.yaml, so installing it
# can never clobber an operator's actual config -- which is why overwriting it
# on upgrade is fine, and why it is package-owned rather than a CONF_FILE.
install:
	mkdir -p /etc/tdns
	install -s -b -c ${PROG} /usr/local/bin/
	install -c -m 0644 ${PROG}.sample.yaml /etc/tdns/

# NetBSD binary package; rule and rationale in ../../utils/Makefile.common.
pkg:	pkg_tdns_zonegen

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
