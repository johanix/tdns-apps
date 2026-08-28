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

# There is ONE package for the whole repo, built one level up -- see ../Makefile.
# Kept here only so running "make pkg" in an app directory says where to go
# rather than failing with "don't know how to make pkg".
pkg:
	@echo "tdns-apps ships a single package for all its apps; build it with:"
	@echo "    make -C .. pkg"
	@false

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
