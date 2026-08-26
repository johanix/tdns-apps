# Aggregate targets across the apps in this directory.
#
# Only tdns-zonegen is listed. The other apps here build against different
# trees (whois-status against tdns-transport, reporter and scanner against the
# legacy tdns/ module), so an "all" that swept them in would fail for reasons
# unrelated to whatever you were doing. Add an app to a target below when it
# is known to build, rather than assuming it does.

.PHONY: all clean install install-dirs check-root pkg

all:
	$(MAKE) -C ./zonegen/

clean:
	$(MAKE) -C ./zonegen/ clean

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Must run as root"; exit 1; fi

install-dirs: check-root
	mkdir -p /usr/local/bin /etc/tdns

install: check-root install-dirs
	$(MAKE) -C ./zonegen/ install

# NetBSD binary packages. Each app's "pkg" target builds, installs and packs
# its own binary, so this needs root for the same reason "install" does.
#
# The .tgz is left in the app directory. Publishing is deliberately NOT a
# target: packages go into a per-osrelease tree on a lab dom0, and which trees
# exist is a property of the lab, not of this repo.
pkg: check-root install-dirs
	$(MAKE) -C ./zonegen/ pkg
