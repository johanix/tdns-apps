# Aggregate targets across the apps in this directory.
#
# Only tdns-zonegen is listed. The other apps here build against different
# trees (whois-status against tdns-transport, reporter and scanner against the
# legacy tdns/ module), so an "all" that swept them in would fail for reasons
# unrelated to whatever you were doing. Add an app to PKG_APPS below when it
# is known to build.

# The apps shipped in the package. ONE package for the repo, deliberately: a
# collection of micro-packages is more to build, publish, install and keep from
# skewing than the things it packages.
PKG_APPS=	zonegen traffic

# What those apps install, as paths from the root. The prefix passed to
# mkpkg.sh is "/" rather than /usr/local because the package spans two roots --
# binaries in /usr/local/bin, sample configs in /etc/tdns -- and mkpkg.sh
# copies each file from <prefix>/<path>, so one prefix has to cover both.
#
# Keep this in step with PKG_APPS. A forgotten entry is caught at build time:
# mkpkg.sh refuses to package a file that is not there.
PKG_FILES=	usr/local/bin/tdns-zonegen \
		etc/tdns/tdns-zonegen.sample.yaml \
		usr/local/bin/tdns-traffic \
		etc/tdns/tdns-traffic.sample.yaml

# VERSION lives at the repo root. "!=" rather than "$(shell ...)": $(shell) is
# GNU-make only and under NetBSD's bmake expands to NOTHING, silently -- which
# once produced a plausibly named, full-size, VERSIONLESS package. mkpkg.sh
# refuses such a version; this is the other half of that fix. It also means
# packaging does not work under macOS's make 3.81, which predates "!=" --
# build packages on the NetBSD host, which is where they belong anyway.
PKGBASEVER!= for f in ../VERSION VERSION; do if [ -f "$$f" ]; then sed -e 's/^[vV]//' -e 's/[^0-9.].*$$//' "$$f"; break; fi; done 2>/dev/null || echo ""
PKGDATE!= date +%Y%m%d
PKGVER=$(PKGBASEVER).$(PKGDATE)
PKG_TDNS_APPS=tdns-apps-$(PKGVER).tgz

.PHONY: all clean install install-dirs check-root pkg

all:
	@for app in $(PKG_APPS); do $(MAKE) -C ./$$app/ || exit 1; done

clean:
	@for app in $(PKG_APPS); do $(MAKE) -C ./$$app/ clean || exit 1; done
	rm -f tdns-apps-*.tgz

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then echo "Must run as root"; exit 1; fi

install-dirs: check-root
	mkdir -p /usr/local/bin /etc/tdns

install: check-root install-dirs
	@for app in $(PKG_APPS); do $(MAKE) -C ./$$app/ install || exit 1; done

# The NetBSD binary package. See ../utils/mkpkg.sh for why a package and not a
# bintar. Needs root for the same reason "install" does: it packages what
# "install" put under the prefix.
#
# The .tgz is left here. Publishing is deliberately NOT a target: packages go
# into a per-osrelease tree on a lab dom0, and which trees exist is a property
# of the deployment, not of this repo.
pkg: check-root install-dirs all install
	PKGVERSION=$(PKGVER) \
	PKGCOMMENT="tdns-apps, DNS operator tools built on the tdns libraries" \
	/bin/sh ../utils/mkpkg.sh tdns-apps / \
	$(PKG_FILES)
