PROG:=tdns-sewhois

GOOS ?= $(shell uname -s | tr A-Z a-z)
GO:= go
include ../../utils/Makefile.common

.PHONY: clean install

install:
	install -s -b -c ${PROG} /usr/local/bin/

clean:
	rm -f $(PROG)
	find . -type f -name '*~' -delete
