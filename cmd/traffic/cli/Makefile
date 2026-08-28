PROG:=traffic-cli

GO:=CGO_ENABLED=0 go

include ../utils/Makefile.common

install:
	install -b -c -s ${PROG} /usr/local/bin/

bintar:	bintar_statusd

dist:	dist_statusd

.PHONY: build clean bintar_statusd

