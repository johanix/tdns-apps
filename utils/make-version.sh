#!/bin/sh
appversion=$1
appdate=$2
prog=$3

# Check if we're on NetBSD
if [ "$(uname -s)" = "NetBSD" ]; then
    # On NetBSD, only create version.go if it doesn't exist
    if [ ! -f version.go ]; then
        echo "package main" > version.go
        echo "const appVersion = \"$appversion\"" >> version.go
        echo "const appDate = \"$appdate\"" >> version.go
        echo "const appName = \"$prog\"" >> version.go
    fi
    # If version.go exists, do nothing
    exit 0
else
    echo generating version.go
    {
    echo "package main"
    echo "const appVersion = \"${appversion}\""
    echo "const appDate = \"${appdate}\""
    echo "const appName = \"${prog}\""
    } > version.go || {
    echo "Error: Failed to generate version.go" >&2
    exit 1
    }
fi
