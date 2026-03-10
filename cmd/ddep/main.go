/*
 * tdns-ddep - DNS Dependency Analyzer
 *
 * A derivative of tdns-imr that instruments the recursive resolver to
 * discover and analyze external DNS dependencies of a service.
 *
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	tdns "github.com/johanix/tdns/v2"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeImr
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Date = appDate

	// Register IMR hooks before TDNS initialization
	registerDdepHooks()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ExecuteContext(ctx)
}
