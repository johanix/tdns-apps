/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	cli "github.com/johanix/tdns/v2/cli"
)

func init() {
	// Standard IMR commands
	rootCmd.AddCommand(cli.ImrDumpCmd)
	rootCmd.AddCommand(cli.ImrQueryCmd)
	rootCmd.AddCommand(cli.ImrStatsCmd)
	rootCmd.AddCommand(cli.ImrShowCmd)
	rootCmd.AddCommand(cli.ImrFlushCmd)
	rootCmd.AddCommand(cli.ImrSetCmd)
	rootCmd.AddCommand(cli.ImrZoneCmd)
	rootCmd.AddCommand(cli.ExitCmd)
	rootCmd.AddCommand(cli.QuitCmd)

	// Dependency analysis commands
	rootCmd.AddCommand(sessionCmd)
	rootCmd.AddCommand(blockCmd)
	rootCmd.AddCommand(unblockCmd)
}
