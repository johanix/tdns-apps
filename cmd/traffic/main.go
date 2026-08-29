/*
 * tdns-traffic -- a DNS query load generator.
 *
 * Sends DNS queries to one or more target nameservers, varying the query rate
 * over time according to a chosen shape, so a server can be watched under a
 * traffic pattern rather than a flat flood. A run can detach and keep going in
 * the background, driven afterwards with stop/extend/status over a control
 * socket.
 *
 * This file is the whole app: everything it does lives in
 * github.com/johanix/tdns-apps/lib/traffic, which is also where a second
 * consumer would reach it.
 *
 * Copyright (c) 2025-2026 Johan Stenstam, johani@johani.org
 */

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/johanix/tdns-apps/lib/traffic"
)

// defaultConfigFile sits with the other tdns apps' configs rather than in
// $HOME, so a host running several of them keeps them together.
const defaultConfigFile = "/etc/tdns/tdns-traffic.yaml"

var cfgFile string

func main() {
	root := &cobra.Command{
		Use:   appName,
		Short: "Generate DNS query traffic in configurable rate shapes",
		Long: `Sends DNS queries to one or more targets, varying the rate over time
according to a shape (trapezoid, arch, sine, peaks, ...).

  ` + appName + ` run --shape trapezoid --max 5000 --cycle 2m -t 192.0.2.1 --qname example.com

With --server the run detaches and keeps going in the background; stop, extend
and status then drive it over a control socket.`,
		SilenceUsage: true,
	}

	cobra.OnInitialize(initConfig)
	root.PersistentFlags().StringVar(&cfgFile, "config", defaultConfigFile,
		"config file (supplies traffic.names, the qname list)")

	// The library hands back its commands rather than a parent to hang them
	// from, so they sit directly under the binary: `tdns-traffic run`, not
	// `tdns-traffic traffic run`.
	traffic.RegisterFlags(root.PersistentFlags())
	root.AddCommand(traffic.Commands()...)
	root.AddCommand(versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s version %s (%s)\n", appName, appVersion, appDate)
		},
	}
}

// initConfig reads the config file if there is one.
//
// A missing config is not an error: the only thing read from it is
// traffic.names, and --qname or --qname-file supply the same list from the
// command line. Staying quiet when the default path is absent keeps a one-off
// invocation clean, while a file the operator named explicitly and which
// cannot be read is worth failing on.
func initConfig() {
	viper.SetConfigFile(cfgFile)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if cfgFile != defaultConfigFile {
			fmt.Fprintf(os.Stderr, "%s: cannot read %s: %v\n", appName, cfgFile, err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
}
