/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
	cli "github.com/johanix/tdns/v2/cli"
)

var cfgFile, cfgFileUsed string
var LocalConfig string

var cliflag bool
var appCtx context.Context
var appCancel context.CancelFunc

var rootCmd = &cobra.Command{
	Use:   "tdns-ddep",
	Short: "DNS Dependency Analyzer",
	Long:  `An instrumented recursive resolver for analyzing DNS dependencies of services`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if cliflag {
			cli.StartInteractiveMode()
			return
		} else {
			fmt.Printf("tdns-ddep: Starting in daemon mode, no CLI\n")
			cli.Conf.MainLoop(appCtx, appCancel)
		}
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func ExecuteContext(ctx context.Context) {
	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}

func init() {
	cobra.OnInitialize(initConfig, initDdep)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", tdns.DefaultImrCfgFile))
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d",
		false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&cliflag, "cli", "", false, "CLI mode")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v",
		false, "verbose output")

	cli.SetRootCommand(rootCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tdns.DefaultImrCfgFile)
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if tdns.Globals.Verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		log.Fatalf("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
	}

	LocalConfig = viper.GetString("imr.localconfig")
	if LocalConfig != "" {
		_, err := os.Stat(LocalConfig)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Fatalf("Error stat(%s): %v", LocalConfig, err)
			}
		} else {
			viper.SetConfigFile(LocalConfig)
			if err := viper.MergeInConfig(); err != nil {
				log.Fatalf("Error merging in local config from '%s': %v", LocalConfig, err)
			} else {
				if tdns.Globals.Verbose {
					fmt.Printf("Merging in local config from '%s'\n", LocalConfig)
				}
			}
		}
	}

	cli.ValidateConfig(nil, cfgFileUsed)
	err := viper.Unmarshal(&cli.Conf)
	if err != nil {
		log.Printf("Error from viper.UnMarshal(cfg): %v", err)
	}
}

func initDdep() {
	appCtx = rootCmd.Context()
	if appCtx == nil {
		appCtx = context.Background()
	}

	var cancel context.CancelFunc
	appCtx, cancel = context.WithCancel(appCtx)
	appCancel = cancel

	err := cli.Conf.MainInit(appCtx, "")
	if err != nil {
		tdns.Shutdowner(&cli.Conf, fmt.Sprintf("Error initializing tdns-ddep: %v", err))
	}

	// Load persistent block rules
	loadBlockRules()

	// SIGHUP reload watcher
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func(ctx context.Context, hup chan os.Signal) {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if _, err := cli.Conf.ParseZones(ctx, true); err != nil {
					log.Printf("SIGHUP reload failed: %v", err)
				}
			}
		}
	}(appCtx, hup)

	imrrouter, err := cli.Conf.SetupSimpleAPIRouter(appCtx)
	if err != nil {
		tdns.Shutdowner(&cli.Conf, fmt.Sprintf("Error setting up API router: %v", err))
	}
	err = cli.Conf.StartImr(appCtx, imrrouter)
	if err != nil {
		tdns.Shutdowner(&cli.Conf, fmt.Sprintf("Error starting threads: %v", err))
	}
}
