/*
 * Johan Stenstam, johani@johani.org
 */
package cmd

import (
	traffic "github.com/johanix/traffic/traffic"
)

func init() {
//	cli.DaemonCmd.AddCommand(cli.DbConfigCmd, cli.DbAccessCmd)

	// from libcli/daemon_cmds.go:
//	rootCmd.AddCommand(cli.PingCmd)
//	rootCmd.AddCommand(cli.DaemonCmd)
//	rootCmd.AddCommand(cli.ProxyCmd)

	// from libcli/traffic_cmds.go:
	rootCmd.AddCommand(traffic.TrafficCmd)
}
