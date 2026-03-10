/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for the DNS dependency analyzer.
 */
package main

import (
	"fmt"
	"sort"
	"strings"

	cli "github.com/johanix/tdns/v2/cli"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// --- session command ---

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage query recording sessions",
}

var sessionStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start recording queries",
	Run: func(cmd *cobra.Command, args []string) {
		session.Start()
		fmt.Println("Session started. All client and iterative queries will be recorded.")
	},
}

var sessionStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop recording queries",
	Run: func(cmd *cobra.Command, args []string) {
		session.Stop()
		entries := session.Entries()
		fmt.Printf("Session stopped. %d queries recorded.\n", len(entries))
	},
}

var sessionShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show recorded queries",
	Long: `Show recorded queries from the current session.

Flags:
  --unique   Deduplicate: show each (qname, qtype, category) only once

Output is sorted by reverse domain name (TLD first, then SLD, etc.).`,
	Run: showQueries,
}

// reverseLabels returns the labels of a DNS name in reverse order for sorting.
// "www.example.com." → ["com", "example", "www"]
func reverseLabels(qname string) []string {
	qname = strings.TrimSuffix(strings.ToLower(qname), ".")
	labels := strings.Split(qname, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
}

// compareReverseQname compares two qnames by their reverse label order.
func compareReverseQname(a, b string) int {
	la := reverseLabels(a)
	lb := reverseLabels(b)
	n := len(la)
	if len(lb) < n {
		n = len(lb)
	}
	for i := 0; i < n; i++ {
		if la[i] < lb[i] {
			return -1
		}
		if la[i] > lb[i] {
			return 1
		}
	}
	return len(la) - len(lb)
}

func showQueries(cmd *cobra.Command, args []string) {
	unique, _ := cmd.Flags().GetBool("unique")

	entries := session.Entries()
	if len(entries) == 0 {
		fmt.Println("No queries recorded.")
		return
	}

	// Deduplicate if --unique
	if unique {
		seen := make(map[string]struct{})
		filtered := entries[:0:0]
		for _, e := range entries {
			key := fmt.Sprintf("%s|%d|%d", strings.ToLower(e.Qname), e.Qtype, e.Category)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			filtered = append(filtered, e)
		}
		entries = filtered
	}

	// Sort by reverse qname, then by qtype
	sort.Slice(entries, func(i, j int) bool {
		cmp := compareReverseQname(entries[i].Qname, entries[j].Qname)
		if cmp != 0 {
			return cmp < 0
		}
		if entries[i].Category != entries[j].Category {
			return entries[i].Category < entries[j].Category
		}
		return entries[i].Qtype < entries[j].Qtype
	})

	fmt.Printf("%-6s %-10s %-40s %-8s %-6s %-30s %s\n",
		"ID", "Category", "Qname", "Qtype", "Rcode", "Server", "Notes")
	fmt.Println(strings.Repeat("-", 120))

	for _, e := range entries {
		cat := "CLIENT"
		if e.Category == QueryIterative {
			cat = "ITER"
		}
		qtypeStr := dns.TypeToString[e.Qtype]
		if qtypeStr == "" {
			qtypeStr = fmt.Sprintf("TYPE%d", e.Qtype)
		}

		server := ""
		if e.ServerName != "" {
			server = fmt.Sprintf("%s (%s)", e.ServerName, e.ServerAddr)
		}

		notes := ""
		if e.Blocked {
			notes = fmt.Sprintf("BLOCKED by %s", e.BlockRule)
		}
		if e.ParentID > 0 && e.Category == QueryIterative {
			if notes != "" {
				notes += " "
			}
			notes += fmt.Sprintf("(parent=%d)", e.ParentID)
		}

		rcodeStr := dns.RcodeToString[e.Rcode]
		if rcodeStr == "" {
			rcodeStr = fmt.Sprintf("%d", e.Rcode)
		}

		fmt.Printf("%-6d %-10s %-40s %-8s %-6s %-30s %s\n",
			e.ID, cat, e.Qname, qtypeStr, rcodeStr, server, notes)
	}

	if unique {
		fmt.Printf("\n%d unique queries shown (from %d total)\n", len(entries), len(session.Entries()))
	}
}

var sessionClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear recorded queries without stopping the session",
	Run: func(cmd *cobra.Command, args []string) {
		wasActive := session.IsActive()
		session.Start() // resets entries
		if !wasActive {
			session.Stop()
		}
		fmt.Println("Session entries cleared.")
	},
}

var sessionFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush resolver cache, clear query log, and start a fresh session",
	Run: func(cmd *cobra.Command, args []string) {
		// Flush the resolver cache (everything except root priming data)
		removed := 0
		if cli.Conf.Internal.RRsetCache != nil {
			removed = cli.Conf.Internal.RRsetCache.FlushAll()
		}

		// Clear query log and start fresh session
		session.Start()

		fmt.Printf("Cache flushed (%d entries removed). Session started.\n", removed)
	},
}

// --- block command ---

var blockCmd = &cobra.Command{
	Use:   "block [action] [qname] [qtype]",
	Short: "Add a block rule",
	Long: `Add a block rule for DNS queries.

Actions:
  nxdomain  - Return NXDOMAIN
  nodata    - Return NODATA (NOERROR with empty answer)
  drop      - Drop the query (client times out)
  redirect  - Redirect to an IP address (use --redirect-to)
  allow     - Whitelist (override other blocks, RPZ PASSTHRU)

The qtype argument is optional. If omitted, all query types are blocked.
Wildcard patterns are supported: *.example.com blocks all subdomains.

Examples:
  block nxdomain tracker.example.com
  block nodata ads.example.com A
  block drop *.badsite.com
  block redirect evil.com --redirect-to 127.0.0.1
  block allow safe.example.com`,
	Args: cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		actionStr := strings.ToLower(args[0])
		action, ok := stringToBlockAction[actionStr]
		if !ok {
			fmt.Printf("Unknown block action: %q. Valid: nxdomain, nodata, drop, redirect, allow\n", actionStr)
			return
		}

		pattern := dns.Fqdn(args[0+1])

		var qtype uint16
		if len(args) == 3 {
			qtypeStr := strings.ToUpper(args[2])
			qt, exists := dns.StringToType[qtypeStr]
			if !exists {
				fmt.Printf("Unknown query type: %q\n", args[2])
				return
			}
			qtype = qt
		}

		if action == BlockActionRedirect && redirectTo == "" {
			fmt.Println("Redirect action requires --redirect-to flag with an IP address.")
			return
		}

		rule := BlockRule{
			Pattern:    pattern,
			Action:     action,
			Qtype:      qtype,
			RedirectTo: redirectTo,
		}
		blockRules.Add(rule)

		qtypeDisplay := "ALL"
		if qtype != 0 {
			qtypeDisplay = dns.TypeToString[qtype]
		}
		fmt.Printf("Block rule added: %s %s %s\n", actionStr, pattern, qtypeDisplay)
	},
}

var redirectTo string

// --- unblock command ---

var unblockCmd = &cobra.Command{
	Use:   "unblock [qname] [qtype]",
	Short: "Remove a block rule",
	Long: `Remove a block rule. The qtype argument is optional.
If qtype is specified, only the rule matching both pattern and qtype is removed.
If qtype is omitted, the first rule matching the pattern is removed.

Examples:
  unblock tracker.example.com
  unblock ads.example.com A`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		pattern := dns.Fqdn(args[0])
		var qtype uint16
		if len(args) == 2 {
			qtypeStr := strings.ToUpper(args[1])
			qt, exists := dns.StringToType[qtypeStr]
			if !exists {
				fmt.Printf("Unknown query type: %q\n", args[1])
				return
			}
			qtype = qt
		}

		if blockRules.Remove(pattern, qtype) {
			fmt.Printf("Block rule removed: %s\n", pattern)
		} else {
			fmt.Printf("No matching block rule found for: %s\n", pattern)
		}
	},
}

// --- list command ---

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List queries or block rules",
}

var listQueriesCmd = &cobra.Command{
	Use:   "queries",
	Short: "List recorded queries from the current session",
	Run:   showQueries,
}

var listBlocksCmd = &cobra.Command{
	Use:   "blocks",
	Short: "List active block rules",
	Run: func(cmd *cobra.Command, args []string) {
		rules := blockRules.List()
		if len(rules) == 0 {
			fmt.Println("No block rules configured.")
			return
		}

		fmt.Printf("%-4s %-12s %-40s %-8s %s\n",
			"#", "Action", "Pattern", "Qtype", "Redirect")
		fmt.Println(strings.Repeat("-", 80))

		for i, r := range rules {
			qtypeStr := "ALL"
			if r.Qtype != 0 {
				qtypeStr = dns.TypeToString[r.Qtype]
			}
			actionStr := blockActionToString[r.Action]
			redirect := ""
			if r.RedirectTo != "" {
				redirect = r.RedirectTo
			}
			fmt.Printf("%-4d %-12s %-40s %-8s %s\n",
				i+1, actionStr, r.Pattern, qtypeStr, redirect)
		}
	},
}

var clearBlocksCmd = &cobra.Command{
	Use:   "clearblocks",
	Short: "Remove all block rules",
	Run: func(cmd *cobra.Command, args []string) {
		blockRules.Clear()
		fmt.Println("All block rules cleared.")
	},
}

func init() {
	// session subcommands
	sessionCmd.AddCommand(sessionStartCmd, sessionStopCmd, sessionShowCmd, sessionClearCmd, sessionFlushCmd)

	// show/list queries flags
	sessionShowCmd.Flags().Bool("unique", false, "Show each (qname, qtype, category) only once")
	listQueriesCmd.Flags().Bool("unique", false, "Show each (qname, qtype, category) only once")

	// block flag
	blockCmd.Flags().StringVar(&redirectTo, "redirect-to", "", "IP address to redirect to (for redirect action)")

	// list subcommands
	listCmd.AddCommand(listQueriesCmd, listBlocksCmd)

	// Register top-level commands
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(clearBlocksCmd)
}
