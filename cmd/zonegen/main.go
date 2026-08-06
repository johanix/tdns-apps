/*
 * tdns-zonegen -- generate a delegated zone tree with per-zone DNSSEC policies.
 *
 * Built for the PQ-DNSSEC testbed: one child zone per KSK/ZSK algorithm pair,
 * each signed with that pair, with the parent carrying the delegations and the
 * matching DS records. It is not PQ-specific, though -- the algorithm pairs
 * come from config and everything the generator knows about them comes from
 * the algorithm registry.
 *
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var cfgFile string

func main() {
	root := &cobra.Command{
		Use:   appName,
		Short: "Generate a delegated zone tree with per-zone DNSSEC policies",
		Long: `Generates a parent zone and one child zone per configured KSK/ZSK
algorithm pair, each bound to a DNSSEC policy for that pair.

The keys are created in the tdns-auth keystore first, so the DS records go
straight into the generated parent zone -- no second pass to collect them, and
no window where the zones are live with keys nobody has a DS for.

What it writes is meant to be reviewed and committed. What it does NOT do is
touch a running server's configuration or the parent zone of the tree.`,
		SilenceUsage: true,
	}
	root.PersistentFlags().StringVar(&cfgFile, "config", "/etc/tdns/tdns-zonegen.yaml", "config file")

	root.AddCommand(planCmd(), generateCmd(), delegationCmd(), versionCmd())
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

// planCmd validates the config and shows what would be generated. No API
// calls, no writes -- so it is safe to run against a config for a server that
// is not up yet, which is exactly when you want to check your algorithm pairs.
func planCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plan",
		Short: "Validate the config and show what would be generated (no changes)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := LoadConfig(cfgFile)
			if err != nil {
				return err
			}
			z := &conf.Zonegen
			parent := Combo{KSK: z.Parent.KSK, ZSK: z.Parent.ZSK}

			fmt.Printf("parent  %s\n", z.Parent.Name)
			fmt.Printf("        KSK %s / ZSK %s  (policy %s)\n\n",
				parent.KSK, parent.ZSK, parent.PolicyName())

			fmt.Printf("%d child zone(s):\n", len(z.Children.Combos))
			for _, c := range z.Children.Combos {
				name := c.Label(z.Children.Label) + "." + z.Parent.Name
				ksk, _ := lookupAlg(c.KSK)
				zsk, _ := lookupAlg(c.ZSK)
				flags := ""
				if ksk.IsLarge() {
					flags = "  [large KSK]"
				}
				fmt.Printf("  %-44s KSK %s (%d) / ZSK %s (%d)%s\n",
					name, ksk.Name, ksk.Codepoint, zsk.Name, zsk.Codepoint, flags)
			}

			if large := largeAlgorithms(z.Children.Combos, parent); len(large) > 0 {
				fmt.Printf("\nlarge_algorithms:  %v\n", large)
			}
			if split := splitAlgorithms(z.Children.Combos, parent); len(split) > 0 {
				fmt.Printf("split_algorithms:  %d KSK algorithm(s) paired with a different ZSK\n", len(split))
			}
			fmt.Printf("\nwould write:\n  %s\n  %s\n",
				z.Output.ZoneDir+"/ (one file per zone, plus the parent)", z.Output.ConfigFile)
			return nil
		},
	}
}

// generateCmd is the authoring pass.
func generateCmd() *cobra.Command {
	var keysOnly, filesOnly bool
	c := &cobra.Command{
		Use:   "generate",
		Short: "Create the keys, then write the zone files and config block",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := LoadConfig(cfgFile)
			if err != nil {
				return err
			}
			tree, err := buildTree(conf, keysOnly, filesOnly)
			if err != nil {
				return err
			}
			if keysOnly {
				return nil
			}
			return writeTree(tree)
		},
	}
	c.Flags().BoolVar(&keysOnly, "keys-only", false, "create the keys, write nothing")
	c.Flags().BoolVar(&filesOnly, "files-only", false,
		"write the files from the keys already in the keystore, creating none")
	return c
}

// delegationCmd re-prints the snippet for the parent of the tree's parent.
func delegationCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delegation",
		Short: "Print the NS + DS records to add to the parent of the tree",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := LoadConfig(cfgFile)
			if err != nil {
				return err
			}
			km, err := NewKeyManager(conf)
			if err != nil {
				return err
			}
			ds, err := km.CollectDS(conf.Zonegen.Parent.Name)
			if err != nil {
				return err
			}
			tree := &Tree{Conf: conf, ParentDS: ds}
			fmt.Print(tree.DelegationSnippet())
			return nil
		},
	}
}

// buildTree does the server-side half: ensure every zone's keys exist, then
// read back the DS records.
func buildTree(conf *Config, keysOnly, filesOnly bool) (*Tree, error) {
	km, err := NewKeyManager(conf)
	if err != nil {
		return nil, err
	}
	z := &conf.Zonegen
	tree := &Tree{Conf: conf, Serial: NewSerial(time.Now())}

	zones := []struct {
		name  string
		combo Combo
	}{{z.Parent.Name, Combo{KSK: z.Parent.KSK, ZSK: z.Parent.ZSK}}}
	for _, c := range z.Children.Combos {
		zones = append(zones, struct {
			name  string
			combo Combo
		}{c.Label(z.Children.Label) + "." + z.Parent.Name, c})
	}

	var created int
	for _, zn := range zones {
		if !filesOnly {
			n, err := km.EnsureKeys(zn.name, zn.combo)
			if err != nil {
				return nil, err
			}
			created += n
		}
		ds, err := km.CollectDS(zn.name)
		if err != nil {
			return nil, err
		}
		if len(ds) == 0 {
			return nil, fmt.Errorf("%s: no active KSK in the keystore, so there is no DS to "+
				"delegate with; run without --files-only", zn.name)
		}
		if zn.name == z.Parent.Name {
			tree.ParentDS = ds
			continue
		}
		tree.Children = append(tree.Children, Child{
			Combo: zn.combo,
			Label: zn.combo.Label(z.Children.Label),
			Name:  zn.name,
			DS:    ds,
		})
	}
	fmt.Printf("%d zone(s), %d key(s) created\n", len(zones), created)
	return tree, nil
}

// writeTree is the local half: everything here is a file an operator will read
// in a diff before it goes anywhere near a server.
func writeTree(t *Tree) error {
	for _, c := range t.Children {
		if err := writeFile(t.ZonefilePath(c.Name), t.childZonefile(c)); err != nil {
			return err
		}
	}
	parent := t.Conf.Zonegen.Parent.Name
	if err := writeFile(t.ZonefilePath(parent), t.parentZonefile()); err != nil {
		return err
	}
	if err := writeFile(t.Conf.Zonegen.Output.ConfigFile, t.authConfig()); err != nil {
		return err
	}

	fmt.Printf("wrote %d zone file(s) to %s\n", len(t.Children)+1, t.Conf.Zonegen.Output.ZoneDir)
	fmt.Printf("wrote the tdns-auth config block to %s\n\n", t.Conf.Zonegen.Output.ConfigFile)
	fmt.Printf("Still to do, by hand:\n")
	fmt.Printf("  1. merge %s into the tdns-auth config and reload\n", t.Conf.Zonegen.Output.ConfigFile)
	fmt.Printf("  2. add this delegation to the parent of %s:\n\n", parent)
	fmt.Print(t.DelegationSnippet())
	fmt.Printf("\n  3. export the keys so a rebuilt host keeps them:\n")
	fmt.Printf("     tdns-cli auth keystore dnssec bulk-export --dest <keydir> --zones %s\n",
		strings.TrimSuffix(parent, "."))
	return nil
}
