/*
 * tdns-zonegen -- generate DNS zones of various shapes, with their keys.
 *
 * One subcommand per kind of zone. They share everything downstream of "what
 * zones exist and what is in them": creating the keys in the tdns-auth
 * keystore, reading back the DS so delegations are complete on first write,
 * rendering, writing atomically, and emitting the tdns-auth config block.
 *
 * What it writes is meant to be reviewed and committed. What it does NOT do is
 * touch a running server's configuration, or the parent zone of whatever it
 * generates.
 *
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	cfgFile     string
	cfgExplicit bool
)

func main() {
	root := &cobra.Command{
		Use:   appName,
		Short: "Generate DNS zones of various shapes, with their keys",
		Long: `Generates zones and the tdns-auth configuration to serve them.

Each subcommand is a different kind of zone:

  pqtree    a parent with one child per KSK/ZSK algorithm pair
  tree      a delegated hierarchy of ordinary zones
  bigzone   one zone with many names and a mix of rrtypes
  rpz       a response-policy zone with many rules

Signing is per-generator. A generator producing unsigned zones never contacts
the keystore, and so needs no API connection and no config file at all.`,
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			cfgExplicit = cmd.Root().PersistentFlags().Changed("config")
		},
	}
	root.PersistentFlags().StringVar(&cfgFile, "config", defaultConfigFile, "config file")

	root.AddCommand(pqtreeCmd(), treeCmd(), bigzoneCmd(), rpzCmd(), versionCmd())
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

// runOptions are the flags every generator shares.
type runOptions struct {
	Api ApiOptions

	Zone    string // --zone: the zone to generate (the apex, for tree generators)
	OutFile string // --outfile: write this single zone here, ignoring zonedir
	Plan    bool   // --plan: validate and describe, change nothing

	// Update is the percentage of a zone's content to churn, for generators
	// that support rewriting an existing file. Zero means a fresh generation.
	Update float64
	Force  bool // --force: rewrite a file this tool did not write

	KeysOnly  bool
	FilesOnly bool
}

func (o *runOptions) addCommonFlags(c *cobra.Command) {
	c.Flags().StringVar(&o.Zone, "zone", "", "the zone to generate")
	c.Flags().StringVar(&o.OutFile, "outfile", "", "write the zone here instead of into zonedir")
	c.Flags().BoolVar(&o.Plan, "plan", false, "validate and describe what would be generated, change nothing")
	o.Api.AddApiFlags(c.Flags())
}

// addUpdateFlags is for generators whose content can be churned in place.
func (o *runOptions) addUpdateFlags(c *cobra.Command) {
	c.Flags().Float64Var(&o.Update, "update", 0,
		"rewrite an existing zone file, changing roughly this percentage of its content")
	c.Flags().BoolVar(&o.Force, "force", false,
		"allow --update on a file this tool did not generate")
}

func loadForRun(o *runOptions) (*Config, error) {
	return LoadConfig(cfgFile, cfgExplicit)
}

// zonePath is where a generator's zone goes: --outfile when given, otherwise
// the configured zonedir.
func zonePath(c *Config, o *runOptions, zone string) string {
	if o.OutFile != "" {
		return o.OutFile
	}
	return c.ZonefilePath(zone)
}

// runGenerate is the shared back half: keys, DS, files, config block.
func runGenerate(c *Config, zs *ZoneSet, o *runOptions) error {
	if zs.Serial == 0 {
		// Read the serial of whatever is being overwritten. Without this a
		// second run on the same day stamps the same YYYYMMDD00 over changed
		// content -- the original serial bug, surviving on the path operators
		// actually use when they change flags and regenerate. The set shares
		// one serial, so the floor is the highest of the files it replaces.
		var prev uint32
		for i := range zs.Zones {
			if s := previousSerialOf(zonePath(c, o, zs.Zones[i].Name), zs.Zones[i].Name); s > prev {
				prev = s
			}
		}
		zs.Serial = NewSerial(nowFunc(), prev)
	}
	if o.OutFile != "" && len(zs.Zones) > 1 {
		return fmt.Errorf("--outfile names a single file but this generates %d zones; "+
			"use zonegen.output.zonedir instead", len(zs.Zones))
	}

	if o.Plan {
		printPlan(c, zs, o)
		return nil
	}

	if zs.NeedsKeys() && !o.FilesOnly {
		if err := ensureKeys(c, zs, o); err != nil {
			return err
		}
		if o.KeysOnly {
			return nil
		}
	} else if zs.NeedsKeys() && o.FilesOnly {
		// Still need the DS to write complete delegations.
		if err := collectDSOnly(c, zs, o); err != nil {
			return err
		}
	}

	d := &c.Zonegen.Defaults
	for i := range zs.Zones {
		z := &zs.Zones[i]
		if err := writeFile(zonePath(c, o, z.Name), zs.Render(z, d)); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d zone file(s)\n", len(zs.Zones))

	// An update rewrites content for a zone the server already knows about, so
	// re-emitting the config block would only produce a file that says what it
	// said last time.
	if o.Update == 0 && c.Zonegen.Output.ConfigFile != "" {
		if err := writeFile(c.Zonegen.Output.ConfigFile, zs.AuthConfig(c)); err != nil {
			return err
		}
		fmt.Printf("wrote the tdns-auth config block to %s\n", c.Zonegen.Output.ConfigFile)
		printNextSteps(c, zs)
	}
	return nil
}

// ensureKeys creates whatever keys the set's zones are missing and reads back
// the DS records, so delegations are complete the first time they are written.
func ensureKeys(c *Config, zs *ZoneSet, o *runOptions) error {
	km, origin, err := newKeyManagerFor(c, o)
	if err != nil {
		return err
	}
	fmt.Printf("keystore: %s (%s)\n", km.BaseUrl(), origin)

	byPolicy := map[string]PolicySpec{}
	for _, p := range zs.Policies {
		byPolicy[p.Name] = p
	}
	var created int
	for i := range zs.Zones {
		z := &zs.Zones[i]
		if z.Policy == "" {
			continue
		}
		p, ok := byPolicy[z.Policy]
		if !ok {
			return fmt.Errorf("%s names policy %q, which the generator did not define",
				z.Name, z.Policy)
		}
		n, err := km.EnsureKeys(z.Name, p.KSKAlg, p.ZSKAlg)
		if err != nil {
			return err
		}
		created += n
		if z.DS, err = km.CollectDS(z.Name); err != nil {
			return err
		}
		if len(z.DS) == 0 {
			return fmt.Errorf("%s: no active KSK in the keystore, so there is no DS to "+
				"delegate with", z.Name)
		}
	}
	fmt.Printf("%d zone(s), %d key(s) created\n", len(zs.Zones), created)
	return nil
}

func collectDSOnly(c *Config, zs *ZoneSet, o *runOptions) error {
	km, origin, err := newKeyManagerFor(c, o)
	if err != nil {
		return err
	}
	fmt.Printf("keystore: %s (%s), reading DS only\n", km.BaseUrl(), origin)
	for i := range zs.Zones {
		z := &zs.Zones[i]
		if z.Policy == "" {
			continue
		}
		if z.DS, err = km.CollectDS(z.Name); err != nil {
			return err
		}
		if len(z.DS) == 0 {
			return fmt.Errorf("%s: no active KSK in the keystore, so there is no DS to "+
				"delegate with; run without --files-only", z.Name)
		}
	}
	return nil
}

func newKeyManagerFor(c *Config, o *runOptions) (*KeyManager, string, error) {
	server, origin, err := ResolveApiServer(c, o.Api)
	if err != nil {
		return nil, "", err
	}
	km, err := NewKeyManager(server)
	return km, origin, err
}

func printPlan(c *Config, zs *ZoneSet, o *runOptions) {
	fmt.Printf("%d zone(s):\n", len(zs.Zones))
	for i := range zs.Zones {
		z := &zs.Zones[i]
		policy := z.Policy
		if policy == "" {
			policy = "unsigned"
		}
		extra := ""
		if n := len(z.Children); n > 0 {
			extra = fmt.Sprintf("  [%d delegation(s)]", n)
		}
		fmt.Printf("  %-52s %-24s %5d record(s)%s\n", z.Name, policy, len(z.Records), extra)
	}
	if len(zs.Policies) > 0 {
		if large := largeAlgorithmsOf(zs.Policies); len(large) > 0 {
			fmt.Printf("\nlarge_algorithms:  %v\n", large)
		}
		if split := splitAlgorithmsOf(zs.Policies); len(split) > 0 {
			fmt.Printf("split_algorithms:  %d KSK algorithm(s) paired with a different ZSK\n", len(split))
		}
	}
	fmt.Printf("\nwould write:\n")
	for i := range zs.Zones {
		fmt.Printf("  %s\n", zonePath(c, o, zs.Zones[i].Name))
	}
	if o.Update == 0 && c.Zonegen.Output.ConfigFile != "" {
		fmt.Printf("  %s\n", c.Zonegen.Output.ConfigFile)
	}
}

func printNextSteps(c *Config, zs *ZoneSet) {
	fmt.Printf("\nStill to do, by hand:\n")
	fmt.Printf("  1. merge %s into the tdns-auth config and reload\n", c.Zonegen.Output.ConfigFile)
	if snippet := zs.DelegationSnippet(); snippet != "" {
		fmt.Printf("  2. add this delegation to the parent of %s:\n\n", zs.Apex)
		fmt.Print(snippet)
	}
	if zs.NeedsKeys() && zs.Apex != "" {
		fmt.Printf("\n  3. export the keys so a rebuilt host keeps them:\n")
		fmt.Printf("     tdns-cli auth keystore dnssec bulk-export --dest <keydir> --zones %s\n",
			strings.TrimSuffix(zs.Apex, "."))
	}
}
