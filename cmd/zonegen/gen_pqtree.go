/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The pqtree generator: one child zone per KSK/ZSK algorithm pair.
 *
 * This is the tree the tool was originally built for. Now that it is one
 * generator among several, the PQ-specific parts -- the algorithm pairing, the
 * self-describing TXT that names the pair -- stop being lab detail leaking into
 * a generic tool and become this generator describing itself, which is what
 * they always were.
 *
 * Its input stays in the config file rather than moving to flags: a list of
 * algorithm pairs is too structured to be comfortable as a command line, and
 * unlike a record count it is not something you vary between runs.
 */

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func pqtreeCmd() *cobra.Command {
	var opts runOptions
	c := &cobra.Command{
		Use:   "pqtree",
		Short: "A parent zone with one child per KSK/ZSK algorithm pair",
		Long: `Generates a parent zone and one child zone per configured KSK/ZSK
algorithm pair, each bound to a DNSSEC policy for that pair.

The pairs come from zonegen.pqtree.children.combos in the config. Every pair is
checked against the algorithm registry, so an unknown name -- or a KSK-only
algorithm asked to serve as a ZSK -- is refused here rather than by tdns-auth
at zone load.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := loadForRun(&opts)
			if err != nil {
				return err
			}
			if opts.Zone != "" {
				conf.Zonegen.Pqtree.Parent.Name = dns.Fqdn(opts.Zone)
			}
			if err := conf.ValidatePqtree(); err != nil {
				return err
			}
			if err := conf.RequireOutput(opts.OutFile == ""); err != nil {
				return err
			}
			zs, err := buildPqtree(conf)
			if err != nil {
				return err
			}
			return runGenerate(conf, zs, &opts)
		},
	}
	opts.addCommonFlags(c)
	return c
}

// buildPqtree turns the config's algorithm pairs into a ZoneSet.
func buildPqtree(c *Config) (*ZoneSet, error) {
	z := &c.Zonegen
	p := &z.Pqtree.Parent
	ch := &z.Pqtree.Children
	d := &z.Defaults
	parentCombo := Combo{KSK: p.KSK, ZSK: p.ZSK}

	zs := &ZoneSet{
		Nameservers: p.Nameservers,
		Rname:       p.Rname,
		Apex:        p.Name,
		Policies:    pqPolicies(z),
	}

	// The parent, with its own addresses and a TXT saying what the tree is.
	parent := ZoneSpec{Name: p.Name, Policy: parentCombo.PolicyName()}
	for _, addr := range p.Addresses {
		parent.Records = append(parent.Records,
			fmt.Sprintf("%s\t%d\tIN\t%s\t%s", p.Name, d.TTL, addressRRType(addr), addr))
	}
	parent.Records = append(parent.Records, fmt.Sprintf("%s\t%d\tIN\tTXT\t%q", p.Name, d.TTL,
		fmt.Sprintf("PQ-DNSSEC testbed: one child zone per KSK/ZSK algorithm pair. See <ksk>-<zsk>.%s",
			strings.TrimSuffix(p.Name, "."))))
	zs.Zones = append(zs.Zones, parent)

	// One child per pair. Every child carries a self-describing apex TXT: in a
	// tree of near-identical zones, being able to ask a zone what it is turns
	// out to matter more than anything else in it.
	for _, combo := range ch.Combos {
		name := combo.Label(ch.Label) + "." + p.Name
		child := ZoneSpec{
			Name:     name,
			Policy:   combo.PolicyName(),
			Comments: []string{fmt.Sprintf("KSK %s / ZSK %s", combo.KSK, combo.ZSK)},
		}
		child.Records = append(child.Records,
			fmt.Sprintf("%s\t%d\tIN\tTXT\t%q", name, d.TTL, describeCombo(combo)))
		for _, addr := range ch.Addresses {
			child.Records = append(child.Records,
				fmt.Sprintf("%s\t%d\tIN\t%s\t%s", name, d.TTL, addressRRType(addr), addr))
		}
		for _, rec := range ch.Records {
			// Expanded through the parser rather than copied verbatim, so a
			// config line like "www IN A 192.0.2.2" comes out fully qualified
			// like everything else. Validated at config load, so an error here
			// is not reachable -- but silently emitting a bad line would be
			// worse than saying so.
			expanded, err := expandRecord(name, rec, d.TTL)
			if err != nil {
				return nil, fmt.Errorf("%s: record %q: %v", name, rec, err)
			}
			child.Records = append(child.Records, expanded)
		}
		zs.Zones = append(zs.Zones, child)

		// Recorded on the parent so the back half knows where the DS goes.
		zs.Zones[0].Children = append(zs.Zones[0].Children, name)
	}
	return zs, nil
}

// pqPolicies is one policy per distinct pair -- the children's, plus the
// parent's own, deduplicated (the parent commonly reuses a child's pair) and
// sorted so the emitted config is stable across runs.
func pqPolicies(z *ZonegenConf) []PolicySpec {
	seen := map[string]bool{}
	var out []PolicySpec
	all := append(append([]Combo{}, z.Pqtree.Children.Combos...),
		Combo{KSK: z.Pqtree.Parent.KSK, ZSK: z.Pqtree.Parent.ZSK})
	for _, c := range all {
		if seen[c.PolicyName()] {
			continue
		}
		seen[c.PolicyName()] = true
		out = append(out, PolicySpec{
			Name: c.PolicyName(), KSKAlg: c.KSK, ZSKAlg: c.ZSK,
			Mode: "ksk-zsk", KSKLife: "forever", ZSKLife: "forever",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
