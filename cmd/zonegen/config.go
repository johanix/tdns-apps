/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The zonegen config: what tree to generate, and where to put it.
 */

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// Config is the whole config file.
type Config struct {
	ApiServers []ApiServerConf `yaml:"apiservers"`
	Zonegen    ZonegenConf     `yaml:"zonegen"`
}

// ApiServerConf points at the tdns-auth whose keystore holds the keys. Same
// shape as tdns-cli's, so an operator can copy the block across.
type ApiServerConf struct {
	Name       string `yaml:"name"`
	BaseUrl    string `yaml:"baseurl"`
	ApiKey     string `yaml:"apikey"`
	AuthMethod string `yaml:"authmethod"`
	RootCAFile string `yaml:"rootcafile"`
}

type ZonegenConf struct {
	Output      OutputConf      `yaml:"output"`
	SigValidity SigValidityConf `yaml:"sigvalidity"`
	Parent      ParentConf      `yaml:"parent"`
	Children    ChildrenConf    `yaml:"children"`
}

// SigValidityConf is the signature validity every generated policy gets.
// tdns-auth requires sigvalidity.default, so this block always ends up in the
// output; the fields here just decide what it says.
type SigValidityConf struct {
	Default string `yaml:"default"`
	Dnskey  string `yaml:"dnskey"`
	DS      string `yaml:"ds"`
}

type OutputConf struct {
	ZoneDir    string `yaml:"zonedir"`    // where the zone files land
	ConfigFile string `yaml:"configfile"` // the tdns-auth config block
	// ZoneFilePattern is how a zone name becomes a file name inside ZoneDir.
	// Defaults to "%s" (the zone name with its trailing dot), matching what
	// the tdns-auth zone declarations this tool emits will point at.
	ZoneFilePattern string `yaml:"zonefile-pattern"`
}

type ParentConf struct {
	Name        string   `yaml:"name"`
	Nameservers []string `yaml:"nameservers"`
	Addresses   []string `yaml:"addresses"`
	Rname       string   `yaml:"rname"`
	KSK         string   `yaml:"ksk"`
	ZSK         string   `yaml:"zsk"`
}

type ChildrenConf struct {
	// Label is the child's leftmost label, with {ksk} and {zsk} replaced by the
	// lowercased algorithm names.
	Label     string   `yaml:"label"`
	Addresses []string `yaml:"addresses"`
	Records   []string `yaml:"records"` // verbatim extra records, one per line
	Combos    []Combo  `yaml:"combos"`
}

// Combo is one KSK/ZSK algorithm pair, by registry name.
type Combo struct {
	KSK string `yaml:"ksk"`
	ZSK string `yaml:"zsk"`
}

const defaultTTL = 3600

// LoadConfig reads and validates the config file. Validation is deliberately
// strict and up front: this tool creates key material and writes files an
// operator will commit, so every objection should surface before any of that
// happens, not halfway through.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo in a key must not be silently ignored
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing %s: %v", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if len(c.ApiServers) == 0 {
		return fmt.Errorf("no apiservers: declared")
	}
	for i, a := range c.ApiServers {
		if a.BaseUrl == "" || a.ApiKey == "" {
			return fmt.Errorf("apiservers[%d]: baseurl and apikey are both required", i)
		}
	}

	z := &c.Zonegen
	if z.Output.ZoneDir == "" {
		return fmt.Errorf("zonegen.output.zonedir is required")
	}
	if z.Output.ConfigFile == "" {
		return fmt.Errorf("zonegen.output.configfile is required")
	}
	if z.Output.ZoneFilePattern == "" {
		z.Output.ZoneFilePattern = "%s"
	}

	// Defaults carried over from the testbed this tool replaces, which ran on
	// them for months. A long DNSKEY validity matters more than usual here:
	// re-signing a
	// DNSKEY RRset with a large PQ KSK is the expensive operation in the tree.
	if z.SigValidity.Default == "" {
		z.SigValidity.Default = "14d"
	}
	if z.SigValidity.Dnskey == "" {
		z.SigValidity.Dnskey = "30d"
	}
	if z.SigValidity.DS == "" {
		z.SigValidity.DS = "14d"
	}
	if !strings.Contains(z.Output.ZoneFilePattern, "%s") {
		return fmt.Errorf("zonegen.output.zonefile-pattern must contain %%s")
	}

	p := &z.Parent
	if p.Name == "" {
		return fmt.Errorf("zonegen.parent.name is required")
	}
	p.Name = dns.Fqdn(p.Name)
	if _, ok := dns.IsDomainName(p.Name); !ok {
		return fmt.Errorf("zonegen.parent.name %q is not a valid domain name", p.Name)
	}
	if len(p.Nameservers) == 0 {
		return fmt.Errorf("zonegen.parent.nameservers is required")
	}
	for i := range p.Nameservers {
		p.Nameservers[i] = dns.Fqdn(p.Nameservers[i])
	}
	if p.Rname == "" {
		p.Rname = "hostmaster." + p.Name
	}
	p.Rname = dns.Fqdn(p.Rname)
	if err := validateAddresses("zonegen.parent.addresses", p.Addresses); err != nil {
		return err
	}
	if p.KSK == "" || p.ZSK == "" {
		return fmt.Errorf("zonegen.parent.ksk and .zsk are both required")
	}
	if err := validateCombo(Combo{KSK: p.KSK, ZSK: p.ZSK}, "zonegen.parent"); err != nil {
		return err
	}
	p.KSK, p.ZSK = strings.ToUpper(p.KSK), strings.ToUpper(p.ZSK)

	ch := &z.Children
	if ch.Label == "" {
		ch.Label = "{ksk}-{zsk}"
	}
	if !strings.Contains(ch.Label, "{ksk}") || !strings.Contains(ch.Label, "{zsk}") {
		return fmt.Errorf("zonegen.children.label must contain both {ksk} and {zsk}, else the zones collide")
	}
	if err := validateAddresses("zonegen.children.addresses", ch.Addresses); err != nil {
		return err
	}
	if len(ch.Combos) == 0 {
		return fmt.Errorf("zonegen.children.combos is empty; nothing to generate")
	}

	seen := map[string]int{}
	for i := range ch.Combos {
		what := fmt.Sprintf("zonegen.children.combos[%d]", i)
		if err := validateCombo(ch.Combos[i], what); err != nil {
			return err
		}
		ch.Combos[i].KSK = strings.ToUpper(ch.Combos[i].KSK)
		ch.Combos[i].ZSK = strings.ToUpper(ch.Combos[i].ZSK)

		// Two combos that produce the same label would silently generate one
		// zone and quietly drop the other's keys into it.
		label := ch.Combos[i].Label(ch.Label)
		if prev, dup := seen[label]; dup {
			return fmt.Errorf("%s and combos[%d] both produce the label %q", what, prev, label)
		}
		seen[label] = i
	}

	// Parse each child's extra records once, here, against its own origin --
	// a syntax error found now names the config line, not a zone file the
	// operator has already committed.
	for _, combo := range ch.Combos {
		origin := combo.Label(ch.Label) + "." + p.Name
		for _, rec := range ch.Records {
			if _, err := dns.NewRR(fmt.Sprintf("$ORIGIN %s\n$TTL %d\n%s", origin, defaultTTL, rec)); err != nil {
				return fmt.Errorf("zonegen.children.records: %q is not a valid record: %v", rec, err)
			}
		}
	}
	return nil
}

// Label expands the label template for this combo, lowercased: zone names are
// case-insensitive but the files and config entries this tool writes are read
// by humans, and a mixed-case MLDSA87-ed25519 reads badly.
func (c Combo) Label(tmpl string) string {
	r := strings.NewReplacer("{ksk}", strings.ToLower(c.KSK), "{zsk}", strings.ToLower(c.ZSK))
	return r.Replace(tmpl)
}

// PolicyName is the DNSSEC policy this combo needs. One policy per pair, named
// after the pair, so the generated config reads as its own documentation.
func (c Combo) PolicyName() string {
	return strings.ToLower(c.KSK) + "-" + strings.ToLower(c.ZSK)
}

// validateCombo checks a pair against the algorithm registry rather than a
// hardcoded table: the registry already knows every algorithm's codepoint and
// whether it is usable as a ZSK, so a bad pair is caught here instead of by
// tdns-auth at zone load (or, worse, by a validator in the field).
func validateCombo(c Combo, what string) error {
	ksk, ok := lookupAlg(c.KSK)
	if !ok {
		return fmt.Errorf("%s: unknown KSK algorithm %q", what, c.KSK)
	}
	if !ksk.ForKSK {
		return fmt.Errorf("%s: %s cannot be used as a KSK", what, ksk.Name)
	}
	zsk, ok := lookupAlg(c.ZSK)
	if !ok {
		return fmt.Errorf("%s: unknown ZSK algorithm %q", what, c.ZSK)
	}
	if !zsk.ForZSK {
		return fmt.Errorf("%s: %s is KSK-only and cannot be used as a ZSK "+
			"(its signatures are too large to put on every RRset in a zone)", what, zsk.Name)
	}
	return nil
}

func validateAddresses(what string, addrs []string) error {
	for _, a := range addrs {
		if !isIPAddr(a) {
			return fmt.Errorf("%s: %q is not an IP address", what, a)
		}
	}
	return nil
}
