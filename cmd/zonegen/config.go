/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The zonegen config: the plumbing, not the shape.
 *
 * The shape of what gets generated -- how many names, which rrtypes, which
 * algorithm pairs -- belongs on the command line, where it is visible in shell
 * history and needs no file to try a variation. What lives here is the stuff
 * that is the same across every run on a host: where files go, how to reach the
 * server, and the defaults every zone inherits.
 *
 * A consequence worth stating: a generator that produces unsigned zones and
 * takes its shape from flags needs no config file at all.
 */

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const defaultConfigFile = "/etc/tdns/tdns-zonegen.yaml"

// Config is the whole config file.
type Config struct {
	ApiServers []ApiServerConf `yaml:"apiservers"`
	Zonegen    ZonegenConf     `yaml:"zonegen"`
}

// ApiServerConf points at the tdns-auth whose keystore holds the keys. Same
// shape as tdns-cli's, which is what lets --tdns-cli lift one verbatim.
type ApiServerConf struct {
	Name       string `yaml:"name"`
	BaseUrl    string `yaml:"baseurl"`
	ApiKey     string `yaml:"apikey"`
	AuthMethod string `yaml:"authmethod"`
	RootCAFile string `yaml:"rootcafile"`
}

type ZonegenConf struct {
	Output      OutputConf      `yaml:"output"`
	Defaults    DefaultsConf    `yaml:"defaults"`
	SigValidity SigValidityConf `yaml:"sigvalidity"`
	Pqtree      PqtreeConf      `yaml:"pqtree"`
}

// DefaultsConf holds what used to be compile-time constants. They are defaults
// rather than required fields: omitting the whole block reproduces the values
// the tool has always used.
type DefaultsConf struct {
	TTL  uint32       `yaml:"ttl"`
	SOA  SOAConf      `yaml:"soa"`
	Zone ZoneDeclConf `yaml:"zone"`
}

type SOAConf struct {
	Refresh uint32 `yaml:"refresh"`
	Retry   uint32 `yaml:"retry"`
	Expire  uint32 `yaml:"expire"`
	Minimum uint32 `yaml:"minimum"`
}

// ZoneDeclConf is what every generated zone declaration says, other than its
// name, file and policy.
type ZoneDeclConf struct {
	Type    string   `yaml:"type"`
	Store   string   `yaml:"store"`
	Options []string `yaml:"options"`
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
	// Defaults to "%s" (the zone name with its trailing dot).
	ZoneFilePattern string `yaml:"zonefile-pattern"`
}

// PqtreeConf is the pqtree generator's own section: the one generator whose
// input is too structured to be comfortable as flags.
type PqtreeConf struct {
	Parent   ParentConf   `yaml:"parent"`
	Children ChildrenConf `yaml:"children"`
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

// LoadConfig reads and validates the config file.
//
// A missing file is only an error when the operator named one: the default
// path not existing simply means this run is taking everything from flags,
// which is a supported way to use an unsigned generator.
func LoadConfig(path string, explicit bool) (*Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	switch {
	case err != nil && (explicit || !os.IsNotExist(err)):
		return nil, fmt.Errorf("reading %s: %v", path, err)
	case err == nil:
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true) // a typo in a key must not be silently ignored
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("parsing %s: %v", path, err)
		}
	}
	if err := c.applyDefaults(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return &c, nil
}

// applyDefaults fills in everything that has one. It deliberately does NOT
// validate any generator's own section: only the generator that was actually
// invoked gets to insist on its inputs.
func (c *Config) applyDefaults() error {
	z := &c.Zonegen
	if z.Output.ZoneFilePattern == "" {
		z.Output.ZoneFilePattern = "%s"
	}
	if !strings.Contains(z.Output.ZoneFilePattern, "%s") {
		return fmt.Errorf("zonegen.output.zonefile-pattern must contain %%s")
	}

	d := &z.Defaults
	if d.TTL == 0 {
		d.TTL = defaultTTL
	}
	// The SOA timers the tool has always emitted.
	if d.SOA.Refresh == 0 {
		d.SOA.Refresh = 3600
	}
	if d.SOA.Retry == 0 {
		d.SOA.Retry = 600
	}
	if d.SOA.Expire == 0 {
		d.SOA.Expire = 1209600
	}
	if d.SOA.Minimum == 0 {
		d.SOA.Minimum = 600
	}
	if d.Zone.Type == "" {
		d.Zone.Type = "primary"
	}
	if d.Zone.Store == "" {
		d.Zone.Store = "map"
	}
	if d.Zone.Options == nil {
		d.Zone.Options = []string{"online-signing"}
	}

	// Defaults carried over from the testbed this tool replaces, which ran on
	// them for months. A long DNSKEY validity matters more than usual here:
	// re-signing a DNSKEY RRset with a large PQ KSK is the expensive operation.
	if z.SigValidity.Default == "" {
		z.SigValidity.Default = "14d"
	}
	if z.SigValidity.Dnskey == "" {
		z.SigValidity.Dnskey = "30d"
	}
	if z.SigValidity.DS == "" {
		z.SigValidity.DS = "14d"
	}
	return nil
}

// RequireOutput is called by generators once they know where they are writing.
// zonedir is only needed when the generator did not get an explicit --outfile.
func (c *Config) RequireOutput(needZoneDir bool) error {
	if needZoneDir && c.Zonegen.Output.ZoneDir == "" {
		return fmt.Errorf("no output directory: set zonegen.output.zonedir or pass --outfile")
	}
	return nil
}

// ZonefilePath is where a zone's file goes, and equally what the generated
// tdns-auth config will point at. One function so the two cannot disagree.
func (c *Config) ZonefilePath(zone string) string {
	return filepath.Join(c.Zonegen.Output.ZoneDir,
		fmt.Sprintf(c.Zonegen.Output.ZoneFilePattern, zone))
}

// ValidatePqtree checks the pqtree section. Only pqtree calls it, so a config
// with no pqtree: block is perfectly valid for every other generator.
func (c *Config) ValidatePqtree() error {
	p := &c.Zonegen.Pqtree.Parent
	ch := &c.Zonegen.Pqtree.Children

	if p.Name == "" {
		return fmt.Errorf("zonegen.pqtree.parent.name is required")
	}
	p.Name = dns.Fqdn(p.Name)
	if _, ok := dns.IsDomainName(p.Name); !ok {
		return fmt.Errorf("zonegen.pqtree.parent.name %q is not a valid domain name", p.Name)
	}
	if len(p.Nameservers) == 0 {
		return fmt.Errorf("zonegen.pqtree.parent.nameservers is required")
	}
	for i := range p.Nameservers {
		p.Nameservers[i] = dns.Fqdn(p.Nameservers[i])
	}
	if p.Rname == "" {
		p.Rname = "hostmaster." + p.Name
	}
	p.Rname = dns.Fqdn(p.Rname)
	if err := validateAddresses("zonegen.pqtree.parent.addresses", p.Addresses); err != nil {
		return err
	}
	if p.KSK == "" || p.ZSK == "" {
		return fmt.Errorf("zonegen.pqtree.parent.ksk and .zsk are both required")
	}
	if err := validateCombo(Combo{KSK: p.KSK, ZSK: p.ZSK}, "zonegen.pqtree.parent"); err != nil {
		return err
	}
	p.KSK, p.ZSK = strings.ToUpper(p.KSK), strings.ToUpper(p.ZSK)

	if ch.Label == "" {
		ch.Label = "{ksk}-{zsk}"
	}
	if !strings.Contains(ch.Label, "{ksk}") || !strings.Contains(ch.Label, "{zsk}") {
		return fmt.Errorf("zonegen.pqtree.children.label must contain both {ksk} and {zsk}, else the zones collide")
	}
	if err := validateAddresses("zonegen.pqtree.children.addresses", ch.Addresses); err != nil {
		return err
	}
	if len(ch.Combos) == 0 {
		return fmt.Errorf("zonegen.pqtree.children.combos is empty; nothing to generate")
	}

	seen := map[string]int{}
	for i := range ch.Combos {
		what := fmt.Sprintf("zonegen.pqtree.children.combos[%d]", i)
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
			if _, err := expandRecord(origin, rec, c.Zonegen.Defaults.TTL); err != nil {
				return fmt.Errorf("zonegen.pqtree.children.records: %q is not a valid record: %v", rec, err)
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
