package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func writeConf(t *testing.T, combos string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "zonegen.yaml")
	conf := `
apiservers:
   - name: a
     baseurl: https://127.0.0.1:8080/api/v1
     apikey: k
zonegen:
   output:
      zonedir: ` + dir + `/zones
      configfile: ` + dir + `/out.yaml
   pqtree:
      parent:
         name: pq.example.
         nameservers: [ ns1.example. ]
         addresses: [ 192.0.2.1 ]
         ksk: ED25519
         zsk: ED25519
      children:
         addresses: [ 192.0.2.2 ]
         combos:
` + combos
	if err := os.WriteFile(path, []byte(conf), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// loadPq is the common preamble: load, then run the pqtree generator's own
// validation. Validation is per-generator now, so a config is only as valid as
// the generator that is about to use it.
func loadPq(t *testing.T, combos string) *Config {
	t.Helper()
	c, err := LoadConfig(writeConf(t, combos), true)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.ValidatePqtree(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return c
}

func buildPq(t *testing.T, c *Config, serial uint32) *ZoneSet {
	t.Helper()
	zs, err := buildPqtree(c)
	if err != nil {
		t.Fatalf("buildPqtree: %v", err)
	}
	zs.Serial = serial
	return zs
}

func TestConfigRefusesBadCombos(t *testing.T) {
	cases := map[string]string{
		"KSK-only algorithm as ZSK": "            - { ksk: ED25519, zsk: MLDSA87 }\n",
		"unknown algorithm":         "            - { ksk: NOPE, zsk: ED25519 }\n",
		"duplicate labels": "            - { ksk: ED25519, zsk: ED25519 }\n" +
			"            - { ksk: ED25519, zsk: ED25519 }\n",
		"no combos at all": "",
	}
	for name, combos := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := LoadConfig(writeConf(t, combos), true)
			if err == nil {
				err = c.ValidatePqtree()
			}
			if err == nil {
				t.Error("expected a refusal, got none")
			}
		})
	}
}

func TestConfigRefusesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	os.WriteFile(path, []byte("apiservers: []\nzonegen:\n   nosuchfield: 1\n"), 0600)
	if _, err := LoadConfig(path, true); err == nil || !strings.Contains(err.Error(), "nosuchfield") {
		t.Errorf("a mistyped key must be named in the error, got %v", err)
	}
}

// TestMissingConfigIsOnlyFatalWhenNamed: a generator taking its shape from
// flags and producing unsigned zones needs no config file, so the DEFAULT path
// not existing must not be an error. Naming a file that is not there still is.
func TestMissingConfigIsOnlyFatalWhenNamed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	if _, err := LoadConfig(missing, false); err != nil {
		t.Errorf("an absent default config must be tolerated, got %v", err)
	}
	if _, err := LoadConfig(missing, true); err == nil {
		t.Error("an explicitly named config that is absent must be an error")
	}
}

func TestConfigDefaultsAndSigValidity(t *testing.T) {
	c := loadPq(t, "            - { ksk: MLDSA87, zsk: ED25519 }\n")
	z := &c.Zonegen
	if z.Pqtree.Children.Label != "{ksk}-{zsk}" {
		t.Errorf("default label = %q", z.Pqtree.Children.Label)
	}
	if z.Pqtree.Parent.Rname != "hostmaster.pq.example." {
		t.Errorf("default rname = %q", z.Pqtree.Parent.Rname)
	}
	// tdns-auth rejects a policy with no sigvalidity.default, so the tool must
	// always have one to emit.
	if z.SigValidity.Default == "" || z.SigValidity.Dnskey == "" || z.SigValidity.DS == "" {
		t.Errorf("sigvalidity must default to something: %+v", z.SigValidity)
	}
	// The constants that used to be compiled in are now defaults, and must
	// still come out at the values every existing zone file was written with.
	d := &z.Defaults
	if d.TTL != 3600 || d.SOA.Refresh != 3600 || d.SOA.Retry != 600 ||
		d.SOA.Expire != 1209600 || d.SOA.Minimum != 600 {
		t.Errorf("defaults changed the historical values: %+v", d)
	}
	if d.Zone.Type != "primary" || d.Zone.Store != "map" {
		t.Errorf("zone declaration defaults changed: %+v", d.Zone)
	}
}

// TestGeneratedPolicyCarriesSigValidity is the regression test for the defect
// the first live run found: policies without sigvalidity are rejected at parse
// time and every zone bound to them is unusable.
func TestGeneratedPolicyCarriesSigValidity(t *testing.T) {
	c := loadPq(t, "            - { ksk: MLDSA87, zsk: ED25519 }\n")
	out := buildPq(t, c, NewSerial(time.Now(), 0)).AuthConfig(c)

	for _, want := range []string{
		"sigvalidity:", "default:  14d",
		"large-algorithms:  [ MLDSA87 ]", // derived, not configured
		"MLDSA87:  [ ED25519 ]",          // the split the pair requires
		"dnssecpolicy:  mldsa87-ed25519",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated config is missing %q:\n%s", want, out)
		}
	}
	// A policy for the parent's own pair must be there too, even though no
	// child uses it.
	if !strings.Contains(out, "ed25519-ed25519:") {
		t.Error("the parent's own policy is missing")
	}
}

func TestChildZonefileIsSelfDescribing(t *testing.T) {
	c := loadPq(t, "            - { ksk: MLDSA87, zsk: ED25519 }\n")
	zs := buildPq(t, c, 2026080600)
	out := zs.Render(&zs.Zones[1], &c.Zonegen.Defaults)

	// The apex TXT is the single most useful record in a tree of near-identical
	// zones: one query says what the zone is.
	if !strings.Contains(out, `"PQ-DNSSEC testbed: KSK=MLDSA87 (201) ZSK=ED25519 (15)"`) {
		t.Errorf("missing the self-describing TXT:\n%s", out)
	}
	if !strings.Contains(out, "2026080600") {
		t.Errorf("missing the serial:\n%s", out)
	}
}

// TestNewSerialIsDateBasedAndMonotonic pins both halves. The date floor is the
// readable part; the monotonicity is the part that was broken. The old code
// formatted "2006010200" believing the trailing "00" was an hour -- it is not a
// Go layout token, so it was emitted literally and every run on one day
// produced an identical serial. New content under an unchanged serial is
// invisible to every secondary, so the second case below is the real test.
func TestNewSerialIsDateBasedAndMonotonic(t *testing.T) {
	day := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	later := time.Date(2026, 8, 6, 23, 59, 0, 0, time.UTC)

	if got := NewSerial(day, 0); got != 2026080600 {
		t.Errorf("a new zone should get the date floor: got %d, want 2026080600", got)
	}
	// The case the old code got wrong: same day, existing serial.
	if got := NewSerial(later, 2026080600); got != 2026080601 {
		t.Errorf("a second run on one day must advance: got %d, want 2026080601", got)
	}
	// And keeps advancing, however many times.
	prev := uint32(0)
	for i := 0; i < 150; i++ {
		next := NewSerial(day, prev)
		if next <= prev && prev != 0 {
			t.Fatalf("serial went backwards or stalled at run %d: %d -> %d", i, prev, next)
		}
		prev = next
	}
	// A serial already ahead of the floor (yesterday's run, clock skew) is
	// advanced rather than reset backwards.
	if got := NewSerial(day, 2030010100); got != 2030010101 {
		t.Errorf("a serial ahead of the floor must not go backwards: got %d", got)
	}
}

// TestGeneratedZonesAreFullyQualified parses the generated zone files with an
// EMPTY origin. That is the whole test: with no origin, the parser cannot
// resolve a relative name, so this only succeeds if every owner name -- and
// every name in the rdata -- is already absolute. A "@" or a bare "www" fails
// here rather than in a zone file someone has to read.
func TestGeneratedZonesAreFullyQualified(t *testing.T) {
	c := loadPq(t, "            - { ksk: MLDSA87, zsk: ED25519 }\n")
	c.Zonegen.Pqtree.Children.Records = []string{"www  IN  A  192.0.2.2"}
	zs := buildPq(t, c, 2026082600)
	for i := range zs.Zones {
		zs.Zones[i].DS = []string{"12345 201 2 " + strings.Repeat("AB", 32)}
	}
	d := &c.Zonegen.Defaults

	for name, zonefile := range map[string]string{
		"parent": zs.Render(&zs.Zones[0], d),
		"child":  zs.Render(&zs.Zones[1], d),
	} {
		zp := dns.NewZoneParser(strings.NewReader(zonefile), "", "")
		n := 0
		for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
			n++
			if owner := rr.Header().Name; !dns.IsFqdn(owner) {
				t.Errorf("%s zone: owner %q is not fully qualified", name, owner)
			}
		}
		if err := zp.Err(); err != nil {
			t.Errorf("%s zone does not parse without an origin (a relative name?): %v\n%s",
				name, err, zonefile)
		}
		if n == 0 {
			t.Errorf("%s zone parsed to no records:\n%s", name, zonefile)
		}
	}
}

// The generated files say "do not edit by hand", so $ORIGIN would be dead
// weight -- and worse, an invitation to add a relative name that the rest of
// the file does not use.
func TestGeneratedZonesCarryNoOrigin(t *testing.T) {
	c := loadPq(t, "            - { ksk: ED25519, zsk: ED25519 }\n")
	zs := buildPq(t, c, 2026082600)
	d := &c.Zonegen.Defaults
	for _, out := range []string{zs.Render(&zs.Zones[0], d), zs.Render(&zs.Zones[1], d)} {
		if strings.Contains(out, "$ORIGIN") || strings.Contains(out, "$TTL") {
			t.Errorf("generated zone carries a directive it does not need:\n%s", out)
		}
	}
}

// TestSampleConfigIsValid keeps the shipped sample honest. It is installed as
// /etc/tdns/tdns-zonegen.sample.yaml and is the first thing an operator copies,
// so a sample that no longer parses is a worse bug than most.
func TestSampleConfigIsValid(t *testing.T) {
	c, err := LoadConfig("tdns-zonegen.sample.yaml", true)
	if err != nil {
		t.Fatalf("the shipped sample does not load: %v", err)
	}
	if err := c.ValidatePqtree(); err != nil {
		t.Fatalf("the shipped sample's pqtree section does not validate: %v", err)
	}
	zs, err := buildPqtree(c)
	if err != nil {
		t.Fatalf("the shipped sample does not generate: %v", err)
	}
	if len(zs.Zones) != 8 { // parent + 7 combos
		t.Errorf("sample should generate 8 zones, got %d", len(zs.Zones))
	}
}
