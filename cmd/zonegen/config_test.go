package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
   parent:
      name: pq.dnslab.
      nameservers: [ ns1.dnslab. ]
      addresses: [ 172.16.1.100 ]
      ksk: ED25519
      zsk: ED25519
   children:
      addresses: [ 172.16.0.1 ]
      combos:
` + combos
	if err := os.WriteFile(path, []byte(conf), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestConfigRefusesBadCombos(t *testing.T) {
	cases := map[string]string{
		"KSK-only algorithm as ZSK": "         - { ksk: ED25519, zsk: MLDSA87 }\n",
		"unknown algorithm":         "         - { ksk: NOPE, zsk: ED25519 }\n",
		"duplicate labels": "         - { ksk: ED25519, zsk: ED25519 }\n" +
			"         - { ksk: ED25519, zsk: ED25519 }\n",
		"no combos at all": "",
	}
	for name, combos := range cases {
		if _, err := LoadConfig(writeConf(t, combos)); err == nil {
			t.Errorf("%s: should have been refused", name)
		}
	}
}

func TestConfigRefusesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	os.WriteFile(path, []byte("apiservers: []\nzonegen:\n   nosuchfield: 1\n"), 0600)
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "nosuchfield") {
		t.Errorf("a mistyped key must be named in the error, got %v", err)
	}
}

func TestConfigDefaultsAndSigValidity(t *testing.T) {
	c, err := LoadConfig(writeConf(t, "         - { ksk: MLDSA87, zsk: ED25519 }\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	z := &c.Zonegen
	if z.Children.Label != "{ksk}-{zsk}" {
		t.Errorf("default label = %q", z.Children.Label)
	}
	if z.Parent.Rname != "hostmaster.pq.dnslab." {
		t.Errorf("default rname = %q", z.Parent.Rname)
	}
	// tdns-auth rejects a policy with no sigvalidity.default, so the tool must
	// always have one to emit.
	if z.SigValidity.Default == "" || z.SigValidity.Dnskey == "" || z.SigValidity.DS == "" {
		t.Errorf("sigvalidity must default to something: %+v", z.SigValidity)
	}
}

// TestGeneratedPolicyCarriesSigValidity is the regression test for the defect
// the first live run found: policies without sigvalidity are rejected at parse
// time and every zone bound to them is unusable.
func TestGeneratedPolicyCarriesSigValidity(t *testing.T) {
	c, err := LoadConfig(writeConf(t, "         - { ksk: MLDSA87, zsk: ED25519 }\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tree := &Tree{Conf: c, Serial: NewSerial(time.Now())}
	out := tree.authConfig()

	for _, want := range []string{
		"sigvalidity:", "default:  14d",
		"large_algorithms:  [ MLDSA87 ]", // derived, not configured
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
	c, err := LoadConfig(writeConf(t, "         - { ksk: MLDSA87, zsk: ED25519 }\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	combo := c.Zonegen.Children.Combos[0]
	tree := &Tree{Conf: c, Serial: 2026080600}
	out := tree.childZonefile(Child{
		Combo: combo,
		Label: combo.Label(c.Zonegen.Children.Label),
		Name:  "mldsa87-ed25519.pq.dnslab.",
	})
	// The apex TXT is the single most useful record in a tree of near-identical
	// zones: one query says what the zone is.
	if !strings.Contains(out, `"PQ-DNSSEC testbed: KSK=MLDSA87 (201) ZSK=ED25519 (15)"`) {
		t.Errorf("missing the self-describing TXT:\n%s", out)
	}
	if !strings.Contains(out, "2026080600") {
		t.Errorf("missing the serial:\n%s", out)
	}
}

func TestNewSerialIsDateBased(t *testing.T) {
	got := NewSerial(time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC))
	if got != 2026080600 {
		t.Errorf("NewSerial = %d, want 2026080600", got)
	}
}
