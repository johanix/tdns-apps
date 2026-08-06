package main

import (
	"sort"
	"strings"
	"testing"
)

// TestIsLargeMatchesTheCuratedList pins the derived large-algorithm rule
// against the hand-maintained list from the pq.axfr.net testbed, which is what
// this tool replaces. If a registry change ever moves an algorithm across the
// line, this test says so rather than the zone quietly getting the wrong
// large_algorithms treatment in production.
func TestIsLargeMatchesTheCuratedList(t *testing.T) {
	// Verbatim from pq-testbed/generate.py's LARGE, plus the two algorithms
	// that testbed did not link (FALCON1024, QRUOV_Q31_L3), both of which are
	// unambiguously large.
	curatedLarge := map[string]bool{
		"MLDSA44": true, "MLDSA65": true, "MLDSA87": true, "SLHDSA128S": true,
		"FALCON512": true, "FALCON1024": true, "MAYO1": true, "MAYO2": true,
		"MAYO3": true, "MAYO5": true, "SNOVA24_5_4": true, "SNOVA37_17_2": true,
		"SNOVA25_8_3": true, "QRUOV_Q31_L3": true, "CROSSRSDPG128SMALL": true,
	}
	// Deliberately NOT large: SQISIGN1's 65+148 bytes are smaller than ECDSA's.
	curatedSmall := []string{"SQISIGN1", "ED25519", "ECDSAP256SHA256", "RSASHA256"}

	for name := range curatedLarge {
		a, ok := lookupAlg(name)
		if !ok {
			t.Errorf("%s is not in the registry", name)
			continue
		}
		if !a.IsLarge() {
			t.Errorf("%s should be large (pubkey %d + sig %d = %d)",
				name, a.PubKey, a.Sig, a.PubKey+a.Sig)
		}
	}
	for _, name := range curatedSmall {
		a, ok := lookupAlg(name)
		if !ok {
			t.Errorf("%s is not known", name)
			continue
		}
		if a.IsLarge() {
			t.Errorf("%s should NOT be large (pubkey %d + sig %d = %d)",
				name, a.PubKey, a.Sig, a.PubKey+a.Sig)
		}
	}
}

func TestLookupAlgSpansBothSources(t *testing.T) {
	// A registered PQ algorithm...
	if a, ok := lookupAlg("MLDSA87"); !ok || a.Codepoint != 201 || a.ForZSK {
		t.Errorf("MLDSA87: got %+v, want codepoint 201 and ForZSK=false", a)
	}
	// ...and a miekg built-in, which is NOT a row in registry.Algorithms.
	if a, ok := lookupAlg("ED25519"); !ok || a.Codepoint != 15 || !a.ForKSK || !a.ForZSK {
		t.Errorf("ED25519: got %+v, want codepoint 15 usable in both roles", a)
	}
	if _, ok := lookupAlg("mldsa87"); !ok {
		t.Error("lookup must be case-insensitive")
	}
	if _, ok := lookupAlg("NOSUCHALG"); ok {
		t.Error("an unknown algorithm must not resolve")
	}
}

func TestSplitAlgorithmsOnlyCoversDifferingPairs(t *testing.T) {
	combos := []Combo{
		{KSK: "MLDSA87", ZSK: "ED25519"},
		{KSK: "MLDSA87", ZSK: "FALCON512"},
		{KSK: "ED25519", ZSK: "ED25519"}, // same alg: needs no entry
	}
	split := splitAlgorithms(combos, Combo{KSK: "ED25519", ZSK: "ED25519"})
	if _, ok := split["ED25519"]; ok {
		t.Error("a same-algorithm pair must not appear in split_algorithms")
	}
	got := split["MLDSA87"]
	sort.Strings(got)
	if strings.Join(got, ",") != "ED25519,FALCON512" {
		t.Errorf("MLDSA87 should be allowed to pair with both ZSKs, got %v", got)
	}
}

func TestComboLabelAndPolicyName(t *testing.T) {
	c := Combo{KSK: "MLDSA87", ZSK: "ED25519"}
	if got := c.Label("{ksk}-{zsk}"); got != "mldsa87-ed25519" {
		t.Errorf("Label = %q", got)
	}
	if got := c.PolicyName(); got != "mldsa87-ed25519" {
		t.Errorf("PolicyName = %q", got)
	}
}

func TestAddressRRType(t *testing.T) {
	if addressRRType("172.16.0.1") != "A" || addressRRType("2a01:bad::1") != "AAAA" {
		t.Error("address type detection is wrong")
	}
}
