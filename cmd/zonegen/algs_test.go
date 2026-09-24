package main

import (
	"sort"
	"strings"
	"testing"

	algregistry "github.com/johanix/dnssec-algorithms/registry"
)

// TestIsLargeMatchesTheCuratedList pins the derived large-algorithm rule
// against the hand-maintained list from the testbed this tool replaces, which is what
// this tool replaces. If a registry change ever moves an algorithm across the
// line, this test says so rather than the zone quietly getting the wrong
// large_algorithms treatment in production.
func TestIsLargeMatchesTheCuratedList(t *testing.T) {
	// Verbatim from the python generator's LARGE list, plus the two algorithms
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

// withoutRegistryRow removes name's row from registry.Algorithms for the rest
// of the test, as a dnssec-algorithms version that no longer carries it would.
// If the pinned version has no such row, there is nothing to remove.
func withoutRegistryRow(t *testing.T, name string) {
	t.Helper()
	saved := algregistry.Algorithms
	t.Cleanup(func() { algregistry.Algorithms = saved })
	rows := make([]algregistry.Alg, 0, len(saved))
	for _, a := range saved {
		if a.Name != name {
			rows = append(rows, a)
		}
	}
	algregistry.Algorithms = rows
}

// ML-DSA-44 is built into every tdns binary (tdns #760), and dnssec-algorithms
// drops its registry row. It must still resolve, at its IANA codepoint, in
// both roles, with its sizes; so must ED448, which never had a row.
func TestBuiltinsResolveWithoutARegistryRow(t *testing.T) {
	withoutRegistryRow(t, "MLDSA44")

	a, ok := lookupAlg("MLDSA44")
	if !ok || a.Codepoint != 18 || !a.ForKSK || !a.ForZSK {
		t.Fatalf("MLDSA44: got %+v, %v; want codepoint 18 usable in both roles", a, ok)
	}
	if a.PubKey != 1312 || a.Sig != 2420 || !a.IsLarge() {
		t.Errorf("MLDSA44 sizes: pubkey %d sig %d; want 1312 and 2420, large", a.PubKey, a.Sig)
	}
	if e, ok := lookupAlg("ed448"); !ok || e.Codepoint != 16 || !e.ForKSK || !e.ForZSK || e.IsLarge() {
		t.Errorf("ED448: got %+v, %v; want codepoint 16 in both roles, not large", e, ok)
	}
}

func TestSplitAlgorithmsOnlyCoversDifferingPairs(t *testing.T) {
	// Derived from the resolved POLICIES rather than from combos. That is the
	// point of the change: a policy written out by hand contributes to these
	// lists exactly like a generated one, so a large algorithm cannot become
	// invisible to large_algorithms just because no matrix produced it.
	policies := []PolicySpec{
		{Name: "a", KSKAlg: "MLDSA87", ZSKAlg: "ED25519"},
		{Name: "b", KSKAlg: "MLDSA87", ZSKAlg: "FALCON512"},
		{Name: "c", KSKAlg: "ED25519", ZSKAlg: "ED25519"}, // same alg: needs no entry
	}
	split := splitAlgorithmsOf(policies)
	if _, ok := split["ED25519"]; ok {
		t.Error("a same-algorithm pair must not appear in split_algorithms")
	}
	got := split["MLDSA87"]
	sort.Strings(got)
	if strings.Join(got, ",") != "ED25519,FALCON512" {
		t.Errorf("MLDSA87 should be allowed to pair with both ZSKs, got %v", got)
	}

	large := largeAlgorithmsOf(policies)
	sort.Strings(large)
	if strings.Join(large, ",") != "FALCON512,MLDSA87" {
		t.Errorf("large_algorithms = %v, want the two PQ algorithms", large)
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
	if addressRRType("192.0.2.2") != "A" || addressRRType("2001:db8::1") != "AAAA" {
		t.Error("address type detection is wrong")
	}
}
