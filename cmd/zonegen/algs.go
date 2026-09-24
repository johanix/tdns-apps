/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Algorithm knowledge, derived rather than hardcoded.
 *
 * Everything here comes out of github.com/johanix/dnssec-algorithms/registry,
 * which is pure metadata: codepoints, KSK/ZSK roles, key and signature sizes.
 * No algorithm implementation is linked, so this binary needs no cgo, no
 * liboqs, and no PQ build tags -- it can reason about MLDSA87 on a laptop that
 * cannot sign with it.
 *
 * That is deliberate. The python generator this replaces carried its own copy
 * of the alias table, the ZSK-capable list and the large-algorithm list, and
 * every one of them was a chance to drift from the registry that tdns-auth
 * actually uses.
 */

package main

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"

	algregistry "github.com/johanix/dnssec-algorithms/registry"
)

// algInfo is one algorithm as this tool needs it, whether it comes from the
// registry (the PQ algorithms an app selects, codepoints 200+) or from the
// algorithms every tdns binary has (builtinAlgs).
type algInfo struct {
	Name      string
	Codepoint uint8
	ForKSK    bool
	ForZSK    bool
	PubKey    int
	Sig       int
}

// builtinAlgs are the algorithms every tdns binary has, whatever its
// algs.list: the classical miekg built-ins, plus ED448 and ML-DSA-44, which
// tdns registers itself (ML-DSA-44 since tdns #760). They are NOT rows in
// registry.Algorithms, which holds what an app selects through its
// algs.list. (A dnssec-algorithms version from before ML-DSA-44 moved into
// tdns still has its row; a row is consulted first and agrees.) Their sizes
// do live in registry.AlgorithmFacts, so only the role has to be stated
// here, and every one of them is fine in both roles.
var builtinAlgs = []string{
	"ED25519", "ED448", "ECDSAP256SHA256", "ECDSAP384SHA384", "RSASHA256", "RSASHA512",
	"MLDSA44",
}

// builtinCodepoints holds the codepoints of the built-ins miekg has no name
// for. dns.StringToAlgorithm learns ML-DSA-44 only when something registers
// it, and this binary links no algorithm implementations.
var builtinCodepoints = map[string]uint8{
	"MLDSA44": 18, // IANA-assigned
}

// lookupAlg resolves an algorithm by canonical name, spanning both sources.
func lookupAlg(name string) (algInfo, bool) {
	name = strings.ToUpper(strings.TrimSpace(name))
	facts := algregistry.AlgorithmFacts[name]

	for _, a := range algregistry.Algorithms {
		if a.Name == name {
			return algInfo{
				Name: a.Name, Codepoint: a.Codepoint,
				ForKSK: a.Caps.ForKSK, ForZSK: a.Caps.ForZSK,
				PubKey: facts.PubKeyBytes, Sig: facts.SigBytes,
			}, true
		}
	}
	for _, b := range builtinAlgs {
		if b != name {
			continue
		}
		code, ok := dns.StringToAlgorithm[name]
		if !ok {
			code, ok = builtinCodepoints[name]
		}
		if !ok {
			return algInfo{}, false
		}
		return algInfo{
			Name: name, Codepoint: code,
			ForKSK: true, ForZSK: true,
			PubKey: facts.PubKeyBytes, Sig: facts.SigBytes,
		}, true
	}
	return algInfo{}, false
}

// dnskeyResponseFloor is the EDNS buffer size below which a DNSKEY response is
// expected to survive a UDP path intact (RFC 9715's advice, and the value
// tdns's own large-algorithm handling is tuned around).
const dnskeyResponseFloor = 1232

// IsLarge reports whether this algorithm belongs in dnssec.large_algorithms.
//
// The test is the algorithm's own contribution to a DNSKEY response -- its
// public key plus one signature -- against the 1232-byte floor. That is the
// question large_algorithms exists to answer, so deriving it beats a
// hand-maintained list that has to be revisited every time an algorithm is
// added. (It reproduces the hand-written list from the testbed this tool
// replaces, exactly: everything PQ except SQISIGN1, whose 65+148 bytes are
// smaller than ECDSA's.)
func (a algInfo) IsLarge() bool {
	return a.PubKey+a.Sig > dnskeyResponseFloor
}

// sortedKeys is shared with the policy-derived versions of these lists in
// zoneset.go, which replaced the Combo-based ones: deriving from the resolved
// policy set covers a hand-written policy as well as a generated one.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// describeCombo is the self-describing apex TXT every child carries. It is the
// single most useful thing in the testbed: one query says what a zone is.
func describeCombo(c Combo) string {
	ksk, _ := lookupAlg(c.KSK)
	zsk, _ := lookupAlg(c.ZSK)
	return fmt.Sprintf("PQ-DNSSEC testbed: KSK=%s (%d) ZSK=%s (%d)",
		ksk.Name, ksk.Codepoint, zsk.Name, zsk.Codepoint)
}

func isIPAddr(s string) bool { return net.ParseIP(s) != nil }

// addressRRType returns A or AAAA for an address string.
func addressRRType(addr string) string {
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "AAAA"
	}
	return "A"
}
