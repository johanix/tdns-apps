/*
 * The generators must produce LEGAL zones. That is not a style preference: a
 * CNAME beside an A, or an NS placed as if it were an ordinary record, produces
 * a file a server will load and then behave strangely with. These tests assert
 * legality directly on the rendered output rather than trusting the generator
 * to have been careful.
 */

package main

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// baseConfig is the minimum a flag-driven generator needs: somewhere to write.
func baseConfig(t *testing.T) *Config {
	t.Helper()
	c := &Config{}
	c.Zonegen.Output.ZoneDir = t.TempDir()
	if err := c.applyDefaults(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	return c
}

// parseZone renders a zone and parses it back with an EMPTY origin, so any
// relative name is a failure, and returns the records grouped by owner.
func parseZone(t *testing.T, zs *ZoneSet, c *Config, idx int) map[string][]dns.RR {
	t.Helper()
	text := zs.Render(&zs.Zones[idx], &c.Zonegen.Defaults)
	byOwner := map[string][]dns.RR{}
	zp := dns.NewZoneParser(strings.NewReader(text), "", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		byOwner[rr.Header().Name] = append(byOwner[rr.Header().Name], rr)
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("generated zone does not parse: %v\n%s", err, truncate(text))
	}
	if len(byOwner) == 0 {
		t.Fatal("generated zone parsed to nothing")
	}
	return byOwner
}

func truncate(s string) string {
	if len(s) > 2000 {
		return s[:2000] + "\n... (truncated)"
	}
	return s
}

// assertLegal checks the two rules a random rrtype mix would otherwise break.
func assertLegal(t *testing.T, byOwner map[string][]dns.RR, apex string) {
	t.Helper()
	// A delegation is any non-apex name holding NS. Everything strictly below
	// one is occluded, which is legal; what is NOT legal is other data AT the
	// delegation point (bar DS, and glue, which lives below it).
	delegations := map[string]bool{}
	for owner, rrs := range byOwner {
		if owner == apex {
			continue
		}
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeNS {
				delegations[owner] = true
			}
		}
	}

	for owner, rrs := range byOwner {
		var hasCNAME, hasOther bool
		for _, rr := range rrs {
			switch rr.Header().Rrtype {
			case dns.TypeCNAME:
				hasCNAME = true
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			default:
				hasOther = true
			}
		}
		if hasCNAME && hasOther {
			t.Errorf("%s has a CNAME beside other data, which is illegal: %v", owner, rrs)
		}
		if delegations[owner] {
			for _, rr := range rrs {
				switch rr.Header().Rrtype {
				case dns.TypeNS, dns.TypeDS:
				default:
					t.Errorf("%s is a delegation point but also holds %s, which is illegal",
						owner, dns.TypeToString[rr.Header().Rrtype])
				}
			}
		}
	}
}

func TestBigzoneIsLegalAndCovers(t *testing.T) {
	c := baseConfig(t)
	bz := &bigzoneOpts{
		count: 300, types: "A,AAAA,MX,TXT,SRV,CNAME,CAA",
		maxLabels: 3, ents: true, delegations: 4,
		addrPool: "192.0.2.0/24", unsigned: true,
	}
	zs, err := buildBigzone(c, "big.example.", bz, &runOptions{})
	if err != nil {
		t.Fatalf("buildBigzone: %v", err)
	}
	byOwner := parseZone(t, zs, c, 0)
	assertLegal(t, byOwner, "big.example.")

	// Every requested type must actually occur -- that was the stated
	// requirement, and leaving it to a dice roll would satisfy it only usually.
	seen := map[uint16]bool{}
	for _, rrs := range byOwner {
		for _, rr := range rrs {
			seen[rr.Header().Rrtype] = true
		}
	}
	for _, want := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX,
		dns.TypeTXT, dns.TypeSRV, dns.TypeCNAME, dns.TypeCAA} {
		if !seen[want] {
			t.Errorf("--types asked for %s but the zone has none", dns.TypeToString[want])
		}
	}
	if !seen[dns.TypeNS] {
		t.Error("--delegations 4 produced no NS records")
	}
}

// TestBigzoneEntsAreActuallyEmpty: an empty non-terminal is a name that exists
// only because something below it does. They are a classic source of NSEC and
// NSEC3 bugs, so --ents has to really produce them rather than merely allow
// them.
func TestBigzoneEntsAreActuallyEmpty(t *testing.T) {
	c := baseConfig(t)
	bz := &bigzoneOpts{count: 200, types: "A,TXT", maxLabels: 3, ents: true,
		addrPool: "192.0.2.0/24", unsigned: true}
	zs, err := buildBigzone(c, "ent.example.", bz, &runOptions{})
	if err != nil {
		t.Fatalf("buildBigzone: %v", err)
	}
	byOwner := parseZone(t, zs, c, 0)

	var ents int
	for owner := range byOwner {
		for _, anc := range ancestorsOf(owner, "ent.example.") {
			if _, populated := byOwner[anc]; !populated {
				ents++
			}
		}
	}
	if ents == 0 {
		t.Error("--ents produced no empty non-terminals")
	}

	// And with --ents off, every intermediate name must carry something.
	bz.ents = false
	zs2, err := buildBigzone(c, "ent.example.", bz, &runOptions{})
	if err != nil {
		t.Fatalf("buildBigzone: %v", err)
	}
	byOwner2 := parseZone(t, zs2, c, 0)
	for owner := range byOwner2 {
		for _, anc := range ancestorsOf(owner, "ent.example.") {
			if _, populated := byOwner2[anc]; !populated {
				t.Errorf("--ents=false left %s empty, below %s", anc, owner)
			}
		}
	}
}

// TestGenerationIsDeterministic is what makes a regenerated zone a small diff
// rather than a whole-file one, and what makes --update a replayable chain.
func TestGenerationIsDeterministic(t *testing.T) {
	build := func() string {
		c := baseConfig(t)
		bz := &bigzoneOpts{count: 120, types: "A,TXT,MX", maxLabels: 2, ents: true,
			delegations: 2, addrPool: "192.0.2.0/24", unsigned: true}
		zs, err := buildBigzone(c, "det.example.", bz, &runOptions{})
		if err != nil {
			t.Fatalf("buildBigzone: %v", err)
		}
		zs.Serial = 1
		return zs.Render(&zs.Zones[0], &c.Zonegen.Defaults)
	}
	if a, b := build(), build(); a != b {
		t.Error("two runs with identical inputs produced different zones")
	}
}

func TestRpzIsLegalAndCoversActions(t *testing.T) {
	c := baseConfig(t)
	rz := &rpzOpts{count: 200, actions: "nxdomain,nodata,drop,passthru,redirect",
		triggers: "qname,nsdname,ip", redirect: "walled-garden.example."}
	zs, err := buildRpz(c, "rpz.example.", rz, &runOptions{})
	if err != nil {
		t.Fatalf("buildRpz: %v", err)
	}
	byOwner := parseZone(t, zs, c, 0)
	assertLegal(t, byOwner, "rpz.example.")

	targets := map[string]bool{}
	for _, rrs := range byOwner {
		for _, rr := range rrs {
			if cn, ok := rr.(*dns.CNAME); ok {
				targets[cn.Target] = true
			}
		}
	}
	for _, want := range []string{".", "*.", "rpz-drop.", "rpz-passthru.", "walled-garden.example."} {
		if !targets[want] {
			t.Errorf("no rule with the %q action; got targets %v", want, keysOf(targets))
		}
	}
	// An RPZ zone is unsigned by default, which is what lets this generator run
	// with no API connection at all.
	if zs.NeedsKeys() {
		t.Error("rpz should be unsigned by default")
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestTreeDelegatesEveryLevel(t *testing.T) {
	c := baseConfig(t)
	zs, err := buildTree(c, "tree.example.", 2, 3, "ED25519", "ED25519", false)
	if err != nil {
		t.Fatalf("buildTree: %v", err)
	}
	// 1 apex + 3 + 9
	if len(zs.Zones) != 13 {
		t.Errorf("depth 2 breadth 3 should be 13 zones, got %d", len(zs.Zones))
	}
	// Every zone except the leaves delegates, and every zone except the apex is
	// somebody's child exactly once.
	childCount := map[string]int{}
	for i := range zs.Zones {
		for _, ch := range zs.Zones[i].Children {
			childCount[ch]++
		}
	}
	for i := range zs.Zones {
		name := zs.Zones[i].Name
		if name == zs.Apex {
			continue
		}
		if childCount[name] != 1 {
			t.Errorf("%s is delegated %d times, want exactly 1", name, childCount[name])
		}
	}
	if !zs.NeedsKeys() {
		t.Error("a signed tree should need keys")
	}
}

// TestInBailiwickNameserverHasAnAddress pins a defect that every parser-based
// test here missed and BIND's named-checkzone caught in one go: a zone whose
// apex NS names a host inside the zone, with no address for that host, PARSES
// perfectly and then fails to LOAD ("has no address records"). The two are
// different claims and only one of them was being checked.
func TestInBailiwickNameserverHasAnAddress(t *testing.T) {
	c := baseConfig(t)
	for _, tc := range []struct {
		name  string
		build func() (*ZoneSet, error)
	}{
		{"rpz", func() (*ZoneSet, error) {
			return buildRpz(c, "rpz.example.", &rpzOpts{count: 20, actions: "nxdomain",
				triggers: "qname", redirect: "walled-garden.example."}, &runOptions{})
		}},
		{"bigzone", func() (*ZoneSet, error) {
			return buildBigzone(c, "big.example.", &bigzoneOpts{count: 20, types: "A,TXT",
				maxLabels: 1, addrPool: "192.0.2.0/24", unsigned: true}, &runOptions{})
		}},
		{"tree", func() (*ZoneSet, error) {
			return buildTree(c, "tree.example.", 1, 2, "ED25519", "ED25519", true)
		}},
		{"pqtree", func() (*ZoneSet, error) {
			// The shipped sample uses out-of-bailiwick nameservers, so point
			// them inside the tree -- which is exactly the configuration that
			// would otherwise produce a zone BIND will not load.
			pq := loadPq(t, "            - { ksk: ED25519, zsk: ED25519 }\n")
			pq.Zonegen.Pqtree.Parent.Nameservers = []string{"ns1.pq.example."}
			return buildPqtree(pq)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zs, err := tc.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			for _, ns := range zs.Nameservers {
				// Only in-bailiwick names need glue from us; an out-of-bailiwick
				// nameserver is somebody else's zone's business.
				var enclosing *ZoneSpec
				for i := range zs.Zones {
					zn := zs.Zones[i].Name
					if ns == zn || strings.HasSuffix(ns, "."+zn) {
						if enclosing == nil || len(zn) > len(enclosing.Name) {
							enclosing = &zs.Zones[i]
						}
					}
				}
				if enclosing == nil {
					continue
				}
				if !enclosing.hasAddressFor(ns) {
					t.Errorf("%s is in-bailiwick for %s but has no address there; "+
						"BIND will refuse to load the zone", ns, enclosing.Name)
				}
			}
		})
	}
}
