/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The only part of this tool that talks to a server.
 *
 * Two things are needed from tdns-auth: create a KSK and a ZSK for each zone,
 * and read back the public halves so the DS records can go straight into the
 * parent zone file. Creating the keys ourselves -- rather than letting the
 * zones mint their own on first load -- is what collapses the old two-pass
 * "generate, start, scrape DS, rewrite parent, reload" dance into one command.
 * A zone whose keys are already in the keystore adopts them at load time
 * (EnsureActiveDnssecKeys) instead of generating new ones.
 *
 * Computing a DS needs no crypto: it is a digest over the owner name and the
 * DNSKEY rdata, so a PQ codepoint this binary cannot sign with is no obstacle.
 */

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"

	tdns "github.com/johanix/tdns/v2"
	cli "github.com/johanix/tdns/v2/cli"
)

// KeyManager wraps the management API for the two operations this tool needs.
type KeyManager struct {
	api     *tdns.ApiClient
	baseUrl string
}

// NewKeyManager builds a client for an already-resolved server. Resolution --
// which config the details came from, and which entry in it -- happens in
// apiresolve.go, because it is a question about the host rather than about
// keys.
//
// It does NOT go through cli.GetApiClient: that resolves a role name against
// the global client table tdns-cli builds from its own multi-role config,
// which is machinery a single-server tool has no use for. The typed keystore
// call below IS reused -- it is the one piece worth sharing.
func NewKeyManager(s ApiServerConf) (*KeyManager, error) {
	authMethod := s.AuthMethod
	if authMethod == "" {
		authMethod = "X-API-Key"
	}
	api := tdns.NewClient(s.Name, s.BaseUrl, s.ApiKey, authMethod, s.RootCAFile)
	if api == nil {
		return nil, fmt.Errorf("could not create an API client for %s", s.BaseUrl)
	}
	return &KeyManager{api: api, baseUrl: s.BaseUrl}, nil
}

// BaseUrl is for reporting which keystore is about to be written to. Printing
// it is not decoration: this tool creates key material, and the one mistake
// worth making impossible is doing that against the wrong server.
func (km *KeyManager) BaseUrl() string { return km.baseUrl }

// EnsureKeys makes sure zone has an active KSK and ZSK of the given
// algorithms, creating whatever is missing. It is idempotent: re-running
// generate against a tree that already has its keys creates nothing and,
// importantly, does not produce a second pair that would leave the zone
// publishing two KSKs and the parent's DS matching only one.
//
// Returns the number of keys actually created.
func (km *KeyManager) EnsureKeys(zone, kskAlg, zskAlg string) (int, error) {
	zone = dns.Fqdn(zone)
	existing, err := km.zoneKeys(zone)
	if err != nil {
		return 0, err
	}

	var created int
	for _, want := range []struct {
		keytype string
		alg     string
		flags   uint16
	}{
		{"KSK", kskAlg, 257},
		{"ZSK", zskAlg, 256},
	} {
		if have, ok := existing[want.flags]; ok {
			// A key of the right role but the WRONG algorithm is not something
			// to paper over by adding another: tdns-auth would refuse the zone
			// at load (reconcileActiveKeyAlgorithms), and silently generating a
			// second key would just make that failure harder to read.
			if !strings.EqualFold(have, want.alg) {
				return created, fmt.Errorf(
					"%s already has an active %s using %s, but the config asks for %s; "+
						"remove the old key (keystore dnssec delete) or change the combo",
					zone, want.keytype, have, want.alg)
			}
			continue
		}
		if err := km.generateKey(zone, want.keytype, want.alg); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

// zoneKeys returns the active keys for a zone, keyed by DNSKEY flags, with the
// algorithm name as the value.
func (km *KeyManager) zoneKeys(zone string) (map[uint16]string, error) {
	resp, err := cli.SendKeystoreCmd(km.api, tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: "list",
	})
	if err != nil {
		return nil, fmt.Errorf("listing keys: %v", err)
	}
	if resp.Error {
		return nil, fmt.Errorf("listing keys: %s", resp.ErrorMsg)
	}

	out := map[uint16]string{}
	for mapkey, k := range resp.Dnskeys {
		// The list response keys its map "<zone>::<keyid>"; the DnssecKey's own
		// Name is not populated on this path.
		name := mapkey
		if i := strings.Index(mapkey, "::"); i >= 0 {
			name = mapkey[:i]
		}
		if !strings.EqualFold(dns.Fqdn(name), zone) || k.State != "active" {
			continue
		}
		out[k.Flags] = k.Algorithm
	}
	return out, nil
}

func (km *KeyManager) generateKey(zone, keytype, alg string) error {
	code, ok := lookupAlg(alg)
	if !ok {
		return fmt.Errorf("unknown algorithm %q", alg)
	}
	resp, err := cli.SendKeystoreCmd(km.api, tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: "generate",
		Zone:       zone,
		KeyType:    keytype,
		Algorithm:  code.Codepoint,
		State:      "active",
	})
	if err != nil {
		return fmt.Errorf("generating %s %s for %s: %v", alg, keytype, zone, err)
	}
	if resp.Error {
		// The likeliest cause by far, and the one worth naming: the server does
		// not link this algorithm, so it cannot make the key however valid the
		// config is.
		return fmt.Errorf("generating %s %s for %s: %s "+
			"(does this tdns-auth link %s? check 'keystore dnssec algorithms')",
			alg, keytype, zone, resp.ErrorMsg, alg)
	}
	return nil
}

// CollectDS returns the DS records for a zone's KSKs, computed locally from
// the published DNSKEYs. SHA-256 only: it is what every validator implements,
// and a second digest doubles the parent's DS RRset for no benefit.
//
// Deliberately uses the redacted `list` rather than the bulk export -- this
// needs public keys, so no private material has any business crossing the wire.
func (km *KeyManager) CollectDS(zone string) ([]string, error) {
	zone = dns.Fqdn(zone)
	resp, err := cli.SendKeystoreCmd(km.api, tdns.KeystorePost{
		Command:    "dnssec-mgmt",
		SubCommand: "list",
	})
	if err != nil {
		return nil, fmt.Errorf("listing keys for %s: %v", zone, err)
	}
	if resp.Error {
		return nil, fmt.Errorf("listing keys for %s: %s", zone, resp.ErrorMsg)
	}

	var out []string
	for mapkey, k := range resp.Dnskeys {
		name := mapkey
		if i := strings.Index(mapkey, "::"); i >= 0 {
			name = mapkey[:i]
		}
		if !strings.EqualFold(dns.Fqdn(name), zone) || k.Flags != 257 || k.State != "active" {
			continue
		}
		rr, err := dns.NewRR(k.Keystr)
		if err != nil {
			return nil, fmt.Errorf("%s: unparsable DNSKEY from the keystore: %v", zone, err)
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("%s: keystore returned a %s where a DNSKEY was expected",
				zone, dns.TypeToString[rr.Header().Rrtype])
		}
		ds := dnskey.ToDS(dns.SHA256)
		if ds == nil {
			return nil, fmt.Errorf("%s: could not compute DS for keyid %d", zone, dnskey.KeyTag())
		}
		out = append(out, strings.TrimSpace(strings.SplitN(ds.String(), "DS\t", 2)[1]))
	}
	sort.Strings(out) // stable output, so a regenerate produces a clean diff
	return out, nil
}
