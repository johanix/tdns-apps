package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"

	tdns "github.com/johanix/tdns/v2"
)

// FetchDelegations performs an AXFR from source for the given zone and
// returns the sorted list of delegation owner names (those with NS RRsets,
// excluding the apex), along with the zone's SOA serial.
func FetchDelegations(zoneName, source string) (uint32, []string, error) {
	zoneName = dns.Fqdn(zoneName)

	zd := &tdns.ZoneData{
		ZoneName:  zoneName,
		ZoneStore: tdns.MapZone,
		Logger:    log.Default(),
	}

	serial, err := zd.ZoneTransferIn(source, 0, "axfr")
	if err != nil {
		return 0, nil, fmt.Errorf("AXFR of %s from %s: %w", zoneName, source, err)
	}
	zd.Ready = true

	names, err := zd.GetOwnerNames()
	if err != nil {
		return serial, nil, fmt.Errorf("listing owners: %w", err)
	}

	delegations := make([]string, 0, len(names)/2)
	for _, owner := range names {
		if strings.EqualFold(owner, zoneName) {
			continue
		}
		od, err := zd.GetOwner(owner)
		if err != nil {
			return serial, nil, fmt.Errorf("reading owner %s: %w", owner, err)
		}
		if od == nil {
			continue
		}
		ns := od.RRtypes.GetOnlyRRSet(dns.TypeNS)
		if len(ns.RRs) == 0 {
			continue
		}
		delegations = append(delegations, dns.Fqdn(owner))
	}
	return serial, delegations, nil
}
