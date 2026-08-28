/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The bigzone generator: one zone, many names, a mix of rrtypes.
 *
 * The zone must be LEGAL. A random type mix will otherwise eventually put a
 * CNAME beside an A on one name, which is illegal, or an NS below the apex,
 * which is not illegal at all but means something quite different -- it is a
 * delegation, and everything under it becomes occluded. Both are handled
 * deliberately here rather than left to chance:
 *
 *   - a name chosen for CNAME gets ONLY a CNAME, and is never a parent
 *   - NS is never part of the random mix; delegations come from --delegations,
 *     which places NS (plus glue) and nothing else at that name
 *
 * Occluded data below a delegation is generated on purpose, one name per
 * delegation, because it is legal, it is what a real zone looks like, and it is
 * exactly the case a signer must NOT sign.
 *
 * Everything is derived from a seeded generator, so the same flags always
 * produce the same zone. Without that, every regeneration is a whole-file diff
 * and the serial bump says nothing about what actually changed.
 */

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// bigzoneMixTypes are the rrtypes that may appear in the random mix. NS is
// deliberately absent: it is a delegation, not a record type you sprinkle.
var bigzoneMixTypes = map[string]bool{
	"A": true, "AAAA": true, "MX": true, "TXT": true, "SRV": true,
	"CNAME": true, "CAA": true,
}

type bigzoneOpts struct {
	count       int
	types       string
	maxLabels   int
	ents        bool
	delegations int
	addrPool    string
	kskAlg      string
	zskAlg      string
	unsigned    bool
}

func bigzoneCmd() *cobra.Command {
	var (
		opts runOptions
		bz   bigzoneOpts
	)
	c := &cobra.Command{
		Use:   "bigzone",
		Short: "One zone with many names and a mix of rrtypes",
		Long: `Generates a single zone with --count names, spread over the requested
rrtypes. Every type named in --types is guaranteed to occur at least once;
beyond that the mix is random but reproducible -- the same flags always produce
the same zone.

Names are pronounceable rather than hashes, and may be up to --max-labels deep.
With --ents, intermediate names are left empty, which is what creates the empty
non-terminals that NSEC and NSEC3 chains so often get wrong.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := loadForRun(&opts)
			if err != nil {
				return err
			}
			if opts.Zone == "" {
				return fmt.Errorf("--zone is required")
			}
			if err := conf.RequireOutput(opts.OutFile == ""); err != nil {
				return err
			}
			zone := dns.Fqdn(opts.Zone)
			zs, err := buildBigzone(conf, zone, &bz, &opts)
			if err != nil {
				return err
			}
			return runGenerate(conf, zs, &opts)
		},
	}
	opts.addCommonFlags(c)
	opts.addUpdateFlags(c)
	c.Flags().IntVar(&bz.count, "count", 1000, "how many names to generate")
	c.Flags().StringVar(&bz.types, "types", "A,AAAA,MX,TXT",
		"rrtypes to include; every one named is guaranteed to occur")
	c.Flags().IntVar(&bz.maxLabels, "max-labels", 1, "maximum labels below the apex on one name")
	c.Flags().BoolVar(&bz.ents, "ents", true,
		"leave intermediate names empty, creating empty non-terminals (needs --max-labels > 1)")
	c.Flags().IntVar(&bz.delegations, "delegations", 0,
		"how many names to make delegations, each with one occluded name below it")
	c.Flags().StringVar(&bz.addrPool, "addr-pool", "192.0.2.0/24",
		"IPv4 prefix that A records are drawn from, cycling if it is too small")
	c.Flags().StringVar(&bz.kskAlg, "ksk", "ED25519", "KSK algorithm")
	c.Flags().StringVar(&bz.zskAlg, "zsk", "ED25519", "ZSK algorithm")
	c.Flags().BoolVar(&bz.unsigned, "unsigned", false, "generate an unsigned zone (no keystore contact)")
	return c
}

func buildBigzone(c *Config, zone string, bz *bigzoneOpts, o *runOptions) (*ZoneSet, error) {
	d := &c.Zonegen.Defaults
	if bz.count < 1 {
		return nil, fmt.Errorf("--count must be at least 1")
	}
	if bz.maxLabels < 1 {
		return nil, fmt.Errorf("--max-labels must be at least 1")
	}
	types, err := parseTypeList(bz.types)
	if err != nil {
		return nil, err
	}
	if len(types) > bz.count {
		return nil, fmt.Errorf("--types names %d rrtypes but --count is only %d, so they "+
			"cannot all occur; raise --count or shorten --types", len(types), bz.count)
	}
	pool, err := newAddrPool(bz.addrPool)
	if err != nil {
		return nil, err
	}

	policy, policies, err := simplePolicy(bz.unsigned, bz.kskAlg, bz.zskAlg)
	if err != nil {
		return nil, err
	}
	ns, rname := treeServerNames(c, zone)
	zs := &ZoneSet{Nameservers: ns, Rname: rname, Policies: policies}

	spec := ZoneSpec{Name: zone, Policy: policy}

	if o.Update > 0 {
		// CNAME is excluded from churn: a name that gains a CNAME beside its
		// existing records would make the zone illegal, and this path does not
		// know what a name already holds.
		mix := make([]string, 0, len(types))
		for _, t := range types {
			if t != "CNAME" {
				mix = append(mix, t)
			}
		}
		if len(mix) == 0 {
			return nil, fmt.Errorf("--update needs at least one non-CNAME type in --types")
		}
		g := &bigzoneGen{zone: zone, types: mix, d: d, pool: pool}
		body, oldSerial, err := applyUpdate(zonePath(c, o, zone), zone, o.Update, o.Force, g)
		if err != nil {
			return nil, err
		}
		spec.Records = body
		spec.Comments = []string{fmt.Sprintf("churned %.1f%% from serial %d", o.Update, oldSerial)}
		zs.Serial = NewSerial(nowFunc(), oldSerial)
		zs.Zones = append(zs.Zones, spec)
		zs.AddGlue(&c.Zonegen.Defaults)
		return zs, nil
	}

	rng := newRand(zone, bz.types, fmt.Sprint(bz.count, bz.maxLabels, bz.ents, bz.delegations))
	names, parents := bigzoneNames(zone, bz, rng)
	spec.Records = bigzoneRecords(zone, names, parents, types, bz, d, pool, rng)
	zs.Zones = append(zs.Zones, spec)
	zs.AddGlue(&c.Zonegen.Defaults)
	return zs, nil
}

// bigzoneNames builds the name set and reports which of them are parents of
// another name. A parent must not be given a CNAME, and (when --ents is off)
// must be populated so that it is not an empty non-terminal.
func bigzoneNames(zone string, bz *bigzoneOpts, rng *rand.Rand) (names []string, parents map[string]bool) {
	seen := map[string]bool{}
	parents = map[string]bool{}
	for i := 0; i < bz.count; i++ {
		depth := 1
		if bz.maxLabels > 1 {
			depth = 1 + rng.Intn(bz.maxLabels)
		}
		n := LabelPath(uint64(i), depth, zone)
		if seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	// Ancestors: always recorded as parents, but only materialised as names of
	// their own when ENTs are switched off.
	for _, n := range names {
		for _, a := range ancestorsOf(n, zone) {
			parents[a] = true
			if !bz.ents && !seen[a] {
				seen[a] = true
				names = append(names, a)
			}
		}
	}
	sort.Strings(names)
	return names, parents
}

// ancestorsOf lists the strict ancestors of name below apex, nearest first.
//
// The apex itself has none, and neither does a name that is not under it. Both
// guards matter: without them TrimSuffix leaves the name intact, the split then
// runs off its end, and the caller is handed nonsense like "example..apex." as
// though it were a real name.
func ancestorsOf(name, apex string) []string {
	if name == apex {
		return nil
	}
	rest := strings.TrimSuffix(name, "."+apex)
	if rest == name {
		return nil // not under the apex at all
	}
	labels := strings.Split(rest, ".")
	var out []string
	for i := 1; i < len(labels); i++ {
		out = append(out, strings.Join(labels[i:], ".")+"."+apex)
	}
	return out
}

func bigzoneRecords(zone string, names []string, parents map[string]bool,
	types []string, bz *bigzoneOpts, d *DefaultsConf, pool *addrPool, rng *rand.Rand) []string {

	var recs []string
	add := func(owner, rtype, rdata string) {
		recs = append(recs, fmt.Sprintf("%s\t%d\tIN\t%s\t%s", owner, d.TTL, rtype, rdata))
	}

	// Delegations first: they claim names, and nothing else may be placed at
	// them. Each gets one name below it, which is occluded -- legal, invisible
	// to a resolver, and something a signer must leave alone.
	delegated := map[string]bool{}
	for i := 0; i < bz.delegations && i < len(names); i++ {
		n := names[i]
		if parents[n] {
			continue // a name with children of its own is a worse delegation point
		}
		delegated[n] = true
		add(n, "NS", "ns1."+n)
		add("ns1."+n, "A", pool.next()) // in-bailiwick glue, so the delegation resolves
		add("occluded."+n, "TXT", `"occluded by the delegation above; must not be signed"`)
	}

	// CNAME names: exclusive, and never a parent.
	wantCNAME := contains(types, "CNAME")
	cnames := map[string]bool{}
	if wantCNAME {
		for _, n := range names {
			if delegated[n] || parents[n] {
				continue
			}
			if rng.Intn(8) == 0 || len(cnames) == 0 {
				cnames[n] = true
			}
		}
	}

	// A single well-known target for MX and SRV, so those records point at
	// something that exists rather than dangling.
	mailHost := "mail." + zone
	needMail := contains(types, "MX") || contains(types, "SRV")

	mixable := make([]string, 0, len(types))
	for _, t := range types {
		if t != "CNAME" {
			mixable = append(mixable, t)
		}
	}

	// Guarantee coverage: hand out one of each mixable type before anything is
	// random. Coverage the operator asked for must not depend on a dice roll.
	guaranteed := map[string]string{}
	gi := 0
	for _, t := range mixable {
		for gi < len(names) && (delegated[names[gi]] || cnames[names[gi]]) {
			gi++
		}
		if gi < len(names) {
			guaranteed[names[gi]] = t
			gi++
		}
	}

	for _, n := range names {
		switch {
		case delegated[n]:
			continue // already emitted, and nothing else may live here
		case cnames[n]:
			add(n, "CNAME", mailHost)
			continue
		}
		set := []string{}
		if t, ok := guaranteed[n]; ok {
			set = append(set, t)
		}
		if len(mixable) > 0 {
			// One or two more types per name, drawn at random.
			for k := 0; k <= rng.Intn(2); k++ {
				t := mixable[rng.Intn(len(mixable))]
				if !contains(set, t) {
					set = append(set, t)
				}
			}
		}
		if len(set) == 0 {
			set = []string{"TXT"}
		}
		recs = append(recs, synthRecords(n, set, zone, d, pool, rng)...)
	}
	if needMail {
		add(mailHost, "A", pool.next())
	}
	return recs
}

// simplePolicy is the one-policy case every generator except pqtree wants.
func simplePolicy(unsigned bool, kskAlg, zskAlg string) (string, []PolicySpec, error) {
	if unsigned {
		return "", nil, nil
	}
	kskAlg, zskAlg = strings.ToUpper(kskAlg), strings.ToUpper(zskAlg)
	if err := validateCombo(Combo{KSK: kskAlg, ZSK: zskAlg}, "--ksk/--zsk"); err != nil {
		return "", nil, err
	}
	name := strings.ToLower(kskAlg + "-" + zskAlg)
	return name, []PolicySpec{{
		Name: name, KSKAlg: kskAlg, ZSKAlg: zskAlg,
		Mode: "ksk-zsk", KSKLife: "forever", ZSKLife: "forever",
	}}, nil
}

func parseTypeList(s string) ([]string, error) {
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.ToUpper(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if t == "NS" {
			return nil, fmt.Errorf("NS is not a mix type: an NS below the apex is a " +
				"delegation, which changes what the zone means. Use --delegations")
		}
		if !bigzoneMixTypes[t] {
			return nil, fmt.Errorf("unsupported rrtype %q for --types", t)
		}
		if !contains(out, t) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--types is empty")
	}
	return out, nil
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// addrPool hands out addresses from a prefix, cycling when it runs out. A /24
// and 100,000 names means repeats, which is entirely normal in a real zone.
type addrPool struct {
	base net.IP
	size uint32
	n    uint32
}

func newAddrPool(cidr string) (*addrPool, error) {
	_, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("--addr-pool %q: %v", cidr, err)
	}
	ip := netw.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("--addr-pool must be an IPv4 prefix, got %q", cidr)
	}
	ones, bits := netw.Mask.Size()
	// A /32 gives size 1, and next() then divides by size-1 == 0. A /0 gives
	// 1<<32, which is 0 in a uint32 and makes the pool nonsense rather than
	// huge. Require a prefix that actually holds host addresses to hand out.
	// A /32 gives size 1, and next() then divides by size-1 == 0. A /0 needs
	// 1<<32, which is 0 in a uint32 and makes the pool nonsense rather than
	// huge. Everything between is fine, however large.
	if hostBits := bits - ones; hostBits < 1 || hostBits > 31 {
		return nil, fmt.Errorf("--addr-pool %q: a /%d has no usable range to cycle "+
			"through; use a prefix between /1 and /31", cidr, ones)
	}
	return &addrPool{base: ip, size: 1 << uint(bits-ones)}, nil
}

func (p *addrPool) next() string {
	v := uint32(p.base[0])<<24 | uint32(p.base[1])<<16 | uint32(p.base[2])<<8 | uint32(p.base[3])
	// Skip the all-zero host part, which is the network address.
	off := p.n%(p.size-1) + 1
	p.n++
	v += off
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// synthRecords renders one name's records for the given types. Shared between
// the fresh path and the churn path so that a name added by --update is
// indistinguishable from one the original generation produced.
func synthRecords(owner string, set []string, zone string,
	d *DefaultsConf, pool *addrPool, rng *rand.Rand) []string {

	mailHost := "mail." + zone
	var out []string
	sort.Strings(set)
	for _, t := range set {
		var rdata string
		switch t {
		case "A":
			rdata = pool.next()
		case "AAAA":
			// Two groups of at most four hex digits each. A single %x over a
			// uint32 produces up to eight, which is not a legal IPv6 group and
			// yields an address no parser accepts.
			v := rng.Uint32()
			rdata = fmt.Sprintf("2001:db8::%x:%x", v>>16, v&0xffff)
		case "MX":
			rdata = "10 " + mailHost
		case "TXT":
			rdata = fmt.Sprintf("%q", "name "+strings.SplitN(owner, ".", 2)[0])
		case "SRV":
			rdata = "0 5 443 " + mailHost
		case "CAA":
			rdata = `0 issue "letsencrypt.org"`
		default:
			continue
		}
		out = append(out, fmt.Sprintf("%s\t%d\tIN\t%s\t%s", owner, d.TTL, t, rdata))
	}
	return out
}

// bigzoneGen is the Mutator half: what --update should invent and what it
// should change. A changed name keeps its name and gets different rdata, which
// is the shape of change that produces a small, realistic IXFR.
type bigzoneGen struct {
	zone    string
	types   []string
	d       *DefaultsConf
	pool    *addrPool
	counter uint64
}

func (g *bigzoneGen) pick(rng *rand.Rand) []string {
	set := []string{g.types[rng.Intn(len(g.types))]}
	if len(g.types) > 1 && rng.Intn(2) == 0 {
		if t := g.types[rng.Intn(len(g.types))]; !contains(set, t) {
			set = append(set, t)
		}
	}
	return set
}

func (g *bigzoneGen) NewEntry(rng *rand.Rand, taken map[string]bool) (string, []string) {
	for tries := 0; tries < 1000; tries++ {
		owner := Label(g.counter) + "." + g.zone
		g.counter++
		if taken[owner] {
			continue
		}
		return owner, synthRecords(owner, g.pick(rng), g.zone, g.d, g.pool, rng)
	}
	return "", nil
}

func (g *bigzoneGen) Remake(rng *rand.Rand, owner string, current []string) []string {
	// As in rpz: a redraw that lands on the same records is not a change. The
	// address pool advances on every call, so an A record differs by itself,
	// but a TXT or MX name can repeat.
	for tries := 0; tries < 20; tries++ {
		recs := synthRecords(owner, g.pick(rng), g.zone, g.d, g.pool, rng)
		if !sameRecords(recs, current) {
			return recs
		}
	}
	return synthRecords(owner, g.pick(rng), g.zone, g.d, g.pool, rng)
}

func sameRecords(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
