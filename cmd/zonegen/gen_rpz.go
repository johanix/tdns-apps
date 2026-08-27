/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The rpz generator: a response-policy zone with many rules.
 *
 * An RPZ rule is an ordinary record whose OWNER encodes what it matches and
 * whose rdata encodes what to do. Both halves are just naming conventions, so
 * generating them needs no policy engine -- only the conventions, which live
 * here.
 *
 * RPZ zones are normally unsigned and served to a resolver rather than to the
 * world, so this generator does not sign by default. That is not a shortcut:
 * an unsigned set never contacts the keystore, so `rpz` runs with no API
 * connection and no config file at all.
 */

package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// rpzActions maps an action name to the CNAME target that expresses it. The
// empty target for "redirect" is filled in from --redirect-target.
var rpzActions = map[string]string{
	"nxdomain": ".",
	"nodata":   "*.",
	"passthru": "rpz-passthru.",
	"drop":     "rpz-drop.",
	"tcp-only": "rpz-tcp-only.",
	"redirect": "",
}

// rpzTriggers are the policy-trigger namespaces. QNAME is the bare zone; the
// rest hang off a reserved label.
var rpzTriggers = map[string]string{
	"qname":     "",
	"ip":        "rpz-ip",
	"nsdname":   "rpz-nsdname",
	"nsip":      "rpz-nsip",
	"client-ip": "rpz-client-ip",
}

type rpzOpts struct {
	count    int
	actions  string
	triggers string
	redirect string
	ttl      uint32
	signed   bool
	kskAlg   string
	zskAlg   string
}

func rpzCmd() *cobra.Command {
	var (
		opts runOptions
		rz   rpzOpts
	)
	c := &cobra.Command{
		Use:   "rpz",
		Short: "A response-policy zone with many rules",
		Long: `Generates an RPZ zone with --count rules, spread over the requested actions
and trigger types. Every action and trigger named is guaranteed to occur at
least once; the rest of the mix is random but reproducible.

With --update N the zone is not regenerated but CHURNED: roughly N percent of
the existing rules are removed, changed or added, and the serial advances. The
churn is seeded from the serial it replaces, so the same file always produces
the same next file -- which is what makes a chain of updates a replayable
sequence of deltas rather than noise.`,
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
			zs, err := buildRpz(conf, dns.Fqdn(opts.Zone), &rz, &opts)
			if err != nil {
				return err
			}
			return runGenerate(conf, zs, &opts)
		},
	}
	opts.addCommonFlags(c)
	opts.addUpdateFlags(c)
	c.Flags().IntVar(&rz.count, "count", 1000, "how many rules to generate")
	c.Flags().StringVar(&rz.actions, "actions", "nxdomain,nodata,passthru,redirect",
		"actions to include: nxdomain, nodata, drop, passthru, tcp-only, redirect")
	c.Flags().StringVar(&rz.triggers, "triggers", "qname",
		"trigger types to include: qname, ip, nsdname, nsip, client-ip")
	c.Flags().StringVar(&rz.redirect, "redirect-target", "walled-garden.example.",
		"where redirect rules point")
	c.Flags().BoolVar(&rz.signed, "signed", false, "sign the zone (RPZ zones are normally unsigned)")
	c.Flags().StringVar(&rz.kskAlg, "ksk", "ED25519", "KSK algorithm, with --signed")
	c.Flags().StringVar(&rz.zskAlg, "zsk", "ED25519", "ZSK algorithm, with --signed")
	return c
}

// rpzGen holds everything needed both to generate a fresh zone and to churn an
// existing one, which is why it is a type rather than a pile of arguments: the
// Mutator methods need exactly this state.
type rpzGen struct {
	zone     string
	actions  []string
	triggers []string
	redirect string
	ttl      uint32
	counter  uint64
}

func buildRpz(c *Config, zone string, rz *rpzOpts, o *runOptions) (*ZoneSet, error) {
	d := &c.Zonegen.Defaults
	if rz.count < 1 {
		return nil, fmt.Errorf("--count must be at least 1")
	}
	actions, err := parseChoices(rz.actions, rpzActions, "--actions")
	if err != nil {
		return nil, err
	}
	triggers, err := parseChoices(rz.triggers, rpzTriggers, "--triggers")
	if err != nil {
		return nil, err
	}
	if contains(actions, "redirect") && rz.redirect == "" {
		return nil, fmt.Errorf("--actions includes redirect, so --redirect-target is required")
	}

	policy, policies, err := simplePolicy(!rz.signed, rz.kskAlg, rz.zskAlg)
	if err != nil {
		return nil, err
	}
	ns, rname := treeServerNames(c, zone)
	zs := &ZoneSet{Nameservers: ns, Rname: rname, Policies: policies}
	spec := ZoneSpec{Name: zone, Policy: policy}

	g := &rpzGen{zone: zone, actions: actions, triggers: triggers,
		redirect: dns.Fqdn(rz.redirect), ttl: d.TTL}

	if o.Update > 0 {
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

	rng := newRand(zone, rz.actions, rz.triggers, fmt.Sprint(rz.count))
	if err := g.fresh(&spec, rz.count, rng); err != nil {
		return nil, err
	}
	zs.Zones = append(zs.Zones, spec)
	zs.AddGlue(&c.Zonegen.Defaults)
	return zs, nil
}

// fresh lays down count rules, guaranteeing that every requested action and
// every requested trigger actually occurs before anything is left to chance.
func (g *rpzGen) fresh(spec *ZoneSpec, count int, rng *rand.Rand) error {
	if need := len(g.actions) * len(g.triggers); count < need {
		return fmt.Errorf("--count is %d but %d action(s) x %d trigger(s) need at least %d "+
			"rules to all occur", count, len(g.actions), len(g.triggers), need)
	}
	taken := map[string]bool{}
	// The guaranteed cross-product first.
	for _, t := range g.triggers {
		for _, a := range g.actions {
			owner := g.owner(t, taken)
			taken[owner] = true
			spec.Records = append(spec.Records, g.rule(owner, a))
		}
	}
	for len(taken) < count {
		owner := g.owner(g.triggers[rng.Intn(len(g.triggers))], taken)
		taken[owner] = true
		spec.Records = append(spec.Records, g.rule(owner, g.actions[rng.Intn(len(g.actions))]))
	}
	spec.Comments = []string{fmt.Sprintf("%d rules; actions: %s; triggers: %s",
		count, strings.Join(g.actions, ","), strings.Join(g.triggers, ","))}
	return nil
}

// owner builds the next unused owner name for a trigger type.
func (g *rpzGen) owner(trigger string, taken map[string]bool) string {
	for {
		var name string
		switch trigger {
		case "qname":
			name = Label(g.counter) + "." + g.zone
		case "nsdname":
			name = Label(g.counter) + ".rpz-nsdname." + g.zone
		default:
			// The address triggers encode a prefix as
			// "<prefixlen>.<reversed-address>", which is the RPZ convention.
			name = rpzAddrLabel(g.counter) + "." + rpzTriggers[trigger] + "." + g.zone
		}
		g.counter++
		if !taken[name] {
			return name
		}
	}
}

// rpzAddrLabel encodes an IPv4 /32 the way RPZ wants it: prefix length first,
// then the octets in reverse.
func rpzAddrLabel(n uint64) string {
	ip := net.IPv4(byte(198), byte(51), byte(100+(n>>24)&0x7f), byte(n)).To4()
	b := byte(n >> 8)
	return fmt.Sprintf("32.%d.%d.%d.%d", ip[3], b, ip[2], ip[0])
}

// rule renders one policy record.
func (g *rpzGen) rule(owner, action string) string {
	target := rpzActions[action]
	if action == "redirect" {
		target = g.redirect
	}
	return fmt.Sprintf("%s\t%d\tIN\tCNAME\t%s", owner, g.ttl, target)
}

// NewEntry and Remake are the Mutator half: what a churn should invent and what
// it should change. A changed rule keeps its owner -- the name it matches is
// the stable part of a policy -- and gets a different action, which is the
// change an operator actually makes.
func (g *rpzGen) NewEntry(rng *rand.Rand, taken map[string]bool) (string, []string) {
	owner := g.owner(g.triggers[rng.Intn(len(g.triggers))], taken)
	return owner, []string{g.rule(owner, g.actions[rng.Intn(len(g.actions))])}
}

func (g *rpzGen) Remake(rng *rand.Rand, owner string, current []string) []string {
	// Keep drawing until the rule actually differs. With a single action in
	// --actions there is nothing else to pick, so give up rather than spin.
	for tries := 0; tries < 20 && len(g.actions) > 1; tries++ {
		rule := g.rule(owner, g.actions[rng.Intn(len(g.actions))])
		if len(current) != 1 || rule != current[0] {
			return []string{rule}
		}
	}
	return []string{g.rule(owner, g.actions[rng.Intn(len(g.actions))])}
}

// parseChoices validates a comma-separated list against a table of known names.
func parseChoices(s string, known map[string]string, what string) ([]string, error) {
	var out []string
	for _, v := range strings.Split(s, ",") {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if _, ok := known[v]; !ok {
			return nil, fmt.Errorf("%s: unknown value %q", what, v)
		}
		if !contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is empty", what)
	}
	return out, nil
}
