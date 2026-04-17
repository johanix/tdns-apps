/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * IMR hook implementations for DNS dependency analysis.
 * Hooks are registered before TDNS initialization and called by the IMR
 * at the three interception points defined in registration.go.
 */
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// --- Context key for linking iterative queries to client queries ---

type ddepContextKey struct{}

func ddepParentID(ctx context.Context) uint64 {
	if v, ok := ctx.Value(ddepContextKey{}).(uint64); ok {
		return v
	}
	return 0
}

// --- Query session ---

type QueryCategory uint8

const (
	QueryClient    QueryCategory = iota // from browser/client
	QueryIterative                      // sub-query to auth server
)

type QueryEntry struct {
	ID         uint64
	Timestamp  time.Time
	Category   QueryCategory
	Qname      string
	Qtype      uint16
	ParentID   uint64 // 0 for client queries; client query ID for iterative
	ServerName string // only for iterative
	ServerAddr string // only for iterative
	Transport  core.Transport
	Rcode      int
	Blocked    bool
	BlockRule  string
}

type QuerySession struct {
	mu      sync.Mutex
	active  bool
	entries []QueryEntry
	counter atomic.Uint64
}

var session = &QuerySession{}

func (s *QuerySession) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = true
	s.entries = nil
	s.counter.Store(0)
}

func (s *QuerySession) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
}

func (s *QuerySession) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *QuerySession) LogClient(qname string, qtype uint16) uint64 {
	id := s.counter.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return 0
	}
	s.entries = append(s.entries, QueryEntry{
		ID:        id,
		Timestamp: time.Now(),
		Category:  QueryClient,
		Qname:     qname,
		Qtype:     qtype,
	})
	return id
}

func (s *QuerySession) LogIterative(parentID uint64, qname string, qtype uint16, serverName, serverAddr string, transport core.Transport) uint64 {
	id := s.counter.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return 0
	}
	s.entries = append(s.entries, QueryEntry{
		ID:         id,
		Timestamp:  time.Now(),
		Category:   QueryIterative,
		Qname:      qname,
		Qtype:      qtype,
		ParentID:   parentID,
		ServerName: serverName,
		ServerAddr: serverAddr,
		Transport:  transport,
	})
	return id
}

func (s *QuerySession) LogBlocked(qname string, qtype uint16, parentID uint64, ruleName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return
	}
	s.entries = append(s.entries, QueryEntry{
		ID:        s.counter.Add(1),
		Timestamp: time.Now(),
		Category:  QueryClient,
		Qname:     qname,
		Qtype:     qtype,
		ParentID:  parentID,
		Blocked:   true,
		BlockRule: ruleName,
	})
}

func (s *QuerySession) UpdateIterResponse(parentID uint64, qname string, qtype uint16, serverName string, rcode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.entries) - 1; i >= 0; i-- {
		e := &s.entries[i]
		if e.Category == QueryIterative && e.ParentID == parentID &&
			e.Qname == qname && e.Qtype == qtype && e.ServerName == serverName {
			e.Rcode = rcode
			return
		}
	}
}

func (s *QuerySession) Entries() []QueryEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]QueryEntry, len(s.entries))
	copy(cp, s.entries)
	return cp
}

// --- Block rules ---

type BlockAction uint8

const (
	BlockActionNone BlockAction = iota
	BlockActionNXDOMAIN
	BlockActionNODATA
	BlockActionDROP
	BlockActionRedirect
	BlockActionAllow // RPZ PASSTHRU — whitelisting
)

var blockActionToString = map[BlockAction]string{
	BlockActionNone:     "none",
	BlockActionNXDOMAIN: "nxdomain",
	BlockActionNODATA:   "nodata",
	BlockActionDROP:     "drop",
	BlockActionRedirect: "redirect",
	BlockActionAllow:    "allow",
}

var stringToBlockAction = map[string]BlockAction{
	"nxdomain": BlockActionNXDOMAIN,
	"nodata":   BlockActionNODATA,
	"drop":     BlockActionDROP,
	"redirect": BlockActionRedirect,
	"allow":    BlockActionAllow,
}

type BlockRule struct {
	Pattern    string      `json:"pattern"`
	Action     BlockAction `json:"action"`
	ActionStr  string      `json:"action_str"`
	Qtype      uint16      `json:"qtype,omitempty"`     // 0 means all qtypes
	QtypeStr   string      `json:"qtype_str,omitempty"` // for readability
	RedirectTo string      `json:"redirect_to,omitempty"`
}

type BlockRuleSet struct {
	mu       sync.RWMutex
	rules    []BlockRule
	filePath string
}

var blockRules = &BlockRuleSet{}

func (rs *BlockRuleSet) Match(qname string, qtype uint16) (BlockAction, *BlockRule) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	qname = dns.CanonicalName(qname)
	for i := range rs.rules {
		r := &rs.rules[i]
		if r.Qtype != 0 && r.Qtype != qtype {
			continue
		}
		if matchesPattern(qname, r.Pattern) {
			return r.Action, r
		}
	}
	return BlockActionNone, nil
}

func matchesPattern(qname, pattern string) bool {
	pattern = dns.CanonicalName(pattern)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com."
		return strings.HasSuffix(qname, suffix) || qname == pattern[2:]
	}
	return qname == pattern
}

func (rs *BlockRuleSet) Add(rule BlockRule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rule.ActionStr = blockActionToString[rule.Action]
	if rule.Qtype != 0 {
		rule.QtypeStr = dns.TypeToString[rule.Qtype]
	}
	rs.rules = append(rs.rules, rule)
	rs.save()
}

func (rs *BlockRuleSet) Remove(pattern string, qtype uint16) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	pattern = dns.CanonicalName(pattern)
	for i, r := range rs.rules {
		if dns.CanonicalName(r.Pattern) == pattern && (qtype == 0 || r.Qtype == qtype) {
			rs.rules = append(rs.rules[:i], rs.rules[i+1:]...)
			rs.save()
			return true
		}
	}
	return false
}

func (rs *BlockRuleSet) Clear() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = nil
	rs.save()
}

func (rs *BlockRuleSet) List() []BlockRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	cp := make([]BlockRule, len(rs.rules))
	copy(cp, rs.rules)
	return cp
}

func (rs *BlockRuleSet) Load() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	data, err := os.ReadFile(rs.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no file yet, that's fine
		}
		return err
	}
	return json.Unmarshal(data, &rs.rules)
}

func (rs *BlockRuleSet) save() error {
	data, err := json.MarshalIndent(rs.rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rs.filePath, data, 0644)
}

// loadBlockRules initializes the block rule set from persistent storage.
func loadBlockRules() {
	path := viper.GetString("ddep.blockrules_file")
	if path == "" {
		path = "/etc/tdns/ddep-block-rules.json"
	}
	blockRules.filePath = path
	if err := blockRules.Load(); err != nil {
		fmt.Printf("Warning: failed to load block rules from %s: %v\n", path, err)
	} else {
		rules := blockRules.List()
		if len(rules) > 0 {
			fmt.Printf("Loaded %d block rules from %s\n", len(rules), path)
		}
	}
}

// --- Hook registration ---

func registerDdepHooks() {
	tdns.RegisterImrClientQueryHook(onClientQuery)
	tdns.RegisterImrOutboundQueryHook(onOutboundQuery)
	tdns.RegisterImrResponseHook(onResponse)
}

// onClientQuery is called when an external client query arrives at the IMR listener.
func onClientQuery(ctx context.Context, w dns.ResponseWriter, r *dns.Msg,
	qname string, qtype uint16, msgoptions *edns0.MsgOptions) (context.Context, *dns.Msg) {

	// Log the client query if session is active
	var clientID uint64
	if session.IsActive() {
		clientID = session.LogClient(qname, qtype)
	}

	// Enrich context with client query ID for linking iterative sub-queries
	newCtx := context.WithValue(ctx, ddepContextKey{}, clientID)

	// Check block rules
	action, rule := blockRules.Match(qname, qtype)
	if action != BlockActionNone && action != BlockActionAllow {
		if session.IsActive() {
			session.LogBlocked(qname, qtype, 0, rule.Pattern)
		}
		response := synthesizeBlockResponse(r, qname, qtype, action, rule)
		if response == nil {
			// DROP action — return nil response so WriteMsg is never called
			// and the client times out
			return newCtx, nil
		}
		return newCtx, response
	}

	return newCtx, nil // proceed with normal resolution
}

// onOutboundQuery is called before the IMR sends an iterative query to an auth server.
func onOutboundQuery(ctx context.Context, qname string, qtype uint16,
	serverName string, serverAddr string, transport core.Transport) error {

	parentID := ddepParentID(ctx)

	// Log the iterative query if session is active
	if session.IsActive() {
		session.LogIterative(parentID, qname, qtype, serverName, serverAddr, transport)
	}

	// Check block rules against the qname being resolved
	action, rule := blockRules.Match(qname, qtype)
	if action != BlockActionNone && action != BlockActionAllow {
		if session.IsActive() {
			session.LogBlocked(qname, qtype, parentID, rule.Pattern)
		}
		return fmt.Errorf("blocked by rule: %s -> %s", rule.Pattern, blockActionToString[action])
	}

	return nil // proceed with query
}

// onResponse is called after the IMR receives a response from an auth server.
// Updates the most recent matching ITER entry with the response rcode.
func onResponse(ctx context.Context, qname string, qtype uint16,
	serverName string, serverAddr string, transport core.Transport,
	response *dns.Msg, rcode int) {
	if !session.IsActive() {
		return
	}
	parentID := ddepParentID(ctx)
	session.UpdateIterResponse(parentID, qname, qtype, serverName, rcode)
}

// synthesizeBlockResponse creates a DNS response for a blocked query.
func synthesizeBlockResponse(r *dns.Msg, qname string, qtype uint16, action BlockAction, rule *BlockRule) *dns.Msg {
	switch action {
	case BlockActionNXDOMAIN:
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.RecursionAvailable = true
		return m

	case BlockActionNODATA:
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		m.RecursionAvailable = true
		return m

	case BlockActionDROP:
		return nil // caller won't send any response

	case BlockActionRedirect:
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		m.RecursionAvailable = true
		if rule != nil && rule.RedirectTo != "" {
			ip := net.ParseIP(rule.RedirectTo)
			if ip != nil {
				if ip.To4() != nil {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ip.To4(),
					})
				} else {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ip,
					})
				}
			}
		}
		return m

	default:
		return nil
	}
}
