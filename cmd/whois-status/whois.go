package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// WhoisQuery sends a whois query for the given domain to server (host:port)
// and returns the raw response body.
//
// The .SE whois server accepts a bare domain followed by CRLF; other servers
// may want flag prefixes ("-T dom foo"). That's not needed for IIS's server,
// so we keep the query minimal.
func WhoisQuery(ctx context.Context, server, domain string, timeout time.Duration) ([]byte, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	// Strip trailing dot for whois; it doesn't expect FQDN notation.
	q := strings.TrimSuffix(domain, ".") + "\r\n"
	if _, err := conn.Write([]byte(q)); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	body, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return body, nil
}

// ExtractStatuses scans a whois response for "status:" lines and returns
// each status value, preserving order and case. Expected input is plain
// ASCII text with lines like "status: ok" or "status: serverTransferProhibited".
func ExtractStatuses(body []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// Case-insensitive match on the key.
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "status:") {
			continue
		}
		v := strings.TrimSpace(line[len("status:"):])
		// Some whois outputs include parenthetical annotations after the
		// code, e.g. "status: serverTransferProhibited (EPP)". Take the
		// first whitespace-delimited token.
		if idx := strings.IndexAny(v, " \t"); idx > 0 {
			v = v[:idx]
		}
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

// MatchesAny reports whether any of needles appears in haystack
// (case-sensitive exact match — EPP status codes are fixed identifiers).
func MatchesAny(haystack, needles []string) bool {
	set := make(map[string]struct{}, len(needles))
	for _, n := range needles {
		set[n] = struct{}{}
	}
	for _, h := range haystack {
		if _, ok := set[h]; ok {
			return true
		}
	}
	return false
}
