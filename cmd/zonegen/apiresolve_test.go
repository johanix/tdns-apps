package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

const cliConfig = `
# A real tdns-cli.yaml is full of keys that are none of our business; the
# resolver must not choke on them.
algorithms:
   costsfile: /etc/tdns/algorithm-costs.yaml
apiservers:
   - name: tdns-server
     baseurl: https://127.0.0.1:8989/api/v1
     apikey: server-key
     authmethod: X-API-Key
   - name: tdns-agent
     baseurl: https://127.0.0.1:8987/api/v1
     apikey: agent-key
`

func TestResolveFromCliConfigPicksTheAuthServer(t *testing.T) {
	p := write(t, "tdns-cli.yaml", cliConfig)
	s, origin, err := ResolveApiServer(&Config{}, ApiOptions{CliFile: p})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Six entries in a stock config and the authoritative one is called
	// "tdns-server", NOT "tdns-auth" -- matching on "auth" finds nothing.
	if s.ApiKey != "server-key" {
		t.Errorf("picked the wrong entry: %+v", s)
	}
	if !strings.Contains(origin, p) {
		t.Errorf("origin should name the file it came from, got %q", origin)
	}
}

func TestResolveNamedEntryAndAmbiguity(t *testing.T) {
	p := write(t, "tdns-cli.yaml", cliConfig)
	s, _, err := ResolveApiServer(&Config{}, ApiOptions{CliFile: p, ServerName: "tdns-agent"})
	if err != nil || s.ApiKey != "agent-key" {
		t.Errorf("--apiserver should select by name, got %+v (%v)", s, err)
	}
	if _, _, err := ResolveApiServer(&Config{}, ApiOptions{CliFile: p, ServerName: "nope"}); err == nil {
		t.Error("an unknown --apiserver name must be an error")
	}

	// Several entries, none conventionally named: refuse rather than guess.
	// Creating key material in the wrong keystore is not a quiet mistake.
	amb := write(t, "amb.yaml", `
apiservers:
   - name: alpha
     baseurl: https://127.0.0.1:1/api/v1
     apikey: a
   - name: beta
     baseurl: https://127.0.0.1:2/api/v1
     apikey: b
`)
	_, _, err = ResolveApiServer(&Config{}, ApiOptions{CliFile: amb})
	if err == nil || !strings.Contains(err.Error(), "--apiserver") {
		t.Errorf("ambiguity must be refused with actionable advice, got %v", err)
	}
}

// TestResolveFromAuthConfigDerivesADialableUrl covers the two ways the
// derivation can be wrong.
//
// The scheme must come from usetls, NOT from whether certfile is set. tdns
// marks apiserver.certfile validate:"required", so a cert path is present even
// on a server that never offers TLS -- an earlier version of this keyed off
// certfile and would point https:// at a plain HTTP listener. tdns has no
// default for UseTLS (it is a plain bool), so an unset usetls means HTTP, and
// this mirrors that.
//
// And a wildcard listen address is bindable but not dialable, so it becomes
// loopback OF THE SAME FAMILY: an IPv6 wildcard must not become 127.0.0.1,
// which would never reach a server bound IPv6-only.
func TestResolveFromAuthConfigDerivesADialableUrl(t *testing.T) {
	cases := []struct {
		name string
		addr string
		// usetls is the literal config line, so the three states stay
		// distinguishable: explicitly true, explicitly false, and absent. An
		// earlier version of this test wrote nothing for the "off" case, which
		// silently conflated "off" with "relying on the default" -- and the
		// default is true, so that case was asserting the wrong thing.
		usetls     string
		wantURL    string
		wantRootCA string
	}{
		{"explicit true", "127.0.0.1:8989", "   usetls:     true\n",
			"https://127.0.0.1:8989/api/v1", "/etc/tdns/certs/server.crt"},
		// The originally reported bug: a cert is configured but TLS is off.
		{"explicit false despite a certfile", "127.0.0.1:8989", "   usetls:     false\n",
			"http://127.0.0.1:8989/api/v1", ""},
		// An absent key means TRUE, because the daemon injects that default
		// into the raw map before decoding. Getting this backwards makes the
		// tool dial HTTP at an HTTPS listener.
		{"omitted means true", "127.0.0.1:8989", "",
			"https://127.0.0.1:8989/api/v1", "/etc/tdns/certs/server.crt"},
		{"ipv4 wildcard", "0.0.0.0:8989", "   usetls:     true\n",
			"https://127.0.0.1:8989/api/v1", "/etc/tdns/certs/server.crt"},
		{"ipv6 wildcard keeps the family", "[::]:8989", "   usetls:     true\n",
			"https://[::1]:8989/api/v1", "/etc/tdns/certs/server.crt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := write(t, "tdns-auth.yaml", `
apiserver:
   addresses:  [ "`+tc.addr+`" ]
   apikey:     the-key
   certfile:   /etc/tdns/certs/server.crt
`+tc.usetls+`
zones:
   - name: example.
`)
			s, origin, err := ResolveApiServer(&Config{}, ApiOptions{AuthFile: p})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if s.BaseUrl != tc.wantURL {
				t.Errorf("baseurl = %q, want %q", s.BaseUrl, tc.wantURL)
			}
			if s.ApiKey != "the-key" {
				t.Errorf("apikey = %q", s.ApiKey)
			}
			// The server's own cert is a usable trust anchor only when it is
			// actually serving TLS with it, and only when self-signed.
			if s.RootCAFile != tc.wantRootCA {
				t.Errorf("rootcafile = %q, want %q", s.RootCAFile, tc.wantRootCA)
			}
			if !strings.Contains(origin, "derived from") {
				t.Errorf("origin should say it was derived, got %q", origin)
			}
		})
	}
}

func TestResolvePrecedenceAndRefusals(t *testing.T) {
	cli := write(t, "tdns-cli.yaml", cliConfig)

	// An explicit flag beats the zonegen config, which is the whole point of
	// the flag: the config is the thing you are trying not to have to write.
	own := &Config{ApiServers: []ApiServerConf{{Name: "own", BaseUrl: "https://x/api/v1", ApiKey: "own-key"}}}
	s, _, err := ResolveApiServer(own, ApiOptions{CliFile: cli})
	if err != nil || s.ApiKey != "server-key" {
		t.Errorf("an explicit --tdns-cli must win over the zonegen config, got %+v", s)
	}
	// With no flag, the tool's own config is used.
	s, origin, err := ResolveApiServer(own, ApiOptions{})
	if err != nil || s.ApiKey != "own-key" {
		t.Errorf("the zonegen config should be used when no flag is given, got %+v (%v)", s, err)
	}
	if !strings.Contains(origin, "zonegen config") {
		t.Errorf("origin = %q", origin)
	}
	// Both flags at once is a contradiction, not a precedence question.
	if _, _, err := ResolveApiServer(&Config{}, ApiOptions{CliFile: cli, AuthFile: cli}); err == nil {
		t.Error("--tdns-auth with --tdns-cli must be refused")
	}
	// An auth config with no address has nothing to connect to.
	empty := write(t, "tdns-auth.yaml", "apiserver:\n   apikey: k\n")
	if _, _, err := ResolveApiServer(&Config{}, ApiOptions{AuthFile: empty}); err == nil {
		t.Error("an auth config with no addresses must be refused")
	}
}
