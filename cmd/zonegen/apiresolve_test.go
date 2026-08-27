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

func TestResolveFromAuthConfigDerivesADialableUrl(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8989": "https://127.0.0.1:8989/api/v1",
		// A wildcard is bindable but not dialable, so it must become loopback
		// rather than being pasted into a URL verbatim.
		"0.0.0.0:8989": "https://127.0.0.1:8989/api/v1",
		"[::]:8989":    "https://127.0.0.1:8989/api/v1",
	}
	for addr, want := range cases {
		t.Run(addr, func(t *testing.T) {
			p := write(t, "tdns-auth.yaml", `
apiserver:
   addresses:  [ "`+addr+`" ]
   apikey:     the-key
   certfile:   /etc/tdns/certs/server.crt
zones:
   - name: example.
`)
			s, origin, err := ResolveApiServer(&Config{}, ApiOptions{AuthFile: p})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if s.BaseUrl != want {
				t.Errorf("baseurl = %q, want %q", s.BaseUrl, want)
			}
			if s.ApiKey != "the-key" {
				t.Errorf("apikey = %q", s.ApiKey)
			}
			// certfile is the server's own cert, which is the right trust
			// anchor only when it is self-signed -- but it is the only thing
			// the server config offers.
			if s.RootCAFile != "/etc/tdns/certs/server.crt" {
				t.Errorf("rootcafile = %q", s.RootCAFile)
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
