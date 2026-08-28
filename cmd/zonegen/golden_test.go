/*
 * The refactor gate.
 *
 * The pqtree generator is being lifted out of a tool that could only ever
 * generate pqtrees. Its OUTPUT must not change while that happens: same zone
 * files, same config block, byte for byte. This test pins that output before
 * the refactor starts, so the whole restructuring reduces to a diff that is
 * either empty or wrong.
 *
 * Everything time- or server-dependent is injected (the serial, the DS
 * records), so the golden file is a pure function of the config.
 */

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite the golden file from current output")

// goldenConfigYAML is inlined rather than read from the shipped sample, so that
// editing the sample cannot silently move the gate.
const goldenConfigYAML = `
apiservers:
   - name: tdns-auth
     baseurl: https://127.0.0.1:8989/api/v1
     apikey: k
zonegen:
   output:
      zonedir: /etc/tdns/zones
      configfile: /etc/tdns/auth-pq-zones.yaml
   sigvalidity:
      default: 14d
      dnskey:  30d
      ds:      14d
   pqtree:
      parent:
         name:         pq.example.
         nameservers:  [ ns1.example., ns2.example. ]
         addresses:    [ 192.0.2.1, "2001:db8::1" ]
         rname:        hostmaster.example.
         ksk:          ED25519
         zsk:          ED25519
      children:
         label:      "{ksk}-{zsk}"
         addresses:  [ 192.0.2.2 ]
         records:
            - "www  IN  A  192.0.2.2"
         combos:
            - { ksk: MLDSA87,    zsk: ED25519 }
            - { ksk: MLDSA44,    zsk: ED25519 }
            - { ksk: SLHDSA128S, zsk: ED25519 }
            - { ksk: FALCON512,  zsk: FALCON512 }
            - { ksk: SQISIGN1,   zsk: SQISIGN1 }
            - { ksk: ED25519,    zsk: ED25519 }
            - { ksk: RSASHA256,  zsk: ED25519 }
`

// fakeDS is a stand-in for what the keystore would return. The content does not
// matter; that it is stable does.
func fakeDS(zone string) []string {
	return []string{"12345 13 2 " + strings.Repeat("ab", 32)}
}

// renderAll renders every artifact the tool writes, in a stable order, into one
// document. Comparing one document rather than N files keeps the golden
// readable as a diff.
//
// Children are rendered before the parent because that is the order the
// pre-refactor tool wrote them in, and the point of this file is that NOTHING
// about the output moved.
func renderAll(t *testing.T, c *Config) string {
	t.Helper()
	zs, err := buildPqtree(c)
	if err != nil {
		t.Fatalf("buildPqtree: %v", err)
	}
	zs.Serial = 2026082701
	for i := range zs.Zones {
		zs.Zones[i].DS = fakeDS(zs.Zones[i].Name)
	}
	d := &c.Zonegen.Defaults

	var b strings.Builder
	for i := 1; i < len(zs.Zones); i++ {
		b.WriteString("===== FILE " + c.ZonefilePath(zs.Zones[i].Name) + "\n")
		b.WriteString(zs.Render(&zs.Zones[i], d))
	}
	b.WriteString("===== FILE " + c.ZonefilePath(zs.Zones[0].Name) + "\n")
	b.WriteString(zs.Render(&zs.Zones[0], d))
	b.WriteString("===== FILE " + c.Zonegen.Output.ConfigFile + "\n")
	b.WriteString(zs.AuthConfig(c))
	b.WriteString("===== DELEGATION SNIPPET\n")
	b.WriteString(zs.DelegationSnippet())
	return b.String()
}

func TestPqtreeGoldenOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zonegen.yaml")
	if err := os.WriteFile(path, []byte(goldenConfigYAML), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := LoadConfig(path, true)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := c.ValidatePqtree(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	got := renderAll(t, c)

	goldenPath := filepath.Join("testdata", "pqtree.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(got))
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading the golden file: %v\nrun: go test -run TestPqtreeGoldenOutput -update-golden", err)
	}
	if got != string(want) {
		t.Errorf("pqtree output changed. First difference:\n%s", firstDiff(string(want), got))
	}
}

// firstDiff reports the first differing line with a little context, which is
// far more useful on a 300-line artifact than dumping both versions.
func firstDiff(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "  line " + itoa(i+1) + "\n  want: " + wl + "\n  got:  " + gl
		}
	}
	return "(no line differs; trailing newline?)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
