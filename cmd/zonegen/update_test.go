/*
 * --update: the zone file is the state, so these tests go through real files.
 */

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRpz generates a fresh RPZ zone to a file and returns the path.
func writeRpz(t *testing.T, c *Config, zone string, count int) (string, *ZoneSet) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rpz.zone")
	o := &runOptions{OutFile: path}
	rz := &rpzOpts{count: count, actions: "nxdomain,nodata,passthru,redirect",
		triggers: "qname", redirect: "walled-garden.example."}
	zs, err := buildRpz(c, zone, rz, o)
	if err != nil {
		t.Fatalf("buildRpz: %v", err)
	}
	zs.Serial = NewSerial(nowFunc(), 0)
	if err := writeFile(path, zs.Render(&zs.Zones[0], &c.Zonegen.Defaults)); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path, zs
}

func ownersOf(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 5 && f[3] == "CNAME" {
			out[f[0]] = f[4]
		}
	}
	return out
}

func TestUpdateChurnsRoughlyThePercentageAsked(t *testing.T) {
	c := baseConfig(t)
	zone := "rpz.example."
	path, before := writeRpz(t, c, zone, 300)
	beforeText := before.Render(&before.Zones[0], &c.Zonegen.Defaults)

	o := &runOptions{OutFile: path, Update: 10}
	rz := &rpzOpts{count: 300, actions: "nxdomain,nodata,passthru,redirect",
		triggers: "qname", redirect: "walled-garden.example."}
	after, err := buildRpz(c, zone, rz, o)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	afterText := after.Render(&after.Zones[0], &c.Zonegen.Defaults)

	// The serial must advance, or no secondary ever notices the change. This is
	// the case the old date-only serial got wrong.
	if after.Serial <= before.Serial {
		t.Errorf("serial did not advance: %d -> %d", before.Serial, after.Serial)
	}

	a, b := ownersOf(beforeText), ownersOf(afterText)
	var removed, changed, added int
	for owner, target := range a {
		switch newTarget, still := b[owner]; {
		case !still:
			removed++
		case newTarget != target:
			changed++
		}
	}
	for owner := range b {
		if _, was := a[owner]; !was {
			added++
		}
	}
	touched := removed + changed + added
	// 10% of 300 is 30. Allow slack for the three-way split rounding, but the
	// point is that it is a SMALL delta -- an IXFR fixture, not a new zone.
	if touched < 20 || touched > 45 {
		t.Errorf("--update 10 on 300 rules touched %d (removed %d, changed %d, added %d); "+
			"want roughly 30", touched, removed, changed, added)
	}
	// Adds and removes should roughly balance, so repeated updates do not make
	// the zone grow or shrink without bound.
	if diff := added - removed; diff > 5 || diff < -5 {
		t.Errorf("adds and removes are unbalanced (%d added, %d removed); "+
			"the zone would drift in size over repeated updates", added, removed)
	}
	if len(b) == 0 {
		t.Fatal("the update emptied the zone")
	}
}

// TestUpdateIsReproducible is what makes a chain of updates replayable: the
// same input file must always churn into the same output file.
func TestUpdateIsReproducible(t *testing.T) {
	c := baseConfig(t)
	zone := "rpz.example."
	path, _ := writeRpz(t, c, zone, 200)

	run := func() string {
		o := &runOptions{OutFile: path, Update: 7}
		rz := &rpzOpts{count: 200, actions: "nxdomain,nodata,passthru,redirect",
			triggers: "qname", redirect: "walled-garden.example."}
		zs, err := buildRpz(c, zone, rz, o)
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		zs.Serial = 1 // the serial is time-dependent; the CONTENT is what is pinned
		return zs.Render(&zs.Zones[0], &c.Zonegen.Defaults)
	}
	if a, b := run(), run(); a != b {
		t.Error("two updates of the same file produced different zones")
	}
}

// TestUpdateRefusesAForeignFile: --update rewrites a file in place. Doing that
// to a hand-written zone because of a typo in --outfile should take an explicit
// --force, the same way the keystore's bulk import does.
func TestUpdateRefusesAForeignFile(t *testing.T) {
	c := baseConfig(t)
	path := filepath.Join(t.TempDir(), "handwritten.zone")
	handwritten := "rpz.example.\t3600\tIN\tSOA\tns1.rpz.example. hostmaster.rpz.example. ( 7 3600 600 1209600 600 )\n" +
		"rpz.example.\t3600\tIN\tNS\tns1.rpz.example.\n" +
		"evil.rpz.example.\t3600\tIN\tCNAME\t.\n"
	if err := os.WriteFile(path, []byte(handwritten), 0644); err != nil {
		t.Fatal(err)
	}

	rz := &rpzOpts{count: 10, actions: "nxdomain", triggers: "qname",
		redirect: "walled-garden.example."}
	_, err := buildRpz(c, "rpz.example.", rz, &runOptions{OutFile: path, Update: 10})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("updating a foreign file must be refused and mention --force, got %v", err)
	}

	// With --force it goes ahead, and still advances the serial it found.
	zs, err := buildRpz(c, "rpz.example.", rz,
		&runOptions{OutFile: path, Update: 10, Force: true})
	if err != nil {
		t.Fatalf("--force should allow it: %v", err)
	}
	if zs.Serial <= 7 {
		t.Errorf("serial should advance past the 7 it found, got %d", zs.Serial)
	}
}

// TestUpdatedZoneIsStillLegal: churn must not be able to produce an illegal
// zone, however many times it runs.
func TestUpdatedZoneIsStillLegal(t *testing.T) {
	c := baseConfig(t)
	zone := "rpz.example."
	path, _ := writeRpz(t, c, zone, 150)

	for round := 0; round < 5; round++ {
		o := &runOptions{OutFile: path, Update: 12}
		rz := &rpzOpts{count: 150, actions: "nxdomain,nodata,drop,passthru,redirect",
			triggers: "qname,nsdname", redirect: "walled-garden.example."}
		zs, err := buildRpz(c, zone, rz, o)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		byOwner := parseZone(t, zs, c, 0)
		assertLegal(t, byOwner, zone)
		if err := writeFile(path, zs.Render(&zs.Zones[0], &c.Zonegen.Defaults)); err != nil {
			t.Fatal(err)
		}
	}
}
