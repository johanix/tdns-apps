/*
 * Guards the library's entry points, which is where the migration changed
 * shape: the commands used to hang off an exported parent and the flags used
 * to register themselves in init(). Both are now explicit, so both can be
 * wrong without the compiler noticing.
 */

package traffic

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestCommandsAreComplete(t *testing.T) {
	want := map[string]bool{
		"run": false, "stop": false, "extend": false,
		"status": false, "rampup": false, "dga": false,
	}
	for _, c := range Commands() {
		name := c.Name()
		if _, expected := want[name]; !expected {
			t.Errorf("unexpected command %q", name)
			continue
		}
		want[name] = true
		if c.Short == "" {
			t.Errorf("command %q has no Short description", name)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("command %q is missing from Commands()", name)
		}
	}
}

// TestRegisterFlagsCoversEveryCommandsNeeds pins that the flags the commands
// actually read are registered. They used to be attached in init() to a parent
// command; moving them into a function is exactly the kind of change that can
// silently drop one.
func TestRegisterFlagsCoversEveryCommandsNeeds(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)

	for _, name := range []string{
		"max", "qname", "qtype", "targets", "rampup", "sustain",
		"rampdown", "cycle", "ipv4", "ipv6", "transport",
	} {
		if fs.Lookup(name) == nil {
			t.Errorf("shared flag --%s was not registered", name)
		}
	}
	// Per-command flags land on their own command, not on the shared set.
	for cmdName, flags := range map[string][]string{
		"run": {"shape", "peaks", "qname-file", "random-prefix", "server", "logfile", "maxtime"},
		"dga": {"seed", "alg", "basename"},
	} {
		var target *pflag.FlagSet
		for _, c := range Commands() {
			if c.Name() == cmdName {
				target = c.Flags()
			}
		}
		if target == nil {
			t.Fatalf("no %s command", cmdName)
		}
		for _, f := range flags {
			if target.Lookup(f) == nil {
				t.Errorf("%s: flag --%s was not registered", cmdName, f)
			}
		}
	}
}

// The control socket is part of the app's identity; it should not drift back
// to the name the standalone tool used.
func TestSocketPathFollowsTheBinaryName(t *testing.T) {
	if SocketPath != "/tmp/tdns-traffic.sock" {
		t.Errorf("SocketPath = %q", SocketPath)
	}
}
