package traffic

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var RampUpCmd = &cobra.Command{
	Use:   "rampup",
	Short: "Send DNS queries in a sawtooth pattern (ramp up to max, then drop to zero qps)",
	Run: func(cmd *cobra.Command, args []string) {
		if len(targetList) == 0 {
			log.Fatal("No targets specified")
		}

		names := getNames()
		targets := resolveTargets(targetList, names)
		clients := makeClients(trafficTransport)

		totalPhaseDuration := rampUpDuration + sustainDuration + rampDownDuration
		if cycleDuration <= totalPhaseDuration {
			fmt.Printf("Cycle duration (%v) must be longer than the sum of rampup, sustain, and rampdown durations (%v)\n", cycleDuration, totalPhaseDuration)
			os.Exit(1)
		}

		zeroQPSDuration := cycleDuration - totalPhaseDuration
		log.Printf("Zero QPS period between cycles: %v", zeroQPSDuration)

		for {
			rampUp(targets, names, clients, rampUpDuration)
			sustain(targets, names, clients, sustainDuration)
			rampDown(targets, names, clients, rampDownDuration)
			fmt.Printf("Sleeping for %v until next cycle\n", zeroQPSDuration)
			time.Sleep(zeroQPSDuration)
		}
	},
}

var DGACmd = &cobra.Command{
	Use:   "dga",
	Short: "Send DNS queries in a DGA pattern",
	Run: func(cmd *cobra.Command, args []string) {
		if len(targetList) == 0 {
			log.Fatal("No targets specified")
		}

		dgaalg, err := ParseDGA(dgaalg)
		if err != nil {
			log.Fatal(err)
		}

		if _, ok := dns.IsDomainName(basename); !ok {
			log.Fatalf("Invalid base name: %s", basename)
		}
		basename = dns.Fqdn(basename)

		if len(seed) < 16 {
			log.Fatalf("Seed must be at least 16 characters")
		}

		targets := resolveTargets(targetList, nil)
		clients := makeClients(trafficTransport)

		changeDGA := time.NewTicker(5 * time.Second)
		defer changeDGA.Stop()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		name := CurrentDGA(dgaalg, seed, basename)

		for {
			select {
			case <-changeDGA.C:
				name = CurrentDGA(dgaalg, seed, basename)
				// sendDGAQueries(targets, name, clients)
			case <-ticker.C:
				sendDGAQueries(targets, name, clients)
			}
		}
	},
}

var seed, basename, dgaalg string

// Commands returns the commands this package provides, for the caller to
// place wherever it likes. Returning them rather than attaching them to an
// exported parent is what lets the app decide its own command hierarchy: the
// binary is called tdns-traffic, so its subcommands are `run`, `stop` and so
// on, not `traffic run`.
func Commands() []*cobra.Command {
	return []*cobra.Command{RunCmd, StopCmd, ExtendCmd, StatusCmd, RampUpCmd, DGACmd}
}

// RegisterFlags attaches the flags shared by every command above to fs, which
// the caller will normally take from its root command's persistent flags.
//
// This is a function rather than an init() because a library that registers
// flags merely by being linked cannot be used twice, cannot be tested without
// global state, and forces its own opinion about which command owns them.
func RegisterFlags(fs *pflag.FlagSet) {
	fs.IntVarP(&maxQPS, "max", "m", 1000, "Maximum queries per second")
	fs.StringVarP(&trafficQName, "qname", "", "", "Domain name to query for")
	fs.StringVarP(&trafficQType, "qtype", "", "A", "RR type to query for (A, AAAA, NS, MX, ...; or 'random' for a mix)")
	fs.StringSliceVarP(&targetList, "targets", "t", []string{}, "List of target IPs or domain names")
	fs.DurationVarP(&rampUpDuration, "rampup", "", 60*time.Second, "Duration of the ramp-up phase")
	fs.DurationVarP(&sustainDuration, "sustain", "", 30*time.Second, "Duration of the sustain phase")
	fs.DurationVarP(&rampDownDuration, "rampdown", "", 10*time.Second, "Duration of the ramp-down phase")
	fs.DurationVarP(&cycleDuration, "cycle", "", 120*time.Second, "Total duration of a cycle")
	fs.BoolVarP(&ipv4Only, "ipv4", "4", false, "Only send queries over IPv4 (like dig -4)")
	fs.BoolVarP(&ipv6Only, "ipv6", "6", false, "Only send queries over IPv6 (like dig -6)")
	fs.StringVar(&trafficTransport, "transport", "udp", "Query transport: udp (default), tcp, or both")

	DGACmd.Flags().StringVarP(&seed, "seed", "S", "", "Seed for the DGA algorithm")
	DGACmd.Flags().StringVarP(&dgaalg, "alg", "A", "", "DGA algorithm (md5+time or linear)")
	DGACmd.Flags().StringVarP(&basename, "basename", "B", "", "Base name for the DGA algorithm")

	RunCmd.Flags().StringVar(&shapeName, "shape", "trapezoid", "QPS shape (see --help for list)")
	RunCmd.Flags().IntVar(&peakCount, "peaks", 3, "Number of peaks per cycle (only for 'peaks' shape)")
	RunCmd.Flags().StringVar(&qnameFile, "qname-file", "", "File with base qnames (one per line)")
	RunCmd.Flags().IntVar(&randomPrefixPct, "random-prefix", 0, "Percentage of qnames that get a random prefix (0-100)")
	RunCmd.Flags().BoolVar(&serverMode, "server", false, "Run as a background server (detach from terminal)")
	RunCmd.Flags().StringVar(&logFile, "logfile", "", "Log file (default: stderr; useful with --server)")
	RunCmd.Flags().DurationVar(&maxTime, "maxtime", 0, "Maximum run time (required for --server, e.g. 30m, 2h)")
}
