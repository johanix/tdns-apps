package traffic

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var TrafficCmd = &cobra.Command{
	Use:   "traffic",
	Short: "Generate DNS query traffic",
}

var TrafficRampUpCmd = &cobra.Command{
	Use:   "rampup",
	Short: "Send DNS queries in a sawtooth pattern (ramp up to max, then drop to zero qps)",
	Run: func(cmd *cobra.Command, args []string) {
		if len(targetList) == 0 {
			log.Fatal("No targets specified")
		}

		names := getNames()
		targets := resolveTargets(targetList)
		client := new(dns.Client)

		totalPhaseDuration := rampUpDuration + sustainDuration + rampDownDuration
		if cycleDuration <= totalPhaseDuration {
			fmt.Printf("Cycle duration (%v) must be longer than the sum of rampup, sustain, and rampdown durations (%v)\n", cycleDuration, totalPhaseDuration)
			os.Exit(1)
		}

		zeroQPSDuration := cycleDuration - totalPhaseDuration
		log.Printf("Zero QPS period between cycles: %v", zeroQPSDuration)

		for {
			rampUp(targets, names, client, rampUpDuration)
			sustain(targets, names, client, sustainDuration)
			rampDown(targets, names, client, rampDownDuration)
			fmt.Printf("Sleeping for %v until next cycle\n", zeroQPSDuration)
			time.Sleep(zeroQPSDuration)
		}
	},
}

var TrafficDGACmd = &cobra.Command{
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

		targets := resolveTargets(targetList)
		client := new(dns.Client)

		changeDGA := time.NewTicker(5 * time.Second)
		defer changeDGA.Stop()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		name := CurrentDGA(dgaalg, seed, basename)

		for {
			select {
			case <-changeDGA.C:
				name = CurrentDGA(dgaalg, seed, basename)
				// sendDGAQueries(targets, name, client)
			case <-ticker.C:
				sendDGAQueries(targets, name, client)
			}
		}
	},
}

var seed, basename, dgaalg string

func init() {
	TrafficCmd.AddCommand(TrafficRampUpCmd, TrafficDGACmd)
	TrafficCmd.PersistentFlags().IntVarP(&maxQPS, "max", "m", 1000, "Maximum queries per second")
	TrafficCmd.PersistentFlags().StringVarP(&trafficQName, "qname", "", "", "Domain name to query for")
	TrafficCmd.PersistentFlags().StringSliceVarP(&targetList, "targets", "t", []string{}, "List of target IPs or domain names")
	TrafficCmd.PersistentFlags().DurationVarP(&rampUpDuration, "rampup", "", 60*time.Second, "Duration of the ramp-up phase")
	TrafficCmd.PersistentFlags().DurationVarP(&sustainDuration, "sustain", "", 30*time.Second, "Duration of the sustain phase")
	TrafficCmd.PersistentFlags().DurationVarP(&rampDownDuration, "rampdown", "", 10*time.Second, "Duration of the ramp-down phase")
	TrafficCmd.PersistentFlags().DurationVarP(&cycleDuration, "cycle", "", 120*time.Second, "Total duration of a cycle")
	TrafficDGACmd.Flags().StringVarP(&seed, "seed", "S", "", "Seed for the DGA algorithm")
	TrafficDGACmd.Flags().StringVarP(&dgaalg, "alg", "A", "", "DGA algorithm (md5+time or linear)")
	TrafficDGACmd.Flags().StringVarP(&basename, "basename", "B", "", "Base name for the DGA algorithm")
}

