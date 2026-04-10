package traffic

import (
	"crypto/md5"
	"fmt"
	"log"
	"math/rand"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

var maxQPS int
var trafficQName string
var trafficQType string
var trafficTransport string
var targetList []string
var rampUpDuration time.Duration
var sustainDuration time.Duration
var rampDownDuration time.Duration
var cycleDuration time.Duration
var ipv4Only bool
var ipv6Only bool

// randomQTypes is the pool used when --qtype=random.
var randomQTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeNS,
	dns.TypeMX,
	dns.TypeTXT,
	dns.TypeSOA,
	dns.TypeCNAME,
	dns.TypePTR,
	dns.TypeSRV,
	dns.TypeDS,
	dns.TypeDNSKEY,
}

// parseQType resolves the --qtype flag to a miekg/dns type code.
// Accepts names like "A", "AAAA", "MX", "TYPE65" (case-insensitive).
// The special value "random" returns 0 — callers must then use
// pickQType to draw a fresh type for each query.
func parseQType(s string) (uint16, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return dns.TypeA, nil
	}
	if s == "RANDOM" {
		return 0, nil
	}
	if t, ok := dns.StringToType[s]; ok {
		return t, nil
	}
	return 0, fmt.Errorf("unknown RR type: %s", s)
}

// pickQType returns a random type from randomQTypes.
func pickQType() uint16 {
	return randomQTypes[rand.Intn(len(randomQTypes))]
}

// makeClients returns one or two dns.Clients based on the --transport
// flag. For "udp" or "tcp" it returns a single client; for "both" it
// returns two (one UDP, one TCP). Callers round-robin across the slice.
func makeClients(transport string) []*dns.Client {
	switch strings.ToLower(transport) {
	case "tcp":
		return []*dns.Client{{Net: "tcp"}}
	case "both":
		return []*dns.Client{{Net: "udp"}, {Net: "tcp"}}
	default:
		return []*dns.Client{{Net: "udp"}}
	}
}

func getNames() []string {
	if trafficQName != "" {
		return []string{trafficQName}
	}
	return viper.GetStringSlice("traffic.names")
}

// resolveTargets expands each target (IP or hostname) into one or more
// "ip:53" addresses. Each address is probed once with a query matching
// what the generator will actually send (same qname, same qtype). The
// probe is informational only — addresses are kept in the returned list
// regardless of the probe outcome, so transient failures or firewall
// quirks at startup do not silently remove an entire address family.
func resolveTargets(targets, names []string) []string {
	if ipv4Only && ipv6Only {
		log.Fatal("Cannot specify both -4 and -6")
	}

	// Pick a representative qname/qtype for the probe. These match what
	// sendQueries will use for real traffic, so a working probe implies
	// the actual workload will be accepted too.
	probeName := "."
	if len(names) > 0 {
		probeName = dns.Fqdn(names[0])
	}
	probeType, err := parseQType(trafficQType)
	if err != nil {
		log.Fatalf("Invalid --qtype: %v", err)
	}
	if probeType == 0 {
		// --qtype=random: just pick A for the probe.
		probeType = dns.TypeA
	}

	var resolved []string
	client := new(dns.Client)
	for _, target := range targets {
		ips, err := net.LookupIP(target)
		if err != nil {
			log.Printf("Error resolving target %s: %v", target, err)
			continue
		}
		log.Printf("Target %s resolved to %d address(es): %v", target, len(ips), ips)
		for _, ip := range ips {
			isV4 := ip.To4() != nil
			if ipv4Only && !isV4 {
				log.Printf("Skipping %s (--ipv4 set)", ip)
				continue
			}
			if ipv6Only && isV4 {
				log.Printf("Skipping %s (--ipv6 set)", ip)
				continue
			}
			address := net.JoinHostPort(ip.String(), "53")
			m := new(dns.Msg)
			m.SetQuestion(probeName, probeType)
			_, _, err := client.Exchange(m, address)
			if err != nil {
				log.Printf("Warning: probe %s %s to %s failed: %v — keeping target anyway",
					probeName, dns.TypeToString[probeType], address, err)
			} else {
				log.Printf("Probe %s %s to %s succeeded",
					probeName, dns.TypeToString[probeType], address)
			}
			resolved = append(resolved, address)
		}
	}
	return resolved
}

func rampUp(targets, names []string, clients []*dns.Client, duration time.Duration) {
	fmt.Printf("Ramping up to %d qps over %v\n", maxQPS, duration)
	step := maxQPS / int(duration.Seconds())
	for qps := 0; qps <= maxQPS; qps += step {
		targets = sendQueries(targets, names, qps, clients)
		time.Sleep(time.Second)
	}
}

func sustain(targets, names []string, clients []*dns.Client, duration time.Duration) {
	fmt.Printf("Sustaining traffic at %d qps for %v\n", maxQPS, duration)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timeout := time.After(duration)
	for {
		select {
		case <-ticker.C:
			targets = sendQueries(targets, names, maxQPS, clients)
		case <-timeout:
			return
		}
	}
}

func rampDown(targets, names []string, clients []*dns.Client, duration time.Duration) {
	fmt.Printf("Ramping down to 0 qps over %v\n", duration)
	step := maxQPS / int(duration.Seconds())
	for qps := maxQPS; qps >= 0; qps -= step {
		targets = sendQueries(targets, names, qps, clients)
		time.Sleep(time.Second)
	}
}

func sendQueries(targets, names []string, qps int, clients []*dns.Client) []string {
	qtype, err := parseQType(trafficQType)
	if err != nil {
		log.Fatal(err)
	}
	randomType := strings.EqualFold(strings.TrimSpace(trafficQType), "random")
	log.Printf("Sending %d qps to each of %d targets: %v", qps, len(targets), targets)
	for _, target := range targets {
		for _, name := range names {
			go func(target, name string) {
				for i := 0; i < qps; i++ {
					m := new(dns.Msg)
					qt := qtype
					if randomType {
						qt = pickQType()
					}
					m.SetQuestion(dns.Fqdn(name), qt)
					client := clients[i%len(clients)]
					_, _, err := client.Exchange(m, target)
					if err != nil {
						log.Printf("Error querying %s: %v", target, err)
						if strings.Contains(err.Error(), "no route to host") {
							log.Printf("No route to host, removing target %s from list", target)
							targets = slices.Delete(targets, slices.Index(targets, target), slices.Index(targets, target)+1)
							log.Printf("New target list: %v", targets)
						}
					}
				}
			}(target, name)
		}
	}
	// remove any targets that are no longer reachable
	return targets
}

var currentnum int

func CurrentDGA(dgaalg, seed, basename string) string {
	var name string
	switch dgaalg {
	case "md5+time":
		currenttime := time.Now().Format("2006-01-02 15:04:05")
		input := seed + currenttime
		md5hash := md5.Sum([]byte(input))

		for i := 0; i < 16; i++ {
			name += string('a' + md5hash[i]%26)
		}
	case "linear":
		currentnum++
		name = fmt.Sprintf("x%07d", currentnum) // Starting with 1, you can increment this number as needed
	default:
		log.Fatalf("Unknown DGA algorithm: %s", dgaalg)
	}
	return name + "." + basename
}

func sendDGAQueries(targets []string, name string, clients []*dns.Client) {
	for _, target := range targets {
		fmt.Printf("Querying %s for %s\n", target, name)
		//		m := new(dns.Msg)
		//		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		//		_, _, err := client.Exchange(m, target)
		//		if err != nil {
		//			log.Printf("Error querying %s: %v", target, err)
		//		}
	}
}

func ParseDGA(dgaalg string) (string, error) {
	switch alg := strings.ToLower(dgaalg); alg {
	case "linear", "md5+time":
		return alg, nil
	default:
		return "", fmt.Errorf("unknown DGA algorithm: %s (must be md5+time or linear)", dgaalg)
	}
}
