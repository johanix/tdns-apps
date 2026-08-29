package traffic

import (
	"bufio"
	crand "crypto/rand"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	shapeName       string
	peakCount       int
	qnameFile       string
	randomPrefixPct int
	serverMode      bool
	logFile         string
	maxTime         time.Duration
)

var RunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run DNS traffic with a configurable QPS shape",
	Long: `Send DNS queries using a QPS shape that varies over each cycle.

If a server instance is already running, the new parameters are sent
to it (reconfiguring the running server) instead of starting a second
instance.

Available shapes:
` + ListShapes(),
	Run: runTraffic,
}

var StopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running traffic server",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := SendCommand(ControlCommand{Action: "stop"})
		if err != nil {
			log.Fatalf("Cannot reach server: %v", err)
		}
		fmt.Println(resp.Message)
	},
}

var ExtendCmd = &cobra.Command{
	Use:   "extend <duration>",
	Short: "Extend the running server's remaining time",
	Long:  `Add time to the running server, e.g. "traffic-cli traffic extend 45m"`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		d, err := time.ParseDuration(args[0])
		if err != nil {
			log.Fatalf("Invalid duration %q: %v", args[0], err)
		}
		if d <= 0 {
			log.Fatal("Duration must be positive")
		}
		resp, err := SendCommand(ControlCommand{
			Action:   "extend",
			ExtendBy: Duration(d),
		})
		if err != nil {
			log.Fatalf("Cannot reach server: %v", err)
		}
		fmt.Println(resp.Message)
	},
}

var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check if a traffic server is running",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := SendCommand(ControlCommand{Action: "status"})
		if err != nil {
			fmt.Println("No server running.")
			return
		}
		fmt.Println(resp.Message)
	},
}

func runTraffic(cmd *cobra.Command, args []string) {
	if len(targetList) == 0 {
		log.Fatal("No targets specified")
	}

	// Enforce --maxtime for server mode.
	if serverMode && maxTime <= 0 {
		log.Fatal("--maxtime is required when using --server (to prevent forgotten runaway processes)")
	}

	// Resolve the shape function early (before checking for server).
	shapeFn := resolveShape()

	// Load qnames early so we can send them to a running server.
	names := loadNames()
	if len(names) == 0 {
		log.Fatal("No qnames specified (use --qname, --qname-file, or config)")
	}

	// If a server is already running, send new config to it.
	if ServerRunning() {
		fmt.Println("Server already running — sending new configuration.")
		resp, err := SendCommand(ControlCommand{
			Action:          "run",
			Shape:           shapeName,
			Peaks:           peakCount,
			MaxQPS:          maxQPS,
			Cycle:           Duration(cycleDuration),
			Targets:         targetList,
			Names:           names,
			RandomPrefixPct: randomPrefixPct,
			Transport:       trafficTransport,
		})
		if err != nil {
			log.Fatalf("Failed to reconfigure server: %v", err)
		}
		fmt.Println(resp.Message)
		return
	}

	// Set up logging to file if requested.
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Cannot open log file %s: %v", logFile, err)
		}
		log.SetOutput(f)
	}

	// Server mode: fork to background.
	if serverMode {
		daemonize()
	}

	targets := resolveTargets(targetList, names)
	if len(targets) == 0 {
		log.Fatal("No reachable targets")
	}

	clients := makeClients(trafficTransport)

	log.Printf("Starting traffic: shape=%s maxQPS=%d cycle=%v targets=%d qnames=%d randomPrefix=%d%% transport=%s",
		shapeName, maxQPS, cycleDuration, len(targets), len(names), randomPrefixPct, trafficTransport)
	if maxTime > 0 {
		log.Printf("Maximum run time: %v", maxTime)
	}

	// Control channels.
	stopCh := make(chan struct{})
	extendCh := make(chan time.Duration, 1)
	reconfigCh := make(chan ControlCommand, 1)

	// Start the control socket listener.
	cs, err := newControlServer(stopCh, extendCh, reconfigCh)
	if err != nil {
		log.Printf("Warning: cannot start control socket: %v", err)
	} else {
		go cs.serve()
		defer cs.close()
		log.Printf("Control socket: %s", SocketPath)
	}

	// OS signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Max time deadline.
	var deadline <-chan time.Time
	if maxTime > 0 {
		deadline = time.After(maxTime)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	cycleStart := time.Now()

	for {
		select {
		case <-sigCh:
			log.Println("Signal received, shutting down.")
			return

		case <-stopCh:
			log.Println("Stop command received, shutting down.")
			return

		case <-deadline:
			log.Printf("Maximum run time (%v) reached, shutting down.", maxTime)
			return

		case d := <-extendCh:
			maxTime += d
			deadline = time.After(maxTime - time.Since(cycleStart))
			log.Printf("Extended by %v, new max time: %v", d, maxTime)

		case newCfg := <-reconfigCh:
			log.Printf("Reconfiguring: shape=%s maxQPS=%d transport=%s", newCfg.Shape, newCfg.MaxQPS, newCfg.Transport)
			shapeName = newCfg.Shape
			peakCount = newCfg.Peaks
			maxQPS = newCfg.MaxQPS
			cycleDuration = time.Duration(newCfg.Cycle)
			randomPrefixPct = newCfg.RandomPrefixPct
			names = newCfg.Names
			shapeFn = resolveShape()
			if newCfg.Transport != "" {
				trafficTransport = newCfg.Transport
				clients = makeClients(trafficTransport)
			}
			if len(newCfg.Targets) > 0 {
				targets = resolveTargets(newCfg.Targets, names)
			}
			cycleStart = time.Now()

		case now := <-ticker.C:
			elapsed := now.Sub(cycleStart)
			if elapsed >= cycleDuration {
				cycleStart = now
				elapsed = 0
			}
			t := elapsed.Seconds() / cycleDuration.Seconds()
			qps := int(shapeFn(t) * float64(maxQPS))
			if qps < 0 {
				qps = 0
			}

			queryNames := names
			if randomPrefixPct > 0 {
				queryNames = addRandomPrefixes(names, randomPrefixPct)
			}
			targets = sendQueries(targets, queryNames, qps, clients)
		}
	}
}

// resolveShape returns the ShapeFunc for the current shapeName/peakCount.
func resolveShape() ShapeFunc {
	if strings.ToLower(shapeName) == "peaks" {
		return PeaksShape(peakCount)
	}
	fn, err := GetShape(shapeName)
	if err != nil {
		log.Fatal(err)
	}
	return fn
}

// loadNames returns qnames from --qname-file, --qname flag, or config.
func loadNames() []string {
	if qnameFile != "" {
		return loadQnameFile(qnameFile)
	}
	return getNames()
}

// loadQnameFile reads a text file with one qname per line.
// Blank lines and lines starting with # are skipped.
func loadQnameFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Cannot open qname file %s: %v", path, err)
	}
	defer f.Close()

	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := dns.IsDomainName(line); !ok {
			log.Printf("Skipping invalid domain name: %s", line)
			continue
		}
		names = append(names, dns.Fqdn(line))
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading qname file: %v", err)
	}
	log.Printf("Loaded %d qnames from %s", len(names), path)
	return names
}

// addRandomPrefixes prepends a random 8-char label to pct% of the qnames.
func addRandomPrefixes(names []string, pct int) []string {
	out := make([]string, len(names))
	for i, name := range names {
		if rand.Intn(100) < pct {
			out[i] = randomLabel(8) + "." + name
		} else {
			out[i] = name
		}
	}
	return out
}

const labelChars = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomLabel(n int) string {
	b := make([]byte, n)
	for i := range b {
		idx, _ := crand.Int(crand.Reader, big.NewInt(int64(len(labelChars))))
		b[i] = labelChars[idx.Int64()]
	}
	return string(b)
}

// daemonize forks a child process and exits the parent.
func daemonize() {
	// Re-exec ourselves with --server stripped out.
	args := make([]string, 0, len(os.Args))
	for _, arg := range os.Args {
		if arg == "--server" {
			continue
		}
		args = append(args, arg)
	}

	attr := &os.ProcAttr{
		Dir: ".",
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			os.Stdout,
			os.Stderr,
		},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	}

	proc, err := os.StartProcess(args[0], args, attr)
	if err != nil {
		log.Fatalf("Failed to daemonize: %v", err)
	}

	fmt.Printf("Traffic generator running in background, PID %d\n", proc.Pid)
	if logFile != "" {
		fmt.Printf("Logging to %s\n", logFile)
	}
	proc.Release()
	os.Exit(0)
}
