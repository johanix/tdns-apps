# tdns-traffic — DNS Traffic Generator

A DNS query load generator with configurable QPS shapes, designed
for testing nameserver performance under various traffic patterns.

## Build

```
cd cmd/traffic && make
```

Produces the `tdns-traffic` binary (statically linked, CGO disabled), or build
the whole repo's packaged apps with `make -C cmd pkg`.

## Structure

`cmd/traffic/main.go` is the entire app: it wires up cobra and nothing else.
Everything it does lives in `lib/traffic`, which is where a second consumer
would reach it -- the reason the code is a library rather than a `package main`
is that `tdns-zonegen` generates the zones this is pointed at, and the two are
meant to be usable together.

The library hands its commands back rather than attaching them to a parent it
owns, so the app decides its own hierarchy: `tdns-traffic run`, not
`tdns-traffic traffic run` as the standalone tool used to require.

## Quick Start

```
# Simple run (foreground, trapezoid shape):
tdns-traffic run --shape trapezoid --max 5000 --cycle 2m \
   -t 10.0.0.1 --qname example.com

# With a qname file and random prefixes:
tdns-traffic run --shape arch --max 3000 --cycle 90s \
   -t ns1.example.com --qname-file names.txt --random-prefix

# As a background server (requires --maxtime):
tdns-traffic run --server --maxtime 1h --shape sine \
   --max 2000 -t 10.0.0.1 --qname example.com \
   --logfile /tmp/traffic.log
```

## Commands

### `run`

The main command. Sends DNS A queries to one or more target
nameservers, varying the QPS over time according to the selected
shape.

| Flag | Description |
|------|-------------|
| `--shape NAME` | QPS shape (default: `trapezoid`) |
| `--peaks N` | Number of peaks per cycle (for `peaks` shape, default: 3) |
| `-m, --max N` | Maximum queries per second (default: 1000) |
| `--cycle DUR` | Duration of one cycle (default: 2m) |
| `-t, --targets` | Target nameserver IPs or hostnames (repeatable) |
| `--qname NAME` | Single domain name to query |
| `--qname-file FILE` | File with base qnames, one per line |
| `--random-prefix` | Prepend a random 8-char label to each qname |
| `--server` | Fork to background (requires `--maxtime`) |
| `--maxtime DUR` | Maximum run time (required with `--server`) |
| `--logfile FILE` | Log to file instead of stderr |

If a server instance is already running, `traffic run` with new
parameters reconfigures the running server instead of starting a
second instance.

### `traffic stop`

Tells a running server to shut down gracefully.

### `traffic extend <duration>`

Adds time to a running server's remaining time limit.

```
tdns-traffic traffic extend 45m
```

### `traffic status`

Checks whether a server instance is running.

### `traffic rampup` (legacy)

The original sawtooth command with explicit `--rampup`, `--sustain`,
and `--rampdown` phase durations. Still works, but `traffic run`
with `--shape` is preferred.

### `traffic dga`

Domain Generation Algorithm mode. Generates query names
algorithmically using MD5+time or linear numbering.

| Flag | Description |
|------|-------------|
| `-S, --seed` | Seed string (min 16 chars for md5+time) |
| `-A, --alg` | Algorithm: `md5+time` or `linear` |
| `-B, --basename` | Base domain for generated names |

## QPS Shapes

Shapes define how QPS varies over each cycle. The time `t` goes
from 0 (cycle start) to 1 (cycle end), and the shape function
returns a fraction of `--max` QPS.

| Shape | Description |
|-------|-------------|
| `sawtooth-up` | Linear rise, vertical drop |
| `sawtooth-down` | Vertical rise, linear drop |
| `triangle` | Linear rise then linear drop (symmetric) |
| `trapezoid` | Rise, sustain at max, drop (default) |
| `bowl` | Parabolic: high at edges, low in middle |
| `arch` | Parabolic: low at edges, high in middle |
| `sine` | Smooth sine wave (one full cycle) |
| `peaks` | Repeated parabolic peaks (use `--peaks N`) |

## Qname File Format

A plain text file with one domain name per line. Blank lines and
lines starting with `#` are ignored.

```
# Production zones
example.com
example.net

# Test zones
test.example.org
```

## Server Mode and Control

When started with `--server`, the process forks to the background
and listens on a unix socket (`/tmp/tdns-traffic.sock`) for control
commands. The `--maxtime` flag is mandatory to prevent forgotten
runaway processes.

The control socket enables:
- **Reconfiguration**: running `traffic run` again sends the new
  parameters to the existing server
- **Extension**: `traffic extend 30m` adds time
- **Shutdown**: `traffic stop` or SIGINT/SIGTERM
- **Status**: `traffic status` checks if a server is running

## Configuration File

Optional YAML config at `~/.traffic-cli.yaml`:

```yaml
traffic:
   names:
      - example.com
      - example.net
```

Names from the config file are used when neither `--qname` nor
`--qname-file` is specified.

## License

2-clause BSD. See [LICENSE](LICENSE).
