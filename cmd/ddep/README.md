# tdns-ddep — DNS Dependency Analyzer

tdns-ddep is an instrumented recursive resolver for discovering and analyzing
external DNS dependencies of a service (web page, API endpoint, etc.).

It is a derivative of tdns-imr that registers hooks into the IMR resolver
to observe and selectively block DNS queries. All standard IMR functionality
(caching, DNSSEC validation, transport upgrade, etc.) is available.

## Use Case

"Can this service function if all DNS infrastructure outside Sweden is
unreachable?"

To answer questions like this, tdns-ddep lets you:

1. Flush the resolver cache (clean slate)
2. Point a browser (or any client) at the resolver
3. Load a web page and record every DNS query — both the client queries
   from the browser and the iterative sub-queries to authoritative servers
4. Selectively block queries using RPZ-like rules
5. Flush and retry to see what breaks

The iterative sub-queries are important: if `company.se` has all its
nameservers hosted outside `.se`, there is an external dependency even
though the client query itself is for a `.se` name.

## Quick Start

```sh
# Generate a TLS certificate (needed for DoH)
cd tdns/utils && ./gen-cert.sh

# Start the resolver
tdns-ddep --config /path/to/tdns-ddep.yaml --cli

# In the interactive shell:
tdns-ddep> session start
# Load a web page in a browser pointed at this resolver
tdns-ddep> list queries --unique
# Add blocks
tdns-ddep> block nxdomain tracker.example.com
# Flush cache + restart session in one command
tdns-ddep> session flush
# Reload the web page, see what breaks
tdns-ddep> list queries --unique
```

## CLI Commands

### Session Management

| Command | Description |
|---------|-------------|
| `session start` | Begin recording queries. Clears any previous log. |
| `session stop` | Stop recording. Queries are still visible via `show`. |
| `session show [--unique]` | Display recorded queries, sorted by reverse domain name. `--unique` deduplicates by (qname, qtype, category). |
| `session clear` | Wipe the query log without affecting cache or session state. |
| `session flush` | Flush the entire resolver cache (except root priming data), clear the query log, and start a fresh session. This is the "clean slate" command for re-testing. |

### Block Rules

Block rules are RPZ-like filters evaluated in first-match-wins order.
They are persistent (saved to a JSON file after every change) and survive
restarts.

| Command | Description |
|---------|-------------|
| `block <action> <qname> [qtype]` | Add a block rule. If qtype is omitted, all query types are blocked. Wildcard patterns (`*.example.com`) are supported. |
| `unblock <qname> [qtype]` | Remove a block rule matching the pattern (and optionally qtype). |
| `list blocks` | Show all active block rules. |
| `clearblocks` | Remove all block rules. |

#### Block Actions

| Action | Effect |
|--------|--------|
| `nxdomain` | Synthesize an NXDOMAIN response. |
| `nodata` | Synthesize a NODATA response (NOERROR, empty answer). |
| `drop` | Silently drop the query (client times out). |
| `redirect` | Redirect to a specified IP address (use `--redirect-to`). |
| `allow` | Whitelist — override any other matching block rule (RPZ PASSTHRU). |

#### Examples

```
block nxdomain tracker.example.com
block nodata ads.example.com A
block drop *.badsite.com
block redirect evil.com --redirect-to 127.0.0.1
block allow safe.example.com
unblock tracker.example.com
```

### Query Listing

| Command | Description |
|---------|-------------|
| `list queries [--unique]` | Same as `session show`. |
| `list blocks` | Same as above. |

### Standard IMR Commands

All standard tdns-imr commands are available:

| Command | Description |
|---------|-------------|
| `query <name> <type>` | Resolve a DNS query through the IMR. |
| `dump` | List records in the RRset cache. |
| `stats` | Show resolver statistics. |
| `show` | Show IMR state. |
| `flush <subcommand>` | Flush cached data (per-domain). For full cache flush, use `session flush` instead. |
| `set` | Set IMR runtime parameters. |
| `zone` | Zone operations. |

## Configuration

tdns-ddep uses the same configuration format as tdns-imr. See
`tdns-ddep.sample.yaml` for a commented example.

Key configuration:

```yaml
imrengine:
  addresses: [ 127.0.0.1:53 ]
  transports: [ do53, doh ]      # DoH requires cert/key below
  certfile: /path/to/cert.crt
  keyfile: /path/to/cert.key

ddep:
  blockrules_file: /etc/tdns/ddep-block-rules.json
```

### DoH Setup

To use a browser as the DNS client (recommended for analyzing web page
dependencies):

1. Generate a certificate with a SAN for 127.0.0.1:
   ```
   ./gen-cert.sh   # enter IP: 127.0.0.1
   ```
2. Trust it on macOS:
   ```
   sudo security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain cert.crt
   ```
3. In Firefox: `about:config` -> `security.enterprise_roots.enabled` = `true`
4. Configure DoH in browser settings:
   ```
   https://127.0.0.1/dns-query
   ```
5. Run tdns-ddep as root (port 443) or configure a non-standard port
   via `dnsengine.ports.doh`.

## Architecture

tdns-ddep registers three hooks into the IMR resolver via the pluggable
hook API (`RegisterImrClientQueryHook`, `RegisterImrOutboundQueryHook`,
`RegisterImrResponseHook`). These hooks:

- **Client query hook**: Logs incoming client queries, enriches the
  context with a parent query ID for linking, and evaluates block rules.
- **Outbound query hook**: Logs iterative sub-queries (linked to their
  parent client query via context), and evaluates block rules against
  the qname being resolved.
- **Response hook**: Observe-only (available for future enhancements).

When no session is active and no block rules are configured, the hooks
are effectively no-ops — the resolver behaves identically to tdns-imr.
