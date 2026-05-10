# tdns-scanner Implementation Plan

**Date:** 2026-05-10
**Author:** Johan Stenstam
**Companion to:** `2026-05-10-tdns-scanner-extraction.md` (design doc)
**Issues:** labstuff#385

---

## Executive Summary

Far less greenfield work than expected. The tdns scanner library (`tdns/v2/scanner.go`, 1319 lines), the per-app config/init framework (`SetupSimpleAPIRouter`, `MainInit`, `MainLoop`), and a working `APIscanner` HTTP handler with job-tracking + status + delete already exist. The `tdns-apps/cmd/scanner/main.go` binary builds and runs — it just doesn't expose the scanner endpoints (it uses the *simple* router, which omits the scanner-specific routes).

The implementation work is roughly:

1. Wire the existing scanner endpoints into `tdns-apps/cmd/scanner` (small)
2. Reshape the API from `POST /scanner` (single endpoint with discriminator) to per-RRtype endpoints `/scan/cds`, `/scan/csync`, `/scan/dnskey` per the design doc (medium — refactor, then add CSYNC's two-phase response shape)
3. Build `tdns-scanner-cli` for ad-hoc scan submission and ops queries (medium — new binary, but uses existing patterns from `tdns-cliv2` etc.)
4. Migrate labstuff statusd from embedded scanners to API client (medium-large — three sites: CDS, CSYNC, DNSKEY; statusd retains all persistence, just outsources the scan)
5. Retire labstuff/lib/scanner*.go once migration verified (small — delete + wire up removal)

Estimated total effort: 3-5 working days for steps 1-3, then 2-4 days for step 4, then trivial for step 5. Total order of magnitude: **~2 weeks of focused work**.

Implementation deferred to post-Intro / Advanced course refresh per #385.

---

## Decisions Locked In (from chat)

These were open in the design doc; pinned down before drafting this plan:

| Decision | Choice |
|---|---|
| Push or pull? | **Pull-only for v1.** Caller asks, scanner answers. No background ticker, no webhooks. Statusd's existing ticker becomes "loop over zones, call API". Push deferred to v2. |
| One service or per-network-segment? | **Single instance** on master VM. Reuses existing IMR/recursive plumbing. Per-segment scanners reconsidered if a real need surfaces. |
| Persistence (status tables) | **Stays in statusd's LabDB.** Scanner is stateless about per-zone history. Statusd does diff/persistence. Scanner's only state is in-flight jobs. |
| Existing tdns-scanner code? | **`tdns-apps/cmd/scanner/main.go` is a working shell.** Not yet a complete app. No conflict — we're building it out, not creating from scratch. |

---

## Code Boundary: tdns vs tdns-apps (Model 1)

**Critical context:** the scanner is *already used in-process* by tdns-auth and tdns-agent. When those daemons receive a NOTIFY for CDS/CSYNC/DNSKEY, they dispatch to `conf.Internal.ScannerQ` directly — same process, in-memory channel. See `tdns/v2/notifyresponder.go:91`, `tdns/v2/main_initfuncs.go:202`. This is not a deployment of tdns-scanner as a service; it's library use.

So building tdns-scanner as a standalone HTTP service raises a real question: do tdns-auth/tdns-agent get rewired to call the external service, or do they keep their in-process channel?

**Three models considered:**

1. **Library, used both in-process and as a service.** `tdns/v2/scanner.go` stays as a library. tdns-auth/tdns-agent keep `conf.Internal.ScannerQ`. tdns-scanner is one *additional* consumer that wraps the library with HTTP. No rewiring of auth/agent.
2. **Service-only.** Scanner library disappears as an in-process API. Every tdns-auth/tdns-agent embeds an HTTP client, talks to a tdns-scanner service. One implementation, one wire format. But: every deployment now needs a separate tdns-scanner; HTTP overhead in the hot NOTIFY path; new failure mode (scanner unreachable → NOTIFY processing breaks); much bigger migration.
3. **Hybrid.** Library with optional service mode, configurable per deployment.

**Decision: Model 1.** Reasons:

- The principle "tdns is the library + built-in daemons; tdns-apps wraps for standalone use" maps cleanly to Model 1.
- The brittleness problem is in *labstuff*, not in tdns-auth/tdns-agent — those are working fine. No problem statement justifies forcing them to depend on an external service.
- Model 2 is a much bigger change that we can defer until there's a specific reason (e.g. resource isolation needs, horizontal scanner scaling).
- The "two code paths" downside of Model 1 is largely illusory — the channel-based path *uses the library*, the HTTP path *wraps* the library. The library is the single implementation; the HTTP layer is thin.

### Code locations after this work

| Component | Lives in | Notes |
|---|---|---|
| `Scanner` struct, `CheckCDS`/`CheckCSYNC`/`CheckDNSKEY` | `tdns/v2/scanner.go`, `tdns/v2/scanner_csync.go` | Existing library, unchanged in shape. Used by both in-process and HTTP-wrapped consumers. |
| `ScanRequest`/`ScanResponse`/`ScanJobStatus` (in-process channel types) | `tdns/v2/scanner.go` | Existing types, unchanged. Used by tdns-auth/tdns-agent in-process. |
| Per-RRtype HTTP request/response types (`ScanCDSRequest`, `ScanCDSResponse`, `ScanCSYNCResponse`, `ScanDNSKEYRequest`, ...) | `tdns/v2/scanner_api.go` (new) | Wire types — must be importable by external clients (labstuff). |
| Per-RRtype HTTP handlers (`APIscanCDS`, `APIscanCSYNC`, `APIscanDNSKEY`) | `tdns/v2/apihandler_funcs.go` | Translate HTTP request → in-process `ScanRequest`, await `ScanResponse`, translate back to HTTP response type. |
| `APIscannerStatus`, `APIscannerDelete` (jobs introspection) | `tdns/v2/apihandler_funcs.go` | Existing, unchanged. Possibly aliased under `/scan/jobs` path per the new API surface. |
| Failure taxonomy (`ErrNSUnreachable`, `ErrTimeout`, ...) | `tdns/v2/scanner_errors.go` (new) | Used in both channel-based `ScanResponse.ErrorCode` and HTTP `ScanCDSResponse.ErrorCode`. |
| `SetupAPIRouter` scanner-conditional block | `tdns/v2/apirouters.go` | Adds the new per-RRtype routes when `Globals.App.Type == AppTypeScanner`. |
| `tdns-scanner` daemon binary (main, version, Makefile, sample config) | `tdns-apps/cmd/scanner/` | Existing shell — fleshed out to use `SetupAPIRouter` (full) instead of `SetupSimpleAPIRouter`. |
| `tdns-scanner-cli` binary | `tdns-apps/cmd/scanner-cli/` (new) | Mirrors `tdns-cliv2` patterns. Subcommands for ping/status, jobs CRUD, ad-hoc scans. |
| labstuff scanner client (`scanner_client.go`) | `labstuff/lib/` | The labstuff side. Imports the wire types from tdns/v2; HTTP-talks to tdns-scanner. |
| labstuff per-zone state (`DnskeyStatus`, `Pending*`, `Current*`, `CdsStatus` tables) | `labstuff/lib/` (LabDB) | **Stays in labstuff.** No move. |

### Scope of change to tdns-auth and tdns-agent: NONE for v1.

They keep using `conf.Internal.ScannerQ` in-process via the channel pattern. The `Scanner` struct, the channel types, and the `CheckCDS`/`CheckCSYNC`/`CheckDNSKEY` methods are all preserved exactly as they are today. The new HTTP handlers are *additional* consumers of the same library.

If a future need surfaces (e.g. "tdns-agent should use a centralized scanner pool to deduplicate scans across many agents"), Model 3 (hybrid library-or-service) becomes the natural next step. Not for this work.

---

## Pass 1: What's Already In Place

### tdns scanner library — `tdns/v2/scanner.go` (1319 lines)

- `type Scanner struct{ AuthQueryQ, ImrEngine, OnDelegationChange, Jobs, JobsMutex, ... }` — encapsulated, dependency-injected
- `type ScanRequest struct{ Cmd, ParentZone, ScanZones, ScanType, ScanTuples, ChildZone, CurrentChildData, RRtype, Edns0Options, Response, JobID }`
- `type ScanResponse struct{ Time, Zone, RRtype, RRset, Msg, Error, ErrorMsg }`
- `type ScanJobStatus` — async job tracking
- `func GenerateJobID() (string, error)` — crypto/rand-based
- `CheckCDS`, `CheckCSYNC`, `CheckDNSKEY` — implementations with `context.Context`, EDNS0 options, response channel
- `ProcessCDSNotify`, `ProcessCSYNCNotify` — NOTIFY-driven variants (v2 luxury, not needed for pull-only v1 but already present)

### tdns-apps scanner binary — `tdns-apps/cmd/scanner/main.go` (60 lines)

```go
tdns.Globals.App.Type = tdns.AppTypeScanner    // already typed
tdns.Globals.App.Version = appVersion
conf.MainInit(ctx, "")                         // standard tdns init
conf.SetupSimpleAPIRouter(ctx)                 // ⚠️ "Simple" — omits scanner endpoints
conf.StartScanner(ctx, apirouter)              // already exists
conf.MainLoop(ctx, stop)                       // standard event loop
```

Sample config `tdns-scanner.sample.yaml` is mostly complete (apiserver address, apikey, certs, log file, db file).

### Existing API handlers — `tdns/v2/apihandler_funcs.go`

- `APIscanner` (line 495) — accepts `ScannerPost{Command, ParentZone, ScanZones, ScanType, ScanTuples}`, generates JobID, queues to `scannerq`, returns `{Status: "queued", JobID, Msg}`. Currently a single discriminated endpoint, but the dispatching logic is small — easy to refactor into per-RRtype endpoints.
- `APIscannerStatus` (line 708) — GET with optional `?job_id=X`. Returns single job or all jobs from `Scanner.Jobs` map. Includes deep-copy to avoid race conditions during JSON encoding.
- `APIscannerDelete` (line 750) — DELETE with `?job_id=X` or `?all=true`. Includes proper "either-or" validation.

### Mgmt API — `SetupSimpleAPIRouter` and `SetupAPIRouter`

Per `tdns/v2/apirouters.go`:
- `SetupSimpleAPIRouter` provides `/ping`, `/command`, `/config`, `/debug` — used by tdns-imr, current tdns-scanner (in tdns-apps), tdns-reporter
- `SetupAPIRouter` (full version) is conditional on `Globals.App.Type`. For `AppTypeScanner` it adds `/scanner` (POST), `/scanner/status` (GET), `/scanner/delete` (DELETE) — but tdns-apps/cmd/scanner uses the *simple* one, so the scanner endpoints don't actually get exposed today.

All routes are X-API-Key authenticated under `/api/v1` subrouter.

### What's Missing

1. **Per-RRtype endpoints** (`/scan/cds`, `/scan/csync`, `/scan/dnskey`) — current single `/scanner` handles all types via discriminator
2. **CSYNC response shape** — per design doc, CSYNC returns resolved NS+glue, structurally different from CDS/DNSKEY
3. **Stateless mode** — caller-supplied current data + diff returned. Current API queues a scan and returns later results via `/scanner/status`; caller polls. For stateless v1 we want a synchronous-ish "scan-and-return-delta" with the option to fall back to the async pattern if the scan takes long.
4. **`tdns-scanner-cli` binary** — for ops queries and ad-hoc scan submission. Will mirror the `tdns-cliv2` pattern.
5. **Failure taxonomy** — error responses currently return `{Error: true, ErrorMsg: "..."}`. Per design doc we want enumerated codes (`NS_UNREACHABLE`, `TIMEOUT`, `BOGUS_SIGNATURE`, `SOA_UNSTABLE`, `NXDOMAIN_AT_CHILD`, etc.).
6. **Statusd migration** — labstuff/lib/scanner*.go needs to be replaced with API client calls.

---

## Pass 2: Implementation Steps

### Step 1: Switch tdns-scanner to the full API router

**Effort: 1-2 hours.** Currently uses `SetupSimpleAPIRouter`, missing scanner endpoints.

**Files:**
- `tdns-apps/cmd/scanner/main.go:33` — change to `SetupAPIRouter` (the conditional-on-AppType one which already wires `/scanner`, `/scanner/status`, `/scanner/delete` for AppTypeScanner)

**Verification:**
- Build, run, `curl -X POST -H 'X-API-Key: …' http://localhost:8082/api/v1/scanner -d '{"command":"status"}'` → should return scanner status
- `curl 'http://localhost:8082/api/v1/scanner/status'` → returns empty job list (no scans yet)

### Step 2: Per-RRtype endpoint refactor

**Effort: 1 day.** Add per-RRtype HTTP endpoints `/scan/cds`, `/scan/csync`, `/scan/dnskey`. Keep the existing in-process `ScanRequest`/`ScanResponse` channel types unchanged — they're used by tdns-auth/tdns-agent (see "Code Boundary" section) and continuing to share them with the HTTP path means one set of scan semantics, not two.

**Files:**
- `tdns/v2/scanner_api.go` (new) — HTTP-side per-RRtype request/response types (see below)
- `tdns/v2/apihandler_funcs.go` — add `APIscanCDS`, `APIscanCSYNC`, `APIscanDNSKEY` handlers next to the existing `APIscanner`. Each handler decodes the new per-RRtype HTTP type, builds an in-process `ScanRequest`, sends it on `scannerq`, awaits `ScanResponse` (with timeout), translates back to the per-RRtype HTTP response type. The existing `APIscanner` is retained — it's still the entry point used by tdns-auth/tdns-agent's NOTIFY-driven dispatch via `conf.Internal.ScannerQ`.
- `tdns/v2/apirouters.go:86` — register the three new routes alongside the existing `/scanner`. Project's "no backwards compat" rule applies: once labstuff has migrated to the new per-RRtype endpoints, the legacy `/scanner` discriminator-style endpoint can be removed.

**New per-type HTTP request/response types** (in `tdns/v2/scanner_api.go`):

```go
type ScanCDSRequest struct {
    Zone           string         `json:"zone"`               // "example.com."
    CurrentDS      []string       `json:"current_ds"`         // current parent-side DS (string form for transport)
    Edns0Options   *MsgOptions    `json:"edns0_options,omitempty"`
}

type ScanCDSResponse struct {
    Status         ScanStatus     `json:"status"`             // "unchanged"|"changed"|"error"
    NewDS          []string       `json:"new_ds,omitempty"`   // present if Status=="changed"
    Validated      string         `json:"validated"`          // "signed"|"insecure"|"bogus"
    ErrorCode      string         `json:"error_code,omitempty"` // taxonomy
    ErrorMsg       string         `json:"error_msg,omitempty"`
    JobID          string         `json:"job_id,omitempty"`   // if async
    Time           time.Time      `json:"time"`
}

// CSYNC has its own shape because it returns resolved NS+glue, not just an RRset
type ScanCSYNCResponse struct {
    Status         ScanStatus     `json:"status"`
    NewNS          []string       `json:"new_ns,omitempty"`
    NewGlue4       map[string][]string `json:"new_glue4,omitempty"` // hostname -> A
    NewGlue6       map[string][]string `json:"new_glue6,omitempty"` // hostname -> AAAA
    Validated      string         `json:"validated"`
    SOAStable      bool           `json:"soa_stable"`         // RFC 7477 stability check
    ErrorCode      string         `json:"error_code,omitempty"`
    ErrorMsg       string         `json:"error_msg,omitempty"`
    JobID          string         `json:"job_id,omitempty"`
    Time           time.Time      `json:"time"`
}
```

**Sync-or-async dispatch:**
- Each handler tries to complete inline (fast path: queue scan, wait on response channel with short timeout, e.g. 10s)
- If timeout fires: return `{Status: "queued", JobID: "..."}` — caller polls `/scan/status?job_id=...`
- This gives stateless callers a clean sync path for fast scans without forcing them into the async pattern

### Step 3: Failure taxonomy

**Effort: 0.5 day.** Add enumerated error codes.

**Files:**
- `tdns/v2/scanner_errors.go` (new) — error code constants + helper `ClassifyScanError(err) string`

```go
const (
    ErrNSUnreachable    = "NS_UNREACHABLE"
    ErrTimeout          = "TIMEOUT"
    ErrNXDOMAIN         = "NXDOMAIN_AT_CHILD"
    ErrLameDelegation   = "LAME_DELEGATION"
    ErrBogusSignature   = "BOGUS_SIGNATURE"
    ErrSOAUnstable      = "SOA_UNSTABLE"     // CSYNC RFC 7477
    ErrNoData           = "NODATA"            // queried RRtype not present
    ErrServfail         = "SERVFAIL"
    ErrInternal         = "INTERNAL"
)
```

Update CheckCDS/CheckCSYNC/CheckDNSKEY to populate the code, not just `ErrorMsg`.

### Step 4: tdns-scanner-cli

**Effort: 1-1.5 days.** New CLI binary, mirroring the existing `tdns-cliv2` pattern.

**New directory:** `tdns-apps/cmd/scanner-cli/` with `main.go`, `Makefile`, `version.go`, sample config

**Subcommands:**
```
tdns-scanner-cli ping                                  # mgmt: liveness
tdns-scanner-cli status                                # mgmt: scanner config + boot time
tdns-scanner-cli jobs list                             # ops: list all in-flight + recent jobs
tdns-scanner-cli jobs show <jobid>                     # ops: details for one job
tdns-scanner-cli jobs delete <jobid>                   # ops: clean up
tdns-scanner-cli jobs delete --all                     # ops: clear all
tdns-scanner-cli scan cds <zone> [--current-ds <DS>... ]      # adhoc: trigger CDS scan
tdns-scanner-cli scan csync <zone> [--current-ns <NS>... ]    # adhoc: trigger CSYNC scan
tdns-scanner-cli scan dnskey <zone> [--current-keys <KEY>... ] # adhoc: trigger DNSKEY scan
tdns-scanner-cli config show                           # mgmt: dump effective config
tdns-scanner-cli config reload                         # mgmt: SIGHUP equivalent via API
```

CLI talks to the daemon via the X-API-Key auth pattern. Reuses `apiclient.go` patterns from `tdns-cliv2`.

### Step 5: Statusd-side migration (the labstuff side)

**Effort: 2-4 days.** This is the part that crosses the labstuff/tdns boundary.

The labstuff scanner integration today:
- `lib/scanner.go` — main loop / dispatch
- `lib/scanner_cds.go` — `CheckCDS` (DB-coupled, calls `AuthRecDNSQuery`, persists to `Pending*`/`Current*` tables, may issue parent UPDATE)
- `lib/scanner_csync.go` — `CheckCSYNC`
- `lib/scanner_dnskey.go` — `CheckDNSKEY` (the brittle one; mostly commented-out; persists to `DnskeyStatus`)
- `lib/rrscanner.go` — generic RR scanner used by HTTP-driven scans

After migration:
- `lib/scanner_client.go` (new, ~300 lines) — thin client: HTTP calls to tdns-scanner via `http.Client`, marshals/unmarshals the per-RRtype request/response types, returns to the existing scanner-loop dispatch
- `lib/scanner.go` retained — the *loop* (ticker over configured zones, dispatch to scanner backend) stays. Just calls `scanner_client.go` instead of `CheckCDS`/`CheckCSYNC`/`CheckDNSKEY`
- `lib/scanner_cds.go` / `lib/scanner_csync.go` / `lib/scanner_dnskey.go` — eventually deleted (after successful migration verified). For the transition, the old code can stay behind a config flag `services.scanner.backend: "internal"|"tdns-scanner"`
- DB tables (`DnskeyStatus`, `Pending*`, `Current*`, `CdsStatus`) **stay in LabDB**. The scanner-client receives the scan result and feeds it into the existing diff/persist code that lives in `lib/`. This is the "stays in statusd" decision in action.

**Config addition** (`/etc/axfr.net/axfr-statusd.yaml`):
```yaml
services:
   scanner:
      backend:        tdns-scanner    # "internal" (legacy) or "tdns-scanner" (new)
      url:            https://scanner.dnslab:8082/api/v1
      apikey:         …
      timeout:        10s             # sync timeout; longer scans return JobID
      ca_cert:        /etc/axfr.net/certs/axfr.netCA.crt
```

**Migration order within step 5:**
1. Implement `scanner_client.go` and add the backend-switch flag, default `"internal"` (no behavior change)
2. Switch CDS to `"tdns-scanner"` first (cleanest existing labstuff implementation, easiest comparison) — verify identical results during a course
3. Switch DNSKEY (highest payoff — this is the brittle scanner)
4. Switch CSYNC (most complex due to two-phase shape)
5. Once all three verified, delete `scanner_cds.go` / `scanner_csync.go` / `scanner_dnskey.go` and rip out the backend-switch flag

### Step 6: Cleanup

**Effort: 0.5 day.** After migration is verified (full course delivered with `backend: tdns-scanner`):

- Delete labstuff `lib/scanner_cds.go`, `lib/scanner_dnskey.go`, `lib/scanner_csync.go`
- Delete the `services.scanner.backend` config knob (no fallback needed; tdns-scanner is the only path)
- Update labstuff trainer-notes if any reference the embedded scanner
- Close labstuff#385

---

## Mgmt API Surface (final shape after Step 4)

All under `/api/v1` with X-API-Key:

| Method | Path | Purpose |
|---|---|---|
| POST | `/ping` | Liveness |
| POST | `/config` | Dump or reload config |
| POST | `/debug` | Debug knobs |
| POST | `/scan/cds` | Synchronous-or-queued CDS scan |
| POST | `/scan/csync` | Synchronous-or-queued CSYNC scan |
| POST | `/scan/dnskey` | Synchronous-or-queued DNSKEY scan |
| POST | `/scan/batch` | Bulk: array of per-type requests, response is array of per-type responses keyed by index |
| GET  | `/scan/jobs` | List all jobs |
| GET  | `/scan/jobs?job_id=X` | One job's status + result |
| DELETE | `/scan/jobs?job_id=X` | Delete one job |
| DELETE | `/scan/jobs?all=true` | Clear all jobs |
| GET  | `/scanner/status` | Scanner daemon status (boot time, queue depth, recent activity) |

(Old `/scanner` endpoint deprecated. `/scanner/status` and `/scanner/delete` aliased to `/scan/jobs` for one cycle, then removed.)

---

## Risks & Open Questions

1. **DNSKEY scanner correctness**. The labstuff DNSKEY scanner is partially commented out (no validation, no change-detection). The tdns scanner has a real `CheckDNSKEY` — but is it producing the *exact same* RRsets that statusd today writes into `DnskeyStatus`? If statusd's downstream code (key bootstrap, KSK rollover automation) depends on a specific not-yet-validated form, the migration will surface bugs in *that* downstream code that have been masked by the broken scanner. **Mitigation:** during step 5, run both scanners in parallel for a course before flipping the switch; diff outputs, fix consumers as needed.

2. **DNSSEC validation policy**. Scanner returns `signed`/`insecure`/`bogus`. Statusd needs to decide what to do with `bogus` (today: probably nothing, since validation is mostly deferred). Need to confirm this doesn't change observable training-lab behavior negatively.

3. **Single-instance scaling**. Single tdns-scanner per master. Up to 26 labgroups. If each scans every minute on the fast ticker that's 26 zones × 3 RRtypes = 78 scans/minute. Should be trivial, but worth a load test before declaring done.

4. **Transport/auth between statusd and scanner**. Both run on the master VM today; they could talk via Unix socket or localhost HTTPS. Going HTTPS keeps the design portable to non-co-located deployments (which we want for sharing the scanner across multiple statusd instances eventually). Recommendation: HTTPS on `127.0.0.1:8082` for v1, X-API-Key auth.

5. **Per-zone configuration**. Today, statusd knows which zones to scan and at what cadence. The new design keeps that knowledge in statusd (statusd's ticker calls the API for each zone). tdns-scanner is "dumb" about zones — it scans whatever it's told, when it's told. Good separation.

6. **CLI for trainer use during a course**. Trainer might want `tdns-scanner-cli scan cds golf.dnslab` to manually re-trigger a CDS scan for a stuck student. The mgmt CLI design (Step 4) covers this.

---

## Effort Summary

| Step | Description | Effort |
|---|---|---|
| 1 | Switch tdns-scanner to full API router | 1-2 hours |
| 2 | Per-RRtype endpoints + sync-or-async dispatch | 1 day |
| 3 | Failure taxonomy | 0.5 day |
| 4 | tdns-scanner-cli | 1-1.5 days |
| 5 | Statusd migration (CDS, then DNSKEY, then CSYNC) | 2-4 days |
| 6 | Cleanup | 0.5 day |
| **Total** | | **~2 weeks of focused work** |

Implementation deferred to **post-Intro / Advanced course refresh** per labstuff#385. ZA Intro May 2026 ships with the existing internal scanners; ZA Advanced October 2026 should ship with tdns-scanner if migration completes during the summer.
