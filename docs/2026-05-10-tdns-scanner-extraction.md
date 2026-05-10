# tdns-scanner API Extraction: Design Document

**Date:** 2026-05-10  
**Author:** Johan Stenstam  
**Issue:** labstuff#385  
**Context:** Post-Intro/Advanced course refresh; DNSKEY scanner brittleness in ZA training

---

## Executive Summary

The labstuff `axfr-statusd` monolith houses three DNS delegation-change scanners (CDS, CSYNC, DNSKEY) that are brittle in training labs (the DNSKEY scanner has caused multiple courses to misbehave). Side-by-side review of those scanners against the existing tdns v2 scanner concludes the tdns scanner is the more mature foundation: it has dependency injection, context-based cancellation, async job dispatch, NOTIFY-driven scans, EDNS0 KeyState support, and is not coupled to any external database. The labstuff scanners are early sketches with explicit author-admitted design/implementation gaps and direct LabDB coupling. Therefore the recommended path is to **build the new `tdns-scanner` app on top of the existing tdns v2 scanner**, exposing it via per-type REST endpoints (`/scan/cds`, `/scan/csync`, `/scan/dnskey`) that return structured change-detection results (unchanged, changed with new RRset, error with taxonomy). Scanning is stateless by default (caller provides current data for comparison), with optional batch endpoints for multi-zone operations. DNSSEC validation lives in the scanner; concurrent scan limits and per-target rate limiting defer to future hardening. Authentication uses API key (X-API-Key header) to match existing tdns-apps convention. Once the API is in place and the training lab is migrated to it as a client, the labstuff scanner code can be retired entirely.

---

## Pass 1: Codebase Reconnaissance

### 1. Scanner Implementations in labstuff

Labstuff contains three independent scanner implementations plus an orchestration layer:

#### **Master Scanner Orchestrator**  
- **/Users/johani/src/git/axfr.net/labstuff/lib/scanner.go** (lines 26–294)
  - **ScannerEngine()** (line 62): time-ticker and channel-based goroutine dispatcher; manages CDS, CSYNC, DNSKEY runs; auto-stop DNSKEY scanner once all DNSKEYs collected
  - **Run()** (line 200): chooses zones (infrastructure + lab-group zones), spawns goroutines for each scanner type
  - Uses lumberjack rotating file logs per RR type
  - Supports two tiers: fast_interval (normal load) + slow_interval (idle 48h+)
  - Accepts internal ScanRequest channel for ad-hoc single-zone scans

#### **CDS Scanner**  
- **/Users/johani/src/git/axfr.net/labstuff/lib/scanner_cds.go** (lines 1–462)
  - **CheckCDS()** (line 28): query child for CDS RR; if found, compare to stored copy and parent DS
  - **AnalyzeCDS()** (line 150): fetch current DS from DB, new CDS from auth/recursive query, return delta + "changed" flag
  - **ValidateCDS()** (line 314): calls external `dnssec-cds` binary (path in viper config) with CDS+DNSKEY+RRSIG+DS, writes temporary zone files, returns validated DS RRset or error
  - **CdsRRsetKnown()** (line 206): query DB (CdsStatus table), compare to parent DS
  - **UpdateCdsStatus()** (line 259): insert/replace CDS RRs in CdsStatus table with timestamp + validated flag
  - **FetchDS()** (line 431): find parent, query parent's auth NS, fetch parent's DS for child
  - State: DB-backed (CdsStatus table); can commit pending updates immediately or defer
  - Data returned: new DS RRset (derived from validated CDS)

#### **CSYNC Scanner**  
- **/Users/johani/src/git/axfr.net/labstuff/lib/scanner_csync.go** (lines 1–435)
  - **CheckCSYNC()** (line 16): query child for CSYNC RR; extract Flags (Immediate, UseSOAMinimum) + TypeBitMap; check if known via MinSOA; three-query protocol (RFC7477): pre-SOA, CSYNC, post-SOA to detect instability
  - **CsyncAnalyzeNS()** (line 337): query zone for new NS; compare to DB's CurrentChildData
  - **CsyncAnalyzeA()** (line 222): for each in-bailiwick NS, query A; compare to DB
  - **CsyncAnalyzeAAAA()** (line 282): same for AAAA
  - **UpdateCsyncStatus()** (line 406): insert CSYNC metadata (Serial, Flags, TypeBitMap) into CsyncStatus table
  - **ZoneCSYNCKnown()** (line 387): consult in-memory KnownCsyncMinSOAs map; stores per-zone MinSOA to avoid re-scanning
  - State: DB + in-memory map (KnownCsyncMinSOAs); multi-step protocol, SOA must be stable
  - Data returned: new NS, A, AAAA RRsets (compared in each sub-analyzer)
  - Key observation: CSYNC response shape genuinely differs from CDS/DNSKEY (three RR types, two-phase sync)

#### **DNSKEY Scanner**  
- **/Users/johani/src/git/axfr.net/labstuff/lib/scanner_dnskey.go** (lines 1–181)
  - **CheckDNSKEY()** (line 15): query zone for DNSKEY with CD=true (needed before DS in place); store in DB
  - **UpdateDnskeyStatus()** (line 97): insert DNSKEYs + RRSIGs (separately) into DnskeyStatus table, skips RRSIG store (they change over time)
  - **DnskeyStatusComplete()** (line 141): check if all expected infrazones have at least one DNSKEY; return true once complete, triggers auto-stop
  - State: DB-backed (DnskeyStatus table); auto-terminating once complete
  - Data returned: DNSKEY RRset (each DNSKEY has KeyTag, Flags, Algorithm, Protocol)
  - Known issue: multiple competing implementations in codebase; brittleness in training (referenced in issue #385)

#### **CLI Scanner Commands (Thin Wrapper)**  
- **/Users/johani/src/git/axfr.net/labstuff/libcli/scanner_cmds.go**: CLI triggers for manual scans; routes to Scanner.Run() or per-zone CheckCDS/CSYNC/DNSKEY
- **/Users/johani/src/git/axfr.net/labstuff/libcli/cds_cmds.go**: CDS-specific CLI commands

#### **Infrastructure**  
- **/Users/johani/src/git/axfr.net/labstuff/lib/dnsutils.go**: Helper functions (AuthRecDNSQuery, FetchRRsFromDB, etc.)
- **/Users/johani/src/git/axfr.net/labstuff/lib/scanner.go** line 87: shared logger per RR type

**Summary:** Three independent check functions (CheckCDS, CheckCSYNC, CheckDNSKEY) tied to a shared Scanner struct with DB access, file logging, and time-based orchestration. The DNSKEY implementation is notably brittle and has caused multiple course failures.

---

### 2. Existing tdns Scanner

The tdns codebase contains a parallel, partially-implemented scanner:

#### **API Layer**  
- **/Users/johani/src/git/tdns-project/tdns/v2/apirouters.go** (line 85): `SetupAPIRouter()` registers `/api/v1/scanner`, `/api/v1/scanner/status`, `/api/v1/scanner/delete` endpoints (only if AppTypeScanner)
- **/Users/johani/src/git/tdns-project/tdns/v2/apihandler_funcs.go**: `APIscanner()`, `APIscannerStatus()`, `APIscannerDelete()` handlers; accept ScannerPost with Command="SCAN", ScanType (CDS|CSYNC|DNSKEY), ScanTuples array; return ScannerResponse with jobID + queued status; async job tracking via Scanner.Jobs map

#### **Scanner Engine**  
- **/Users/johani/src/git/tdns-project/tdns/v2/scanner.go** (lines 1-1319) — the live tdns scanner library (note: tdns/tdns/ is the frozen legacy tree; all new work lives in tdns/v2/)
  - **ScannerEngine()** (line 107): goroutine-based dispatcher; receives ScanRequest on channel; spawns goroutines for each tuple's check function
  - **CheckCDS()** (line 423): query imr (internal recursive resolver) or all authoritative NS (if "all-ns" option); compare to CurrentData.CDS; return ScanTupleResponse with DataChanged flag
  - **CheckCSYNC_NG()** (line 537): **not implemented** (returns edns0 error code EDECSyncScannerNotImplemented)
  - **CheckDNSKEY()** (line 557): **not implemented** (returns edns0 error code)
  - **Scanner struct** (line 53): holds ImrEngine (internal resolver), Jobs map for async tracking, per-type loggers
  - **ScanTuple** (inferred from usage): represents a single (zone, currentdata, options) tuple; ScanRequest groups tuples for batch processing
  - **ScanTupleResponse** (inferred): Qname, ScanType, NewData (JSON), DataChanged bool, Error bool, ErrorMsg, AllNSInSync bool

#### **Scanner Entry Point**  
- **/Users/johani/src/git/tdns-project/tdns/cmd/scanner/main.go**: calls conf.StartScanner(), sets up API router, handles SIGHUP reload
- **/Users/johani/src/git/tdns-project/tdns-apps/cmd/scanner/main.go**: wrapper in tdns-apps that calls tdns.StartScanner()

**Key Observations:**
- tdns scanner has API infrastructure (request/response structs, job tracking, async processing) but only CDS is partially implemented
- CSYNC and DNSKEY are stub methods returning "not implemented"
- No DB; uses IMR (internal recursive resolver) or direct auth queries, comparison is in-memory only
- Response struct is per-tuple (ScanTupleResponse), not per-zone, enabling bulk operations

#### **Library Reuse Assessment**  
The tdns Scanner is library-shaped for CDS (see queryAllNSAndCompare, CheckCDS); CSYNC and DNSKEY would need extraction from labstuff logic. The labstuff implementations are heavily DB-dependent (ldb.FetchRRsFromDB, UpdateCdsStatus, etc.); decoupling them requires deciding: wrap labstuff's Scanner struct directly, or reimplement the core logic (CDS validation, CSYNC multi-query protocol) from first principles with tdns patterns.

---

### 3. tdns-apps Layout & API Convention

The tdns-apps project houses companion binaries with consistent structure:

```
/Users/johani/src/git/tdns-project/tdns-apps/
├── cmd/
│   ├── scanner/        # Minimal wrapper: main.go, version.go, Makefile
│   │   └── tdns-scanner.sample.yaml
│   ├── reporter/       # Full HTTP server: main.go, setup, integration
│   │   └── defaults.go
│   ├── ddep/
│   └── whois-status/
└── docs/               # Design & spec (to be created)
```

#### **API Pattern (from reporter, scanner)**  
- **Config Initialization**: `conf.MainInit(ctx, "")` derives app name from binary name
- **Router Setup**: `conf.SetupSimpleAPIRouter(ctx)` (minimal) or `conf.SetupAPIRouter(ctx)` (full)
- **Authentication**: X-API-Key header, matched against ApiServer.ApiKey in config
- **Handler Signature**: `func(http.ResponseWriter, *http.Request)`
- **Endpoints**: POST methods for commands, GET for status
- **Response Format**: JSON, with top-level Error and ErrorMsg fields
- **Port**: configurable via viper (e.g., "reporter.api.listen" → ":8080")

#### **Config Structure** (sample.yaml)  
```yaml
apiserver:
  apikey: "your-secret-key"
  listen: "127.0.0.1:8000"

scanner:
  interval: 300          # seconds between periodic scans (ignored for API-driven)
  # per-zone timeout, rate limiting (future)
```

**Convention**: Handlers use Globals.App.Type (AppTypeScanner) to gate features; response JSON includes AppName, Time, Status, Message.

---

## Pass 2: Design Sketch

### (a) Request Data: Stateless (Caller Provides Current View)

**Recommendation: Stateless**

The scanner API does not cache zone state. Each request includes the zone name and optionally the caller's current delegation data (CDS, NS, A, AAAA from the caller's perspective). The scanner queries the zone and compares to that snapshot, returning a delta.

**Rationale:**
- Caller (training lab, other agents) controls what "current" means (e.g., from last successful deployment, from cached last-scan, from its own zone file)
- No server-side state to lose or expire
- Simpler deployment (no persistent storage needed for the scanner itself)
- Caller can retry identical requests and get identical results

**Alternative considered**: Stateful with modification tokens. Scanner caches old state, client sends `if-modified-since` token. Rejected because training lab needs to bootstrap scans against fresh zones that have no prior state.

**Request Structure Example:**
```json
{
  "scan_type": "cds",
  "zones": [
    {
      "zone": "example.com.",
      "current_data": {
        "cds": ["60 3 1 abc123..."],
        "validated": true
      },
      "options": ["all-ns"]
    }
  ]
}
```

---

### (b) Scope: Single Zone Primary, Batch Secondary; Start Simple

**Recommendation: Offer both, but start with single-zone; add `/batch` for multi-zone**

**Single Zone (Primary, v1.0):**
```
POST /api/v1/scan/cds       (or /csync, /dnskey)
```
Request: zone name, optional current data, options  
Response: zone name, new RRset, changed bool, error if any

**Batch (Secondary, backlog):**
```
POST /api/v1/scan/batch
```
Request: array of single-zone scan requests (same structure, multiple zones)  
Response: array of responses, one per zone; job ID for async tracking if long-running

**Rationale:**
- Single zone is the common case (training lab scans one zone at a time)
- Batch is useful for activation-time scans of all zones in a lab (deferred to backlog; can add later without API break)
- Async job tracking (via /api/v1/scanner/status?job_id=...) already in tdns.ScanJobStatus struct

**Alternative considered**: Single generic `/api/v1/scan` with discriminated union response. Rejected because CSYNC's response genuinely differs (three RR types, multi-step): per-type endpoints avoid versioning nightmare.

---

### (c) Response Format: Encode Change State + Metadata

**Recommendation: Structured response with Status field (unchanged, changed, error)**

```json
{
  "zone": "example.com.",
  "scan_type": "cds",
  "status": "changed",
  "data": {
    "cds_rrset": ["60 3 1 abc123..."],
    "signature_validated": true,
    "validation_time": "2026-05-10T14:32:00Z"
  },
  "metadata": {
    "all_ns_queried": false,
    "all_ns_in_sync": true,
    "nameservers_checked": 2,
    "signed_response": true,
    "nsec_proof": null
  },
  "error": false,
  "error_msg": ""
}
```

**Status Field Values:**
- `"unchanged"`: New data matches caller's current_data
- `"changed"`: New data differs; details in data field
- `"error"`: Scan failed (e.g., zone unreachable); details in error_msg

**Data Subfields (per RR type):**
- **CDS**: cds_rrset (array of RR strings), signature_validated bool
- **CSYNC**: csync_rr (single RR), new_ns_rrset, new_a_glue, new_aaaa_glue, csync_stable (SOA pre/post match), rr_types_in_bitmap
- **DNSKEY**: dnskey_rrset, keyids_present, ksk_count, zsk_count

**Metadata:**
- all_ns_in_sync: true if "all-ns" option set and all NS returned identical RRset
- nameservers_checked: count of NS queried (if "all-ns")
- signed_response: DNSSEC validation passed (AD bit in response or explicit sig check)
- nsec_proof: proof of NXDOMAIN or NODATA (base64 NSEC/NSEC3 RRs), null if N/A

**Rationale:**
- Status field allows easy client logic (if status == "changed" then update)
- Metadata enables training lab to distinguish "genuinely absent" from "unsigned/unvalidated"
- DNSSEC validation status (validated, bogus, insecure) embedded per-zone, not global

**Alternative considered**: Three separate response types (ChangedResponse, UnchangedResponse, ErrorResponse). Rejected as overly verbose; single struct with nullable fields is simpler for REST.

---

### (d) CSYNC: Per-Type Endpoint due to Different Response Shape

**Recommendation: `/api/v1/scan/csync` (separate from /cds and /dnskey)**

CSYNC scanning is fundamentally multi-step and multi-RRtype:
1. Query child CSYNC at zone apex
2. Extract Flags (Immediate, UseSOAMinimum) + TypeBitMap
3. Pre-scan: query SOA, confirm stable
4. For each type in bitmap:
   - If NS: query zone NS, compare to parent delegation
   - If A: for each in-bailiwick NS, query A
   - If AAAA: same for AAAA
5. Post-scan: re-query SOA, confirm unchanged (RFC7477)

**CSYNC Response Example:**
```json
{
  "zone": "example.com.",
  "scan_type": "csync",
  "status": "changed",
  "data": {
    "csync_rr": "example.com. 3600 IN CSYNC 2026050901 3 NS A AAAA",
    "csync_stable": true,
    "changes": {
      "ns": {
        "status": "changed",
        "current_ns": ["ns1.example.com.", "ns2.example.com."],
        "new_ns": ["ns1.example.com.", "ns3.example.com."]
      },
      "a": {
        "status": "changed",
        "new_glue": ["192.0.2.1", "198.51.100.1"]
      },
      "aaaa": {
        "status": "unchanged"
      }
    }
  },
  "metadata": { ... }
}
```

**CDS/DNSKEY Responses (Simpler):**
```json
{
  "zone": "example.com.",
  "scan_type": "cds",
  "status": "unchanged",
  "data": {
    "cds_rrset": [...],
    "signature_validated": true
  },
  "error": false
}
```

**Rationale:**
- CSYNC endpoint can fully implement RFC7477 logic (three queries, stability check, per-type sub-analyzers)
- CDS endpoint focuses on single-RRtype logic
- DNSKEY endpoint focuses on key presence/rotation logic
- Future: if CSYNC logic grows, it can evolve independently without affecting other scanners
- Client code is clearer: use /scan/csync for delegation sync, /scan/cds for DS staging

**Alternative considered**: Generic `/scan` with response union. Rejected: endpoint explosion is cleaner than response type explosion for maintainability.

---

### DNSSEC Validation: Scanner Validates, Returns Status

**Recommendation: Scanner validates (via DNSSEC chain or external tool), returns status**

The scanner performs DNSSEC validation inline:
- For CDS: query zone for CDS+RRSIG; query parent for DS+RRSIG; call external `dnssec-cds` tool (as labstuff does) or use miekg/dns validation, return "validated" / "bogus" / "insecure"
- For DNSKEY: query zone for DNSKEY+RRSIG; return "signed" (RRSIG present) or "unsigned"
- For CSYNC: validate CSYNC RRset signature; if unsigned and zone signed, mark bogus

Validation status appears in response Metadata.signature_validated (bool) and error_msg if bogus.

**Caller does not re-validate**; caller can trust the scanner's verdict if it's authenticated (e.g., over mTLS, or via API key from a trusted source).

**Rationale:**
- Scanner is authoritative on validation (has access to full chain, can use libdnssec)
- Training lab code stays simple (just checks "validated": true)
- Validation errors are scanner's concern (misconfiguration, expired DS, key rollover timing)

---

### Concurrency & Rate Limiting

**Recommended (v1.0): No rate limiting; defer to v2.0 hardening**

v1.0 constraints:
- Up to N concurrent scans (configurable, default 10)
- Per-zone timeout (configurable, default 30s)
- Queue depth: drop requests if backlog exceeds M (default 100)

v2.0 (future):
- Per-target rate limiting (e.g., max 1 query per zone per 60s)
- Exponential backoff for non-responsive zones
- Per-zone concurrency cap (e.g., max 2 parallel scans of same zone)

**Rationale:**
- Training lab is controlled environment; high load is not expected
- Per-zone query overhead is acceptable (one recursive query + optional NS fan-out)
- Avoid premature optimization; measure in production first

---

### Failure Taxonomy: Distinct Error Outcomes

**Recommended: Return specific error codes and messages for each failure mode**

Scanner distinguishes:
- **NS_UNREACHABLE**: No authoritative nameservers found for zone
- **NXDOMAIN**: Zone does not exist (NODATA response to SOA query)
- **LAME_DELEGATION**: Nameserver claims no authority
- **TIMEOUT**: Query did not complete within timeout window
- **BOGUS_SIGNATURE**: DNSSEC validation failed (bad signature, key missing)
- **UNSIGNED**: Expected signed response, got unsigned
- **SOA_UNSTABLE** (CSYNC only): SOA changed during multi-query scan
- **QUERY_ERROR**: Generic DNS error (SERVFAIL, REFUSED, etc.)

Each error appears in response.error_msg as a structured message:
```json
{
  "error": true,
  "error_msg": "BOGUS_SIGNATURE: zone example.com. DNSKEY RRset signature invalid (key 12345 not found in parent)",
  "error_code": "BOGUS_SIGNATURE"
}
```

**Rationale:**
- Training lab can automate remediation (LAME_DELEGATION → check NS glue, TIMEOUT → retry with longer window, etc.)
- Debugging is easier with taxonomy vs. generic "error"
- API is versioned; new error codes do not break existing clients

---

### Authentication & Authorization

**Recommended: API Key (X-API-Key header); defer mTLS/SIG(0) to v2.0**

Scanner uses X-API-Key header matching ApiServer.ApiKey, same as other tdns-apps (reporter, ddep, whois-status). No per-zone ACLs in v1.0.

**Rationale:**
- Consistent with existing tdns-apps
- Simple to configure in training lab (one shared key for all scanner consumers)
- Future v2.0 can add SIG(0) for DNSSec-signed requests or mTLS for inter-service auth

---

## Scope: Wrap, Don't Rewrite

**Recommendation (revised 2026-05-10 after side-by-side comparison): Use the existing tdns v2 scanner as the foundation. Do NOT extract labstuff scanner code.**

Side-by-side reading of `tdns/v2/scanner.go` (1319 lines) vs `labstuff/lib/scanner.go` + `scanner_cds.go` + `scanner_dnskey.go` + `scanner_csync.go` (~1300 lines combined) reveals the tdns scanner is meaningfully more mature:

| Aspect | tdns v2 scanner | labstuff scanners |
|---|---|---|
| Encapsulation | `Scanner` struct with injected dependencies (`AuthQueryQ`, `ImrEngine`, `OnDelegationChange` callback) | Looser, with `scanner.LabDB` embedded — direct DB coupling to statusd's database |
| Async dispatch | `ScanRequest`/`ScanResponse` channels, `Jobs` map with crypto/rand-generated IDs, `JobsMutex` | Synchronous calls only |
| Cancellation | `context.Context` threaded through `CheckDNSKEY`/`CheckCDS`/`CheckCSYNC` | None |
| Polling vs NOTIFY | Both: `ProcessCDSNotify`/`ProcessCSYNCNotify` separate from polling `CheckCDS`/`CheckCSYNC` | Polling only |
| EDNS0 KeyState | `Edns0Options *edns0.MsgOptions` first-class on every scan | Not present |
| ScanType | Enum (`ScanCDS`/`ScanCSYNC`/`ScanDNSKEY`) with `ScanTuple` carrying parent/child/current data | String dispatch in scanner.Run() |
| DNSKEY logic | `CheckDNSKEY` is a real implementation | `CheckDNSKEY` (47 lines): half commented-out (`KnownDNSKEY` lookup disabled, "FIXME: need a AnalyzeDNSKEY", "FIXME: need to sort out the data type for the dnskey_rrs"), no change-detection, no validation. **This is the brittle scanner that has misbehaved during ZA courses.** |
| CDS logic | Coherent flow with explicit job/response semantics | `scanner_cds.go:26`: `XXX: This is not what the code presently DOES, but it is what it SHOULD DO :-)` — explicit author admission of design/implementation mismatch |
| Persistence coupling | None at the scanner layer; caller decides | `scanner.LabDB` directly used inside CheckCDS / CheckDNSKEY etc. — must be cut to extract |

The labstuff scanners read as early sketches written under course-delivery time pressure. The tdns scanner is the design that learned from that experience.

**Therefore the work is:**

1. **Take tdns v2 `Scanner` as-is** as the engine of `tdns-scanner`
2. **Build the API layer** (per-RRtype endpoints from §Pass 2) on top of that engine — this is genuinely new work, since the tdns scanner is currently embedded in tdns binaries, not exposed as a service
3. **Migrate or retire** labstuff's scanner code: training-lab statusd becomes a *client* of the new tdns-scanner service rather than embedding its own scanner. Once that's done, `labstuff/lib/scanner*.go` can be deleted entirely (subject to confirming no out-of-band callers).

**Not rewritten** (reused from tdns scanner):
- DNSSEC validation (already in tdns)
- RFC 7477 CSYNC protocol with SOA stability check (`tdns/v2/scanner_csync.go`)
- RRset diff and change-detection logic
- Job/response channel plumbing

---

## Implementation Sketch: Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Request statefulness** | Stateless (caller provides current data) | Simplifies deployment; caller controls "current" definition |
| **Single vs. batch** | Both (single primary, batch deferred) | Single covers 90% of use cases; batch is nice-to-have |
| **Response format** | Structured JSON with Status field (unchanged/changed/error) | Clear client logic; avoids response type explosion |
| **CSYNC endpoint** | Separate `/scan/csync` from `/scan/cds` | CSYNC response shape differs; per-type is cleaner |
| **DNSSEC validation** | Scanner validates inline, returns status | Client doesn't need to re-validate; validation errors are scanner's concern |
| **Concurrency** | No rate limiting in v1.0; defer to v2.0 | Training lab is controlled; avoid premature optimization |
| **Error reporting** | Taxonomy with error codes (NS_UNREACHABLE, TIMEOUT, BOGUS_SIGNATURE, etc.) | Enables client automation; aids debugging |
| **Auth** | X-API-Key header (API key) | Consistent with existing tdns-apps |
| **Code reuse** | Use existing tdns v2 scanner as engine; retire labstuff scanners as clients migrate | tdns scanner is the more mature design (context, async jobs, EDNS0, NOTIFY-driven); labstuff DNSKEY scanner is the known-brittle one that prompted this work — extracting it would carry the same brittleness forward |

---

## Appendix: API Endpoint Summary (v1.0)

```
POST /api/v1/scan/cds
  Request: { "zone": "example.com.", "current_data": { "cds": [...] }, "options": [...] }
  Response: { "zone": "example.com.", "status": "changed", "data": { ... }, "error": false }

POST /api/v1/scan/csync
  Request: { "zone": "example.com.", "current_data": { "ns": [...], "a": [...], "aaaa": [...] }, "options": [...] }
  Response: { "zone": "example.com.", "status": "changed", "data": { "csync_rr": "...", "changes": { "ns": {...}, "a": {...}, "aaaa": {...} } }, ... }

POST /api/v1/scan/dnskey
  Request: { "zone": "example.com.", "current_data": { "dnskey": [...] }, "options": [...] }
  Response: { "zone": "example.com.", "status": "changed", "data": { "dnskey_rrset": [...], "keyids": [...] }, ... }

GET  /api/v1/scanner/status?job_id=... (async job tracking; optional in v1.0)

HEAD /api/v1/ping (health check)
```

---

## Next Steps (for the record, not in this doc)

1. **Prototype**: Extract CheckCDS from labstuff into tdns; add API endpoint; test against labstuff's scanner.go expectations
2. **Training Lab Integration**: Wire into ZA course; verify DNSKEY brittleness is resolved
3. **Rollout**: Deploy tdns-scanner sidecar in training lab; retrain lab code to call API instead of importing scanner
4. **Hardening** (v2.0): Rate limiting, per-zone timeout config, SIG(0) auth, batch endpoint
5. **Deprecation**: Sunset labstuff's embedded scanner; recommend external service for other consumers

---

**Document ends.**
