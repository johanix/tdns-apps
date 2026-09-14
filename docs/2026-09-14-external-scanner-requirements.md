# External CDS/CSYNC scanner: requirements

Written 2026-09-14. Requirements for a first implementation; the design follows.

Revisions:
- r1 2026-09-14: first version.

## Purpose

tdns-auth has a built-in scanner. It runs inside the server that hosts the
parent zone, is triggered by NOTIFY, and applies what it finds to that zone
(tdns `docs/2026-03-19-csync-scanner-plan.md`). The built-in scanner stays.

The external scanner is a separate binary, built from the same tdns library
code, that scans the children of parent zones it does not serve. It checks what
each child publishes -- CDS and CDNSKEY for the DS RRset, CSYNC for NS and glue
-- and reports what it finds to wherever the parent's delegation data is
managed.

The scanner reports observations. Whether an observed change is applied, and
under which policy, is decided after the scanner: by a later policy-evaluation
step, or by whoever consumes the delegation store.

### Earlier design

`docs/2026-05-10-tdns-scanner-extraction.md` and
`docs/2026-05-10-tdns-scanner-implementation-plan.md` sketched a scanner service of a different shape:
- stateless, with the caller supplying the current data;
- pull-only;
- per-RRtype scan endpoints for CDS, CSYNC and DNSKEY;
- new code in `tdns/v2`.

These requirements differ:
- the scanner knows its parents and owns its diff source (sections 1 and 5);
- NOTIFY triggers scans (R2.6);
- state survives a restart (R7.1);
- scale and rate limiting are requirements from the start (section 3);
- the code lives in tdns-apps ("Where the code lives");
- DNSKEY scanning is not covered (open question 4).

## Terms

- **Parent**: a zone whose children the scanner is configured to scan.
- **Child**: a zone delegated from a parent.
- **Target**: one address (IP and port) of one of a child's nameservers.
- **Job**: one scan request and everything it scans.
- **Sink**: where the scanner writes the changes it finds for a parent.
- **Diff source**: the current delegation data a scan compares against.

## 1. Parents and children

- **R1.1** The scanner scans the children of several parents, each configured
  separately.
- **R1.2** The scanner has access to every configured parent zone, and lists a
  parent's children from it.
- **R1.3** A child belongs to the closest enclosing configured parent. With both
  `example.` and `sub.example.` configured, `a.sub.example.` belongs to
  `sub.example.`.
- **R1.4** A zone under no configured parent can still be scanned when it is
  named explicitly. That scan only reports: its nameservers come from the
  parent's public referral, its current DS from a validated DS query, and it has
  no sink.

## 2. Triggers

- **R2.1** An API request scans every child of a named parent.
- **R2.2** An API request scans a list of named zones, under any parent.
- **R2.3** Scanning the children of a parent that match a filter is a later
  addition. The request format leaves room for it.
- **R2.4** A request names the scan types: CDS, CSYNC, or both (the default).
- **R2.5** The CLI sends every request type. Jobs are asynchronous: a request
  returns a job id, and the CLI and the API report a job's progress (children
  done and remaining, percentage, ETA) and its results.
- **R2.6** A NOTIFY(CDS) or NOTIFY(CSYNC) (RFC 9859 NOTIFY scheme) for a child of
  a configured parent scans that child for that type.

## 3. Scale and rate limiting

- **R3.1** A TLD-sized parent is a supported case: one job over hundreds of
  thousands of children or more. An earlier scanner found around 15,000
  concurrent workers optimal for such a parent.
- **R3.2** Scans run on one global worker pool. Its size comes from the config,
  with a conservative default, and can be changed through the API without a
  restart.
- **R3.3** Every query to a target passes a limiter in the send path. The limiter
  enforces a minimum interval between two queries to the same target: a
  configured default (25 ms unless set) and per-target overrides in the config.
- **R3.4** The limiter holds under concurrency: a query claims its send slot for
  the target before it waits, so any number of workers queued on one target send
  at most one query per interval.
- **R3.5** A nameserver name is resolved to its addresses once per job, not once
  per child that uses it.

## 4. What a scan requires

These are the scanner's responsibility. Parent policy is not (section 8).

### Validation and consistency

- **R4.1** All data the scanner copies from a child validates Secure through the
  embedded IMR. A type proven absent by NSEC or NSEC3 is a validated absence.
- **R4.2** The scanner uses no external resolver.
- **R4.3** The nameservers a scan queries are the parent's NS RRset for the child.
- **R4.4** Every address of every one of those nameservers is queried directly,
  and they all agree. A timeout, an error, or a missing answer from any of them
  is a disagreement, and a disagreement stops the scan of that child.

### CDS and CDNSKEY (RFC 7344, RFC 8078, RFC 9615)

- **R4.5** For a child with a DS RRset, the CDS validates Secure and is signed by
  a key that the current DS RRset points to (RFC 7344 §4.1).
- **R4.6** For a child without a DS RRset, the only bootstrap is RFC 9615:
  authenticated CDS at the signaling names of the child's nameservers.
- **R4.7** CDNSKEY is read as well as CDS. When a child publishes both, they
  describe the same keys, or the scan refuses.
- **R4.8** The CDS removal sentinel (RFC 8078 §4) reports removal of the whole DS
  RRset.
- **R4.9** The DS RRset a scan reports matches keys in the child's DNSKEY RRset,
  and the child still validates with it.

### CSYNC (RFC 7477)

- **R4.10** A CSYNC with a flag bit other than immediate and soaminimum is not
  processed. A CSYNC without the immediate flag is reported and not processed.
- **R4.11** With soaminimum set, a CSYNC whose serial is above the child's SOA
  serial is not processed.
- **R4.12** The child's SOA serial is the same at the start and at the end of the
  scan, or the scan is discarded.
- **R4.13** A CSYNC whose serial is lower than the last one processed for that
  child is not processed.
- **R4.14** A CSYNC whose type bitmap names a type the scanner does not implement
  is not acted upon.
- **R4.15** Only the types the bitmap names are processed, NS before A and AAAA.
- **R4.16** Glue is only for nameservers inside the child zone. A glue type proven
  absent at the child is reported as an empty set.
- **R4.17** A result that would leave the child's in-bailiwick nameservers without
  any A or AAAA glue is refused.

### Lameness and hold-down

- **R4.18** Every nameserver a scan would add answers an SOA query for the child
  with AA set, on each of its addresses. Its SOA serial may differ from the
  others'.
- **R4.19** After reporting a change for a child, the scanner reports no further
  change for that child until a configured hold-down period has passed.

## 5. Results and sinks

- **R5.1** Every child a job scans gets a result: unchanged, changed (with the
  records to add and to remove), refused (with the requirement from section 4
  that failed), or error. Results are available through the API and the CLI,
  and logged.
- **R5.2** A refusal or an error is reported to the child's reporting agent
  through RFC 9567 DNS error reporting, when the child's nameservers advertise a
  Report-Channel.
- **R5.3** Each parent has one sink. The diff source is the sink's own view of the
  delegation, so a change that has been written but not yet published is not
  reported again:

  | Sink | Writes | Diff source |
  |---|---|---|
  | external-db | the delegation store tdns-agent already uses | the store |
  | tdns-auth management API | `/zone` `update` into the parent zone | `/zone` `get-name` for the child's apex and each nameserver name |
  | DNS UPDATE | TSIG-signed UPDATE to the parent's primary | the parent zone |
  | zonefile | per-child fragments, through the existing zonefile writer | the writer's store |

- **R5.4** The tdns-auth API sink needs a parent zone in tdns-auth that originates
  its own content, carries `allow-api-updates`, and is not frozen. A refusal for
  any of these is reported as a sink error on the job.
- **R5.5** What the scanner writes is labelled as scanner output, by scan type, so
  a consumer of the store can tell it from child updates arriving over other
  channels.
- **R5.6** The scanner does not decide whether a change is applied. With the
  external-db sink, the consumer of the store decides.

## 6. tdns-auth with an external scanner

- **R6.1** tdns-auth gets a server-wide setting `scanner: internal | external`,
  default `internal`. It has an effect only when a `childsync:` block is
  configured.
- **R6.2** With `external`, tdns-auth does not run its built-in scanner and
  refuses NOTIFY(CDS) and NOTIFY(CSYNC) for its zones.
- **R6.3** With `external`, the DSYNC NOTIFY records tdns-auth publishes name the
  external scanner (`childsync.notify` target, port and addresses), not tdns-auth
  itself.

## 7. Operation

- **R7.1** State survives a restart: jobs and their results, the last processed
  CSYNC serial per child, and hold-downs.
- **R7.2** The embedded IMR runs with configured trust anchors.
- **R7.3** The API is authenticated as the other tdns APIs are. Credentials the
  scanner holds (TSIG keys, database credentials) are protected by the host's
  file permissions; nothing beyond the host's Unix security is required.

## 8. Not in the first implementation

- **Parent policy.** Accepted DS digest types and DNSKEY algorithms, NS and DS
  counts, TTLs, manual approval. The scanner reports records as the child
  publishes them, TTLs included.
- **Filtered child selection** (R2.3).
- **Adaptive rate limiting.** The limiter in R3.3 uses fixed intervals. The later
  version recalibrates per job, not per query. For every target seen in a job,
  it counts queries, timeouts and REFUSED answers. It then moves the target's
  interval by binary search between an interval known to be safe and one known
  to cause trouble, and keeps both across jobs and restarts. It never goes below
  a floor or above a ceiling, and it adjusts only on a minimum number of
  queries. R3.4 applies to it unchanged.
- **Scheduling inside the scanner.** Periodic scans are CLI requests from cron.
- **RFC 8078 accept-after-delay bootstrap.** R4.1 excludes it: a child without a
  DS cannot validate at its apex.

## Where the code lives

The external scanner is a tdns-apps application. It imports `tdns/v2` and can
use any code there. New code goes where it touches the built-in scanner least:

- **`tdns-apps/cmd/scanner`**: the binary and its configuration. The existing
  `cmd/scanner` is a shell on the legacy `github.com/johanix/tdns/tdns` module
  and the simple API router; it is rebuilt on `tdns/v2`.
- **`tdns-apps/lib/`**: everything that does not change tdns-auth's built-in
  scanner:
  - the job engine and worker pool (R3.2);
  - the limiter (R3.3, R3.4);
  - listing a parent's children (R1.2);
  - the sinks and their diff sources (section 5);
  - persistent state (R7.1);
  - NOTIFY handling (R2.6);
  - the scanner's API endpoints and CLI commands.
- **`tdns/v2`**: only what the built-in scanner shares, or what tdns-auth needs:
  - the prerequisites below;
  - changes to the shared scan code, such as scanning a child without a hosted
    parent zone, or a hook for the limiter in the query path;
  - the `scanner:` setting and its DSYNC publication (section 6).

## Prerequisites in tdns

The external scanner reuses the built-in scanner's code, so these are fixed in
tdns first. tdns-auth needs the fixes too.

- **P1** The processed-CSYNC-serial map (`KnownCsyncMinSOAs`) is read and written
  by concurrent scans without a lock. Two NOTIFY(CSYNC) handled at the same time
  can crash tdns-auth.
- **P2** `StartScanner` does not start `AuthQueryEngine`, so a scanner-only
  application cannot send its queries to children.
- **P3** DNS error reporting uses EDNS option code 65003. RFC 9567 §7 assigns 18.
  The code changes to 18, with no compatibility for 65003.
- **P4** The shared CSYNC code deviates from RFC 7477 and from R4.4:
  - it skips a bitmap type it does not implement and processes the rest (R4.14);
  - it processes NS when the bitmap does not name it (R4.15);
  - an empty answer is an error, so a glue type cannot become empty (R4.16);
  - nothing refuses a result without glue (R4.17);
  - nameservers that time out or answer with nothing are left out of the
    agreement check (R4.4).
- **P5** A DS change found by the built-in scanner skips the DS-against-DNSKEY
  check that DNS UPDATE and the DSYNC API run (R4.9, and tdns#641 for R4.5).

## Open questions

1. **NOTIFY volume.** A NOTIFY only triggers a scan, and the scan validates
   everything, so NOTIFY needs no authentication of its own. Repeated NOTIFYs
   for one child should still not each start a scan. Proposal: coalesce them, at
   most one NOTIFY-triggered scan per child per configured interval.
2. **CDS or CDNSKEY first.** When a child publishes only one of them, the scanner
   uses it. When it publishes both and they match (R4.7), which one is the
   source of the DS RRset is a design decision. It affects only which digest
   type is reported.
3. **Address families.** Under R4.4 a timeout on any address is a disagreement,
   so a scanner host without IPv6 connectivity refuses every child with an IPv6
   nameserver address. Proposal: a setting for the address families the scanner
   queries, both by default; R4.4 then applies to the configured families.
4. **DNSKEY scanning.** The earlier design included a DNSKEY scan. These
   requirements cover CDS and CSYNC; whether the external scanner also scans
   DNSKEY is open.
