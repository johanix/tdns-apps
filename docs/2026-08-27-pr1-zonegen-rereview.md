# Re-review: tdns-apps PR #1 (zonegen generalization)

2026-08-27

**PR:** [johanix/tdns-apps#1](https://github.com/johanix/tdns-apps/pull/1)
**Branch:** `feature/tdns-zonegen` → `main`
**Design:** [`2026-08-27-zonegen-generalization.md`](2026-08-27-zonegen-generalization.md)
**First review:** [`2026-08-27-pr1-zonegen-review.md`](2026-08-27-pr1-zonegen-review.md)

Follow-up commits: `3f0ff93` (the six defects) and `c2bdd52` (README). Re-ran
`go test` in `cmd/zonegen`: pass, including the golden gate.

## Verdict

**Mergeable.** Every first-round finding is fixed in code, with a regression
test that would have failed on the old behaviour. F7 (delegation churn) was
called low and optional; they did it anyway.

One remaining disagreement: the design note says the first review was wrong
that the daemon defaults `usetls` to true. That claim is looking at the Go
struct zero value, not the loader. It is not a merge blocker for the original
F4 (explicit `usetls: false` plus a required certfile), which is actually
fixed. It is a leftover hole for configs that *omit* the key.

| | |
|---|---|
| Architecture vs design | Still matches |
| Merge as-is | Yes |
| Blocking | None |
| Leftover | Omitted `usetls` vs current tdns `decodeConfigMap` (see F4 remainder) |

## First-round findings

### F1 — Fresh generate serial — **closed**

`runGenerate` now, when `zs.Serial == 0`, walks the set, takes
`previousSerialOf` (SOA serial or 0) as the floor, then `NewSerial(now, prev)`.
`--update` still sets the serial itself and is skipped. The regression
(`TestRegenerateAdvancesTheSerial`) regenerates with different flags over an
existing file and requires the serial to advance.

### F2 — README — **closed**

`cmd/zonegen/README.md` is rewritten around `pqtree` / `tree` / `bigzone` /
`rpz`. `--plan` is a flag. The examples are the current CLI.

### F3 — `/32` addr-pool panic — **closed**

`newAddrPool` rejects `hostBits < 1 || hostBits > 31`. Tests cover `/32`, `/0`,
and still accept `/31` and `/24`. Cosmetic: the explanatory comment is pasted
twice (lines 392–397 of `gen_bigzone.go`).

### F4 — scheme from `certfile` — **closed for the reported bug**

`fromAuthConfig` now reads `usetls`. HTTPS and `RootCAFile=certfile` only when
`UseTLS` is true. IPv6 unspecified becomes `::1`. Tests cover TLS on, TLS off
despite a certfile, IPv4 wildcard, and IPv6 wildcard.

The original lab failure (explicit `usetls: false` plus a required cert path
dialling HTTPS at an HTTP listener) is gone.

### F5 — pqtree `AddGlue` — **closed**

`buildPqtree` calls it. `TestInBailiwickNameserverHasAnAddress` includes a
pqtree case with `nameservers: [ns1.pq.example.]`.

### F6 — churn remainder to adds — **closed**

`nAdd = nDel`, remainder to `nMod`. `TestChurnKeepsTheZoneSize` runs six
rounds and requires the CNAME owner count to be unchanged.

### F7 — `--update` ate delegations — **closed** (was optional)

Cuts, and everything below them, are held out of the victim set.
`TestChurnPreservesDelegations` churns a 200-name zone with 6 cuts, four times,
and requires the NS count to stay put.

## Remaining: F4 and the UseTLS default

The design note (and the comments in `apiresolve.go` / `apiresolve_test.go`)
say the first review was wrong to ask for default-true, because `UseTLS` is a
plain bool with no `SetDefault`, so unset means false and `apirouters.go`
serves HTTP.

That is the struct after decode. It is not what the daemon does.

Current tdns injects the default **before** decode, in `decodeConfigMap`:

```129:134:tdns/v2/parseconfig.go
	// apiserver.usetls defaults to true, applied to the raw map so an absent
	// key and an explicit `usetls: true` decode identically.
	if apiserverMap, ok := configMap["apiserver"].(map[string]interface{}); ok {
		if _, explicitlySet := apiserverMap["usetls"]; !explicitlySet {
			apiserverMap["usetls"] = true
```

The IMR sample comments the same fact (`usetls defaults to TRUE when not
set`). `apirouters.go` then sees `UseTLS == true` and serves HTTPS.

zonegen YAML-unmarshals the auth file itself, so an omitted `usetls:` is
false and it dials HTTP. Against a current tdns-auth that omitted the key,
that is HTTP client vs HTTPS listener — the opposite handshake of the original
F4, same class of failure.

The shipped `tdns-auth.sample.yaml` writes `usetls: true`, so the documented
copy-paste path is fine. Operators who omit the key because the daemon
documents a default will not be.

This is not the bug that was reported (explicit false). Retract the “review
was wrong about the daemon” paragraph; either:

- inject default-true the way `decodeConfigMap` does, or
- say in the README that `--tdns-auth` requires an explicit `usetls:` because
  zonegen does not run the tdns loader.

The “tls off despite a certfile” test currently *omits* the key rather than
writing `usetls: false`. Both unmarshal to false today, so they do not
distinguish “explicit off” from “rely on default.” If the default is flipped
to true, that test should write the key.

## Other leftovers (not blocking)

- **Apex glue is still a churn victim.** `readExistingZone` skips apex NS but
  keeps the in-bailiwick A that `AddGlue` wrote. Deleting that name and adding
  a rule, then `AddGlue` putting the A back, grows the RPZ rule count by one.
  `TestChurnKeepsTheZoneSize` counts CNAMEs only, so it can miss this; the
  current seed happens not to pick the glue. Hold nameservers’ in-bailiwick
  addresses out of the victim set the same way cuts are, if size-stability is
  meant to be a fact rather than “usually.”
- Duplicate `/32` comment in `newAddrPool`.

Neither re-opens F1–F7.
