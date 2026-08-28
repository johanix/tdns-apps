# Review: tdns-apps PR #1 (zonegen generalization)

2026-08-27

**PR:** [johanix/tdns-apps#1](https://github.com/johanix/tdns-apps/pull/1)
**Branch:** `feature/tdns-zonegen` → `main`
**Design:** [`2026-08-27-zonegen-generalization.md`](2026-08-27-zonegen-generalization.md)

Tests: `go test` in `cmd/zonegen` is green (including the golden gate). This
review is against the design note and the three areas the PR itself asked to
have looked at: `gen_bigzone.go` legality, `update.go` churn, `apiresolve.go`.

## Verdict

**Request changes.** The split (one generator → `ZoneSet` → shared back half)
matches the design, the golden file is the right kind of gate, and the new
generators are careful about DNS legality on the *fresh* path. Two claimed
fixes are incomplete, the README still documents the old CLI, and a `/32`
addr-pool panics.

| | |
|---|---|
| Architecture vs design | Matches. Separate subcommands, unsigned skips the keystore, policies drive `large_algorithms`/`split_algorithms`. |
| Merge as-is | No |
| Blocking | Fresh regenerate still stamps `YYYYMMDD00`; README is the old `plan`/`generate` CLI |

## What matches the design

- Generators produce only a `ZoneSet`. Keys, DS, render, atomic write, auth
  block live in `zoneset.go` / `keys.go` / `runGenerate`.
- Empty policy ⇒ `NeedsKeys() == false` ⇒ rpz runs with no API and no config
  file (`LoadConfig` treats a missing default path as empty).
- Shape on the command line, plumbing in YAML. pqtree keeps `combos:` in
  config. `ValidatePqtree` is only called from the pqtree command.
- `largeAlgorithmsOf` / `splitAlgorithmsOf` walk `[]PolicySpec`, not combos.
- `--tdns-cli` / `--tdns-auth`, conventional name `tdns-server`, refuse on
  ambiguous multi-server configs, print the resolution before creating keys.
- CNAME-exclusive names, NS only via `--delegations`, occluded name under
  each cut — all present in `bigzoneRecords`, and `assertLegal` actually
  checks CNAME-with-other-data and extra types at a delegation point.
- `--update` is only on bigzone and rpz. pqtree/tree churn is correctly out of
  scope (DS/key operations).
- The `"2006010200"` serial bug is real, and `NewSerial(now, previous)` is the
  right function. Tests pin floor, same-day increment, and “do not go
  backwards.”
- In-bailiwick NS without A is the BIND load failure they describe.
  `AddGlue` + `TestInBailiwickNameserverHasAnAddress` cover rpz, bigzone, tree.

`f38cfdc` standing alone is a good commit split.

## Blocking findings

### F1 — Fresh generate still never reads the previous serial — **High**

The PR presents the serial fix as closing: *regenerating a zone twice in one
day wrote new content under an unchanged serial*.

`NewSerial` does the right thing **when given `previous`**. The fresh path
never gives it:

```117:119:cmd/zonegen/main.go
	if zs.Serial == 0 {
		zs.Serial = NewSerial(time.Now(), 0)
	}
```

`--update` sets `zs.Serial` from the file before `runGenerate`, so it is
fixed there. A second `tdns-zonegen bigzone --count 2000 …` on the same day,
overwriting a 1000-name zone, still stamps `YYYYMMDD00`. That is the original
bug, on the path operators will use when they change flags and regenerate.

Identical deterministic regen (same flags) hiding under the same serial is
harmless. Different flags, or a pqtree combo list edit, is not: secondaries
keep the old zone.

Fix: if the target file exists, parse its SOA serial and pass it in, same as
`--update`. The 150-iteration test already shows overflow into the next day’s
numbers stays monotonic.

### F2 — README documents a CLI that this PR deletes — **High** (docs)

`cmd/zonegen/README.md` still says:

```
tdns-zonegen plan --config …
tdns-zonegen generate --config …
tdns-zonegen delegation --config …
```

The binary now has `pqtree` / `tree` / `bigzone` / `rpz`. `plan` is a flag.
Someone following the README in this PR gets “unknown command”. The sample
yaml and the design note are current; the README was not updated in the same
change.

## Other findings

### F3 — `--addr-pool …/32` panics — **Medium**

```392:401:cmd/zonegen/gen_bigzone.go
	ones, bits := netw.Mask.Size()
	return &addrPool{base: ip, size: 1 << uint(bits-ones)}, nil
…
	off := p.n%(p.size-1) + 1
```

`/32` → `size == 1` → `size-1 == 0` → modulo by zero. A `/0` is
`1 << 32` which is 0 in Go, same class of mess. Reject prefixes smaller than
two hosts (or special-case a single address). Default `/24` hides this.

### F4 — `fromAuthConfig` treats `certfile` as “use HTTPS” — **Medium**

tdns-auth requires `apiserver.certfile` even when `usetls: false`. The
derivation does not read `usetls`:

```204:207:cmd/zonegen/apiresolve.go
	scheme := "http"
	if a.CertFile != "" {
		scheme = "https"
	}
```

A lab `tdns-auth.yaml` with `usetls: false` and a required cert path becomes
`https://…` against an HTTP listener. Tests only cover configs that include
`certfile` and expect https. Derive the scheme from `usetls` (default true, as
the daemon does), and keep `certfile` as the self-signed anchor only when
HTTPS is actually on.

`[::]:8989` → `127.0.0.1` is tested as intentional. An IPv6-only bind then
fails; `::1` for an IPv6 wildcard would be the matching pair of the IPv4
case. Lower, but the same function.

### F5 — pqtree never calls `AddGlue` — **Medium**

tree / bigzone / rpz all call it. `buildPqtree` does not. The sample and the
golden file use out-of-bailiwick `ns1.example.` / `ns2.example.`, so BIND
still loads. An operator who sets `nameservers: [ns1.pq.example.]` recreates
exactly the “parses, will not load” failure this PR exists to remember.
`TestInBailiwickNameserverHasAnAddress` does not include pqtree. One call
next to the other generators.

### F6 — Churn remainder always becomes extra names — **Low**

The write-up says adds and removes are balanced so the zone neither grows nor
shrinks. The split is:

```
nDel = total/3
nMod = total/3
nAdd = total - nDel - nMod   // remainder, 0..2 extra adds
```

`go test` itself prints `4 removed, 4 changed, 6 added` (7% of ~200). The
size-stability test allows a diff of 5, so it cannot catch this. Over a day
of RPZ `--update` that is slow growth, not unbounded, but it is not what the
doc claims. `nAdd = nDel` and give the remainder to `nMod`.

`--update` on a one-name foreign file (`--force`) becomes “0 removed, 1
added”: integer floor plus `total = max(1, …)` cannot split three ways.

### F7 — `--update` does not preserve bigzone delegations — **Low**

Fresh `--delegations` is legal. Churn operates on owner groups: Remake of a
cut point replaces NS with mix types; delete of the cut leaves `ns1.*` glue
and `occluded.*` as ordinary names. Still parseable, no longer the fixture
`--delegations` described. `TestUpdatedZoneIsStillLegal` only runs on RPZ.
Either skip cuts in the victim set, or document that `--update` is for
non-delegated bigzones.

## Design-doc nits (not merge blockers)

- Header still says “nothing is committed yet (signing was unavailable).”
- `AuthConfig` still tells the operator not to `include:` the generated
  file. Correct for tdns today; when tdns `merge: true` lands, zonegen’s
  printed next-steps should follow.

## Suggested order

1. Pass the existing file’s SOA into `NewSerial` on overwrite (F1).
2. Rewrite the README to the subcommand CLI (F2).
3. Reject `/32` (and `/0`) addr-pools (F3).
4. Honour `usetls` in `fromAuthConfig` (F4).
5. `buildPqtree`: `AddGlue`, and add pqtree to the BIND-glue test (F5).
6. `nAdd = nDel` (F6), if the size claim stays in the docs.

The generator split, the golden gate, and the unsigned/keystore rule do not
need to be revisited.
