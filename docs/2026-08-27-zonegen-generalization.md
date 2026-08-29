# tdns-zonegen: from an algorithm matrix to a zone generator

2026-08-27. Status: **implemented and under review.** All four generators,
`--update` and the API-connection resolution are built, tested and committed;
[tdns-apps#1](https://github.com/johanix/tdns-apps/pull/1) is open. Review round
one is addressed — see the section at the end.

## The problem

zonegen fused three separate concerns into one object, `Combo{KSK, ZSK}`:

1. **which zones exist** — the zone set was literally `children.combos`
2. **what each zone contains** — every child was byte-identical apart from a TXT
3. **how each zone is signed** — one auto-generated policy per pair, fixed shape

There was no way to say "generate zone `alpha`" without also saying "with KSK A
and ZSK B", no way to give two zones different content, and no way to vary
anything but the algorithm pair. The PQ matrix was the only tree expressible.

## What was built

A **subcommand per kind of zone**, over a **shared back half**.

    tdns-zonegen pqtree   --zone pq.example.
    tdns-zonegen tree     --zone tree.example. --depth 3 --breadth 5
    tdns-zonegen bigzone  --zone big.example.  --count 100000 --types A,AAAA,MX
    tdns-zonegen rpz      --zone rpz.example.  --count 10000 --actions nxdomain,passthru

An earlier draft of this document proposed the opposite: one declarative config
language with `explicit:`/`matrix:` sources, N-dimensional axes and content
templates, so that a single generator could produce any of these. That was
over-unification. "100k names with an rrtype mix", "10k RPZ rules" and "one
child per algorithm pair" share nothing in their *inputs*, and forcing them
through one YAML language means growing a programming language in YAML — the
common cases get verbose and the language sprouts conditionals as soon as one
generator needs something the others do not. Separate generators with their own
flags and their own `--help` are simply better, and the N-dimensional matrix and
content-template machinery both became unnecessary rather than merely unbuilt.

What survives from that draft is the part that was load-bearing: generators
produce nothing but a `ZoneSet`, and everything downstream is shared.

### The shared back half

A generator decides what zones exist and what is in them. Everything after that
is identical whether the zones came from an algorithm matrix or a list of RPZ
rules: create the keys, read back the DS, splice delegations into parents,
render, write atomically, emit the tdns-auth block.

`ZoneSpec` is the currency — name, policy, comments, records, children. An empty
policy means unsigned, which is not a degenerate case but a load-bearing one:
**if no zone in the set names a policy, the keystore is never contacted**, so
`rpz` runs with no API connection and no config file at all.

### Where the input lives

**Shape on the command line, plumbing in the config.** A record count or an
action list is something you vary between runs and want visible in shell
history; a zonedir or an API key is not. The one exception is `pqtree`, whose
input is a list of algorithm pairs — too structured for a command line, and not
something that changes run to run — so it keeps a config section.

### Two derivations got better

`large_algorithms` and `split_algorithms` are now computed from the **resolved
policy set** rather than by walking combos. Today that is equivalent, because
combos and policies are the same set. It stops being equivalent as soon as a
policy can be written out by hand, which the new model allows: such a policy
would contribute nothing to `large_algorithms` if the derivation still walked
combos, and the zone would serve a DNSKEY response nothing was told to expect.

### The API connection

The details already exist on a host running tdns-auth — in the server's own
config, and usually again in `tdns-cli.yaml`. Writing them a third time is
busywork, so:

    --tdns-cli /etc/tdns/tdns-cli.yaml     lift a client config verbatim
    --tdns-auth /etc/tdns/tdns-auth.yaml   derive one from the server's config

with `/etc/tdns/tdns-cli.yaml` then `/etc/tdns/tdns-auth.yaml` tried when
neither is given. Precedence is flag, then this tool's own `apiservers:`, then
discovery, and the resolution is **always printed** before any key is created:
resolving to the wrong keystore should not be possible to do quietly.

Two details that needed care. A stock `tdns-cli.yaml` declares six servers and
the authoritative one is named `tdns-server`, not `tdns-auth` — matching on
"auth" finds nothing — so the conventional name is used, `--apiserver` overrides
it, and several candidates with no conventional name is a refusal rather than a
guess. And `apiserver.addresses` may be `0.0.0.0:8989`, which is bindable but
not dialable, so an unspecified host becomes loopback. `certfile` is the
server's own certificate rather than a CA: the right trust anchor when it is
self-signed, and not derivable at all when it is not.

### Legality

Generated zones must be legal, which a random rrtype mix does not give you for
free:

- a name chosen for CNAME gets **only** a CNAME, and is never a parent
- NS is never in the random mix. It is a delegation, not a record type you
  sprinkle, so it comes from `--delegations`, which places NS plus glue and
  nothing else at that name
- occluded data below a delegation is generated **on purpose**, one name per
  delegation: it is legal, it is what a real zone looks like, and it is exactly
  what a signer must not sign

### --update

`--update N` rewrites an existing zone file, churning roughly N% of it. The zone
file is the state — there is no sidecar — so it still works on a file that has
been hand-edited, and refuses a file this tool did not write unless `--force` is
given.

The churn is split three ways (remove, change, add) with adds and removes
balanced, so repeated updates neither grow nor shrink the zone. A "change" is
guaranteed to actually change: an early version redrew the action at random, so
one rule in five redrew the same value and `--update 5` quietly delivered less
than 5%. It is seeded from the zone name and the serial it replaces, so a given
input file always produces the same next file — a chain of updates is a
replayable sequence of deltas rather than a random walk.

### The serial bug this uncovered

`NewSerial` formatted the time as `"2006010200"`, believing the trailing `"00"`
was an hour. It is not a Go layout token, so it was emitted literally: **every
run on a given day produced the same serial.** Regenerating a zone twice in one
day wrote new content under an unchanged serial, which no secondary would ever
pick up. Now the datestamp is a floor and a serial that has reached it is
incremented.

## Verification

- **A golden-output gate.** The complete pqtree output — every zone file, the
  config block, the delegation snippet — was pinned *before* the refactor and is
  byte-identical after it. The restructuring is a diff that is empty.
- **BIND validates the output.** `named-checkzone` on a 100,000-name zone and a
  10,000-rule RPZ zone: OK. This caught what the Go-parser tests could not — a
  synthesised in-bailiwick nameserver with no address parses perfectly and then
  fails to *load*. "Parses" and "loads" are different claims; only one was being
  checked. Now pinned by a regression test, mutation-verified.
- Legality, type coverage, ENT creation, determinism, churn accuracy and the
  connection-resolution edge cases all have tests.

## What is deliberately not built

- **Programmatic record templates.** `bigzone` covers the large-zone case
  directly, so the `repeat:` construct a template language would have needed has
  no remaining customer.
- **Broken-DNSSEC negatives, NSEC3 variants, wildcard/CNAME-chain shapes.**
  Discussed, not chosen. Each would be a new subcommand rather than a change to
  the model.
- **`--update` for pqtree and tree.** Churning a delegation means DS changes and
  key operations, which is a different feature from rewriting a zone's contents.

## Extent

~2,900 lines across 15 files in `cmd/zonegen`, of which ~1,000 are tests. The
estimate in the earlier draft (+700/−250 for the unified model) does not compare
usefully: that design was replaced, and four generators is more than one.

## Review round one

An external review of PR #1 requested changes. Six findings, all real, all
fixed. Two are worth recording because of what they say about the original
work rather than the code:

**The serial fix was only half done.** `NewSerial(now, previous)` was correct,
but only `--update` ever passed `previous`; the plain regenerate path passed 0.
So the original bug survived on the path an operator actually uses when they
change flags and regenerate: new content, same `YYYYMMDD00`, invisible to every
secondary. The commit message claimed the bug was closed. It was not. A
regenerate now reads the SOA serial of whatever it is overwriting — the highest
across the set, since one serial covers all of it.

**The README documented a CLI this change deletes.** It still described
`plan` / `generate` / `delegation` as subcommands. The sample config and this
document were both updated in the same change; the README was missed entirely,
because the check for stale docs was a grep of the repo-root README rather than
the one next to the code.

The rest:

- `--addr-pool` with a `/32` panicked — size 1, then a modulo by size-1 == 0.
  A `/0` overflowed `1<<32` to zero. The default `/24` hid both.
- `fromAuthConfig` derived the scheme from whether `certfile` was set. tdns
  marks `apiserver.certfile` `validate:"required"`, so a cert path is present
  even on a server that never offers TLS, and the derivation would point
  `https://` at a plain HTTP listener. It now reads `usetls`, **defaulting to
  true when the key is absent** — see the retraction below.
- An IPv6 wildcard listen address became `127.0.0.1`, which would never reach a
  server bound IPv6-only. It now becomes `::1`, keeping the family.
- `buildPqtree` never called `AddGlue`, so the one generator whose zones the
  BIND-load fix was discovered on was the one still able to produce a zone that
  will not load — for an operator who sets in-bailiwick nameservers.
- Churn gave its split remainder to adds, so every update grew the zone by up
  to two names. Adds now equal removes and the remainder goes to
  modifications, which are size-neutral.
- Churn could remake or delete a delegation, replacing its NS with ordinary
  records or stranding its glue and occluded name. Cuts and everything below
  them are now held out of the victim set.

Each fix has a regression test, and the three behavioural ones (serial on
regenerate, size stability, delegation preservation) are mutation-verified.

## Follow-up: in sync with tdns's config after #404/#406 (2026-08-28)

Two tdns changes landed and both reach the file zonegen generates.

**tdns#406** respelled every config key with hyphens and kept no alias, so
`large_algorithms`/`split_algorithms` became `large-algorithms`/
`split-algorithms`. The failure mode was silence: the daemon's decoder ignores a
key it has no tag for, so the old spelling would not error, the guardrail would
simply be empty, and PQ zones would be served with DNSKEY responses nothing was
told to expect. The two names were already isolated in constants for exactly
this, so the change is one line plus fixtures.

**tdns#404** added opt-in include merging, which changes the *workflow* rather
than the content. The generated block used to carry a header saying "do NOT
pull this in with include:", because a bare include replaces the server's
`zones:` list wholesale. Now it can be included with `merge: true`, so the
operator wires it in once and a re-run plus a reload is enough -- no re-pasting
each time the zone set changes.

The header, the printed next steps, the README and the sample config all say
so, and all of them state that `merge: true` is required and that this needs a
tdns new enough to understand the map form.

Verified across both repos rather than by reading: real generated output was fed
through tdns's own `processConfigFile` as an opt-in include. The server's own
zone and policy survive alongside the generated ones (9 zones, 8 policies), and
`large-algorithms` unions to 5 rather than being replaced. The warning was
checked too: with a bare include the server's own zone is gone and tdns records
a clobber -- so the instruction to use `merge: true` is load-bearing, not
cautious phrasing.

## Retraction: the `usetls` default (2026-08-28)

An earlier version of this note said the first review was wrong to ask for
`usetls` to default to true, on the grounds that `UseTLS` is a plain `bool`
with no `SetDefault`, so an unset key decodes to false and `apirouters.go`
serves HTTP.

That was wrong, and the review was right. tdns injects the default into the
**raw map, before decoding**, in `decodeConfigMap`:

```go
// apiserver.usetls defaults to true, applied to the raw map so an absent
// key and an explicit `usetls: true` decode identically.
if apiserverMap, ok := configMap["apiserver"].(map[string]interface{}); ok {
    if _, explicitlySet := apiserverMap["usetls"]; !explicitlySet {
        apiserverMap["usetls"] = true
    }
}
```

That code has been on main since January. The mistake was looking at the Go
struct and at `SetDefault` and concluding from their silence; the default is
applied under the *YAML key name*, which neither of those searches would find.
A GitHub issue was filed against tdns on the strength of the wrong conclusion
and has been corrected.

The consequence for zonegen was real rather than theoretical. It unmarshals the
auth config itself instead of running tdns's loader, so an omitted `usetls:`
made it dial `http://` at an HTTPS listener — the same class of failure as the
bug F4 reported, with the handshake the other way round. `fromAuthConfig` now
pre-sets `UseTLS = true` before unmarshalling, matching `decodeConfigMap`.

The test that covered "TLS off" had *omitted* the key rather than writing
`usetls: false`, so it could not tell "explicitly off" from "relying on the
default". It now covers all three states separately.

Two further leftovers from the re-review are fixed alongside: the duplicated
comment in `newAddrPool`, and apex glue being a churn victim. The latter is
worth noting for how it was found — the first regression test for it passed
even with the fix removed, because at a low churn rate whether the glue is
picked is a property of the seed. Raising the churn to 100% makes every name a
victim and the test then fails without the fix, which is what a regression test
has to do to be worth having.
