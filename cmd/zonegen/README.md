# tdns-zonegen

Generates DNS zones of various shapes, together with their keys, and the
tdns-auth configuration to serve them.

One subcommand per kind of zone:

| | |
|---|---|
| `pqtree` | a parent with one child per KSK/ZSK algorithm pair — a DNSSEC algorithm testbed |
| `tree` | a delegated hierarchy of ordinary zones |
| `bigzone` | one zone with many names and a mix of rrtypes |
| `rpz` | a response-policy zone with many rules |

They differ only in deciding *what zones exist and what is in them*. Everything
after that is shared: create the keys, read back the DS, splice delegations into
parents, render, write atomically, emit the tdns-auth block.

Nothing here is PQ-specific. Algorithm pairs come from config, and everything
the tool knows about an algorithm comes from `dnssec-algorithms/registry`.

## Use

```sh
# Validate and describe, without contacting a server or writing a file.
tdns-zonegen bigzone --zone big.example. --count 1000 --plan

# A zone with 100,000 names, empty non-terminals and 25 delegations.
tdns-zonegen bigzone --zone big.example. --count 100000 \
    --types A,AAAA,MX,TXT,SRV,CNAME,CAA --max-labels 4 --ents --delegations 25

# An RPZ zone. Unsigned, so it needs no server and no config file at all.
tdns-zonegen rpz --zone rpz.example. --outfile /tmp/rpz.zone --count 10000 \
    --actions nxdomain,nodata,drop,passthru,redirect --triggers qname,nsdname,ip

# Churn 5% of that zone's rules and advance the serial.
tdns-zonegen rpz --zone rpz.example. --outfile /tmp/rpz.zone --update 5

# A three-level delegated hierarchy, signed.
tdns-zonegen tree --zone tree.example. --depth 3 --breadth 5

# The algorithm testbed. Its pairs come from zonegen.pqtree in the config.
tdns-zonegen pqtree --config tdns-zonegen.yaml
```

`--plan` works on every generator and changes nothing.

## Signing is per generator

A zone with no DNSSEC policy is unsigned, and an unsigned set **never contacts
the keystore** — so `rpz`, and `bigzone --unsigned`, run with no API connection
and no config file. Where a generator does sign, `--ksk` and `--zsk` choose the
algorithms; `pqtree` takes a pair per child from config instead.

## Why it creates the keys

For the signed generators the keys are created in the tdns-auth keystore
*before* the zone files are written, which is what lets DS records go straight
into the parent.

The alternative — let the zones mint their own keys at first load, then scrape
the DS out of DNS and rewrite the parent — is what the python generator this
replaces did, in two passes with a live-but-undelegatable window in between. A
zone whose keys are already in the keystore adopts them at load time instead of
generating new ones, so one pass is enough.

Creating a key needs the server. Computing a DS does not: it is a digest over
the owner name and the DNSKEY rdata, so this binary handles MLDSA87 without
linking a single PQ algorithm. Pure Go, no cgo.

Key creation is idempotent. A zone that already has an active KSK and ZSK of the
right algorithms gets no new keys; one that has an active key of the *wrong*
algorithm is an error rather than a second key, because tdns-auth would refuse
such a zone at load and adding a key would only make that harder to read.
`--files-only` regenerates files from keys already in the keystore;
`--keys-only` does the reverse.

## Reaching the server

The connection details usually already exist on the host, so they need not be
written a third time here:

```sh
tdns-zonegen tree --tdns-auth /etc/tdns/tdns-auth.yaml ...   # derive from the server's config
tdns-zonegen tree --tdns-cli  /etc/tdns/tdns-cli.yaml  ...   # lift a client config
```

With neither, `/etc/tdns/tdns-cli.yaml` and then `/etc/tdns/tdns-auth.yaml` are
tried, and an `apiservers:` block in this tool's own config beats discovery. A
`tdns-cli.yaml` usually declares several servers; the authoritative one is
conventionally `tdns-server`, and `--apiserver` picks another. Several
candidates with no conventional name is a refusal, not a guess.

However it resolves, the resolution is printed before any key is created.

## Generated zones are legal

A random rrtype mix does not give that for free, so:

- a name chosen for CNAME gets **only** a CNAME, and is never a parent;
- NS is never in the random mix — it is a delegation, not a record type you
  sprinkle — so it comes from `--delegations`, which places NS plus glue and
  nothing else at that name;
- occluded data below a delegation is generated **on purpose**, one name per
  delegation: legal, realistic, and exactly what a signer must not sign.

Names are pronounceable rather than hashes (`bacoli.temuza`), because a
100,000-name zone is something a human reads in a capture or a log. Generation
is deterministic: the same flags always produce the same zone, so a regenerate
is a small diff rather than a whole-file one.

## Churning a zone with `--update`

`--update N` rewrites an existing zone file, changing roughly N percent of it —
for fixtures that move, such as an RPZ zone whose rules change every few
minutes, or a large zone that produces a small IXFR.

The zone file *is* the state, so it works on a file that has been hand-edited,
and refuses a file this tool did not write unless `--force` is given. Churn is
split between removing, changing and adding, with adds and removes balanced so
repeated updates neither grow nor shrink the zone; delegations are held out of
it. It is seeded from the zone name and the serial it replaces, so a given input
file always produces the same next file — a chain of updates is a replayable
sequence of deltas rather than a random walk.

`--update` is available on `bigzone` and `rpz`. It is deliberately not on
`pqtree` or `tree`, where churning a delegation would mean DS changes and key
operations.

## Configuration

Shape goes on the command line; the config holds only what is the same for every
run on a host — output paths, the API connection, and the defaults every zone
inherits (TTL, SOA timers, zone declaration type/store/options). `pqtree` is the
exception: its list of algorithm pairs lives in `zonegen.pqtree`, being too
structured for a command line and not something that varies between runs.

See `tdns-zonegen.sample.yaml`. Every algorithm pair is checked against
`dnssec-algorithms/registry` at config-load time: an unknown algorithm, or a
KSK-only one asked to serve as a ZSK, is refused there rather than by tdns-auth
at zone load. `large_algorithms` is derived from each algorithm's key and
signature sizes rather than hand-listed.

## After generating

The tool stops short of three things, deliberately:

1. **Merging the config block** into the tdns-auth config. It is emitted as a
   block to merge, not a file to `include:` — tdns-auth's include merge replaces
   list-valued keys wholesale, so an included file carrying `zones:` would
   silently replace every other zone the server has. (tdns is gaining opt-in
   merging; once that lands this can become an `include:` with `merge: true`.)
2. **Adding the delegation** to the parent of whatever it generated.
3. **Exporting the keys.** Run
   `tdns-cli auth keystore dnssec bulk-export --dest <keydir> --zones <parent>`
   and commit the result, so a rebuilt host restores the same keys and every
   committed DS stays valid.

## Packaging

tdns-apps ships a **single** NetBSD binary package for all its apps, not one per
app:

```sh
make -C .. pkg        # as root, on a NetBSD host -> tdns-apps-<version>.tgz
```

It contains `/usr/local/bin/tdns-zonegen` and
`/etc/tdns/tdns-zonegen.sample.yaml`. Adding an app means adding it to
`PKG_APPS` and its installed files to `PKG_FILES` in `../Makefile`.
