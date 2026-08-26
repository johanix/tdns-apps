# tdns-zonegen

Generates a delegated zone tree in which every child zone is signed with a
different KSK/ZSK algorithm pair — the shape of a DNSSEC algorithm testbed.

It was written to replace a python generator that built one such testbed by
hand, and to make that arrangement reproducible somewhere other than the
machine it grew on.
Nothing about it is PQ-specific: the pairs come from config, and everything the
tool knows about an algorithm comes from the algorithm registry.

## What it produces

For a parent `pq.example.` and a list of pairs:

- **one zone file per child**, `<ksk>-<zsk>.pq.example.`, each with a
  self-describing apex TXT (`KSK=MLDSA87 (201) ZSK=ED25519 (15)`);
- **the parent zone file**, delegations and **DS records already in it**;
- **a tdns-auth config block** — one DNSSEC policy per pair, plus the derived
  `split_algorithms` and `large_algorithms`, plus a zone declaration each;
- **the delegation snippet** for the parent of the tree, printed for the
  operator to paste. The tool never touches that zone: it usually belongs to a
  different nameserver entirely.

## Why it creates the keys

The keys are created in the tdns-auth keystore *before* the zone files are
written, which is what lets the DS records go straight into the parent.

The alternative — let the zones mint their own keys at first load, then scrape
the DS out of DNS and rewrite the parent — is what the python generator did, in
two passes with a live-but-undelegatable window in between. A zone whose keys
are already in the keystore adopts them at load time instead of generating new
ones, so one pass is enough.

Creating a key needs the server. Computing a DS does not: it is a digest over
the owner name and the DNSKEY rdata, so this binary handles MLDSA87 without
linking a single PQ algorithm. It is pure Go, no cgo.

## Use

```sh
# Validate the config and show the tree. No server, no writes.
tdns-zonegen plan --config tdns-zonegen.yaml

# Create the keys and write everything.
tdns-zonegen generate --config tdns-zonegen.yaml

# Re-print the delegation snippet for the parent of the tree.
tdns-zonegen delegation --config tdns-zonegen.yaml
```

`generate` is idempotent: a zone that already has an active KSK and ZSK of the
configured algorithms gets no new keys. A zone that has an active key of the
*wrong* algorithm is an error rather than a second key — tdns-auth would refuse
such a zone at load time, and adding a key would only make that harder to read.

`--files-only` regenerates the files from keys already in the keystore;
`--keys-only` does the reverse.

## Configuration

See `tdns-zonegen.sample.yaml`. Every pair is checked against
`dnssec-algorithms/registry` at config-load time: an unknown algorithm, or a
KSK-only one asked to serve as a ZSK, is refused there rather than by tdns-auth
at zone load. `large_algorithms` is derived from each algorithm's key and
signature sizes rather than hand-listed.

## After generating

The tool stops short of three things, deliberately:

1. **Merging the config block** into the tdns-auth config. It is emitted as a
   block to merge, not a file to `include:` — tdns-auth's include merge
   replaces list-valued keys wholesale, so an included file carrying `zones:`
   would silently replace every other zone the server has.
2. **Adding the delegation** to the parent of the tree.
3. **Exporting the keys.** Run
   `tdns-cli auth keystore dnssec bulk-export --dest <keydir> --zones <parent>`
   and commit the result, so a rebuilt host restores the same keys and every
   committed DS stays valid.
