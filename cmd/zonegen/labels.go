/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Pronounceable, deterministic label generation.
 *
 * A zone with 100,000 names in it is something a human has to read: in a packet
 * capture, in a log line, in a failing test. "bacoli.temuza" can be read out
 * loud and typed from memory; a truncated SHA cannot. That is the whole reason
 * this file exists.
 *
 * Labels are derived from an index, not drawn at random, so the n-th name is
 * always the same name. Uniqueness is by construction rather than by keeping a
 * set: the index is written in bijective base-k over the syllable alphabet,
 * which -- unlike ordinary positional notation -- has exactly one
 * representation per number, so two indices can never collide.
 */

package main

import (
	"hash/fnv"
	"math/rand"
	"strings"
)

// The syllable alphabet. Deliberately small and free of the pairs that read
// badly or collide across languages; the point is legibility, not coverage.
var (
	labelCons = []string{
		"b", "d", "f", "g", "k", "l", "m", "n", "p", "r",
		"s", "t", "v", "z", "br", "tr", "st", "kr", "pl", "fl",
	}
	labelVows = []string{"a", "e", "i", "o", "u", "ae", "ea", "ou", "ia"}
)

// syllableCount is the radix: every syllable is one consonant plus one vowel.
// 20 x 9 = 180, so three syllables cover 5.8M distinct labels and four cover a
// billion -- far past any zone this tool will be asked to write.
var syllableCount = uint64(len(labelCons) * len(labelVows))

func syllable(d uint64) string {
	return labelCons[d/uint64(len(labelVows))] + labelVows[d%uint64(len(labelVows))]
}

// Label returns the n-th label. Successive n give successive labels of
// non-decreasing length: "ba", "be", ... then two syllables, then three.
//
// The bijective numeration is what makes this collision-free. In ordinary
// base-k the number 0 and the empty string both mean "nothing", so a
// fixed-minimum-length encoding maps several indices onto one string. Here each
// digit runs 1..k rather than 0..k-1, and every index has exactly one form.
func Label(n uint64) string {
	var syllables []string
	n++ // shift to the 1-based domain bijective numeration needs
	for n > 0 {
		n--
		syllables = append(syllables, syllable(n%syllableCount))
		n /= syllableCount
	}
	// Reverse: least-significant syllable was produced first, and reading them
	// in index order makes consecutive labels look consecutive.
	for i, j := 0, len(syllables)-1; i < j; i, j = i+1, j-1 {
		syllables[i], syllables[j] = syllables[j], syllables[i]
	}
	return strings.Join(syllables, "")
}

// LabelPath returns a name of the given depth below an origin, derived from n.
// Each level gets its own label, so the tree is deterministic and every
// intermediate name is itself a valid, derivable label -- which is what lets
// the caller decide whether to populate intermediates or leave them as empty
// non-terminals.
func LabelPath(n uint64, depth int, origin string) string {
	if depth < 1 {
		depth = 1
	}
	parts := make([]string, 0, depth)
	for d := 0; d < depth; d++ {
		// Mix the depth into the index so level 2 of name 5 is not the same
		// label as level 1 of name 5; without this every path reads "ba.ba.ba".
		parts = append(parts, Label(n*uint64(depth+1)+uint64(d)))
	}
	return strings.Join(parts, ".") + "." + origin
}

// seedFrom derives a PRNG seed from strings. Churn and record mixes are drawn
// randomly but must be REPRODUCIBLE: regenerating a zone from the same inputs
// has to produce the same zone, or every regeneration is a whole-file diff and
// the serial bump says nothing about what actually changed.
func seedFrom(parts ...string) int64 {
	h := fnv.New64a()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0}) // so ("ab","c") and ("a","bc") differ
	}
	return int64(h.Sum64() &^ (1 << 63))
}

// newRand returns the generator for one run, seeded from the run's identity.
func newRand(parts ...string) *rand.Rand {
	return rand.New(rand.NewSource(seedFrom(parts...)))
}
