/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * SOA serial arithmetic.
 */

package main

import (
	"fmt"
	"time"
)

// nowFunc is a seam so tests can pin the clock; production always uses the
// real one.
var nowFunc = time.Now

// NewSerial returns the SOA serial for this run, in the conventional
// YYYYMMDDNN form, given whatever serial the zone carried before (0 if the zone
// is new).
//
// The counter half matters. An earlier version of this formatted the time as
// "2006010200" and relied on the trailing "00" being an hour -- but "00" is not
// a Go layout token, so it was emitted literally and EVERY run on a given day
// produced the same serial. Regenerating a zone twice in one day wrote new
// content under an unchanged serial, which no secondary would ever pick up and
// no journal would ever record. With --update rewriting a zone deliberately,
// that stops being a latent wart and becomes the whole feature failing.
//
// So: the datestamp is the floor, and a serial that has already reached today's
// floor is simply incremented. Monotonic across arbitrarily many runs per day,
// and still readable as a date on the first run of each day.
func NewSerial(now time.Time, previous uint32) uint32 {
	var floor uint32
	if _, err := fmt.Sscanf(now.UTC().Format("20060102"), "%d", &floor); err != nil {
		// An unformattable time is not a thing time.Time can be; fall back to
		// bumping rather than returning a zero serial.
		return previous + 1
	}
	floor *= 100
	if previous >= floor {
		return previous + 1
	}
	return floor
}
