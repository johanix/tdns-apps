package main

import (
	"context"
	"log"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// whoisResult carries one worker's whois outcome to the single DB writer.
type whoisResult struct {
	domain    string
	queriedAt time.Time
	err       error
	statuses  []string
	matched   bool
}

// ScanPending runs whois against every pending delegation for fetchID.
//
// Architecture: N whois workers produce results on a channel; a single
// dbwriter goroutine consumes the channel and writes to SQLite. This
// keeps SQLite strictly single-writer from the app's side, so there's
// no lock contention regardless of how many whois workers are in flight.
func ScanPending(ctx context.Context, cfg *Config, db *DB, fetchID int64) error {
	limiter := rate.NewLimiter(rate.Limit(cfg.Whois.RateLimit), cfg.Whois.Burst)
	timeout := time.Duration(cfg.Whois.TimeoutSec) * time.Second

	// Batch size of 5000: enough to keep workers busy without holding a long
	// read transaction open on SQLite.
	in, errCh := db.PendingDomains(ctx, fetchID, 5000)
	results := make(chan whoisResult, cfg.Whois.Concurrency*2)

	// Whois worker pool.
	var workerWg sync.WaitGroup
	for i := 0; i < cfg.Whois.Concurrency; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for domain := range in {
				if err := limiter.Wait(ctx); err != nil {
					return // ctx cancelled
				}
				queriedAt := time.Now().UTC()
				body, werr := WhoisQuery(ctx, cfg.Whois.Server, domain, timeout)
				r := whoisResult{domain: domain, queriedAt: queriedAt, err: werr}
				if werr == nil {
					r.statuses = ExtractStatuses(body)
					r.matched = MatchesAny(r.statuses, cfg.Report.MatchStatuses)
				}
				select {
				case <-ctx.Done():
					return
				case results <- r:
				}
			}
		}()
	}

	// Close results once all workers have finished.
	go func() {
		workerWg.Wait()
		close(results)
	}()

	// Single DB writer: sole writer to SQLite, no contention.
	var done, matched, errored int
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			log.Printf("scan interrupted: queried=%d matched=%d errors=%d", done, matched, errored)
			break loop
		case <-tick.C:
			log.Printf("scan progress: queried=%d matched=%d errors=%d", done, matched, errored)
		case r, ok := <-results:
			if !ok {
				log.Printf("scan complete: queried=%d matched=%d errors=%d", done, matched, errored)
				break loop
			}
			if err := db.RecordWhoisResult(ctx, fetchID, r.domain, r.queriedAt, r.err, r.statuses, r.matched); err != nil {
				log.Printf("db update failed for %s: %v", r.domain, err)
			}
			done++
			if r.err != nil {
				errored++
			}
			if r.matched {
				matched++
			}
		}
	}

	// Surface any error from the pending-domains streamer.
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
