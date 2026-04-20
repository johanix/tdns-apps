package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func OpenDB(path string) (*DB, error) {
	// WAL lets concurrent readers (e.g. 'status'/'report' commands) run
	// alongside the scan writer. The app funnels all writes through a
	// single dbwriter goroutine, so no app-level lock contention exists.
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)",
		path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pinging %s: %w", path, err)
	}
	db := &DB{conn: conn}
	if err := db.ensureSchema(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func (d *DB) Close() error { return d.conn.Close() }

func (d *DB) ensureSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS zone_fetches (
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			zone              TEXT    NOT NULL,
			source            TEXT    NOT NULL,
			serial            INTEGER,
			fetched_at        TEXT    NOT NULL,
			delegation_count  INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS delegations (
			fetch_id          INTEGER NOT NULL,
			domain            TEXT    NOT NULL,
			whois_queried_at  TEXT,
			whois_error       TEXT,
			status_codes      TEXT,
			matched           INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (fetch_id, domain),
			FOREIGN KEY (fetch_id) REFERENCES zone_fetches(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending
			ON delegations(fetch_id, whois_queried_at)
			WHERE whois_queried_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_matches
			ON delegations(fetch_id, matched)`,
	}
	for _, s := range stmts {
		if _, err := d.conn.Exec(s); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}
	return nil
}

// ZoneFetch represents a row in zone_fetches.
type ZoneFetch struct {
	ID              int64
	Zone            string
	Source          string
	Serial          uint32
	FetchedAt       time.Time
	DelegationCount int
}

// StartFetch opens a new zone_fetches row and returns its id.
func (d *DB) StartFetch(ctx context.Context, zone, source string, serial uint32) (int64, error) {
	res, err := d.conn.ExecContext(ctx,
		`INSERT INTO zone_fetches (zone, source, serial, fetched_at) VALUES (?, ?, ?, ?)`,
		zone, source, serial, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("insert zone_fetches: %w", err)
	}
	return res.LastInsertId()
}

// InsertDelegations bulk-inserts delegation names for a fetch. Uses a single
// transaction for throughput; caller passes all names at once (reasonable for
// up to ~2M names).
func (d *DB) InsertDelegations(ctx context.Context, fetchID int64, domains []string) error {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO delegations (fetch_id, domain) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, dom := range domains {
		if _, err := stmt.ExecContext(ctx, fetchID, dom); err != nil {
			return fmt.Errorf("insert %s: %w", dom, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE zone_fetches SET delegation_count = (SELECT COUNT(*) FROM delegations WHERE fetch_id = ?) WHERE id = ?`,
		fetchID, fetchID); err != nil {
		return fmt.Errorf("update count: %w", err)
	}

	return tx.Commit()
}

// LatestFetchID returns the most recent fetch_id for the given zone,
// or sql.ErrNoRows if no fetches exist.
func (d *DB) LatestFetchID(ctx context.Context, zone string) (int64, error) {
	var id int64
	err := d.conn.QueryRowContext(ctx,
		`SELECT id FROM zone_fetches WHERE zone = ? ORDER BY id DESC LIMIT 1`,
		zone).Scan(&id)
	return id, err
}

// GetFetch returns a zone_fetches row by id.
func (d *DB) GetFetch(ctx context.Context, id int64) (*ZoneFetch, error) {
	var f ZoneFetch
	var fetchedAt string
	err := d.conn.QueryRowContext(ctx,
		`SELECT id, zone, source, COALESCE(serial, 0), fetched_at, delegation_count
		 FROM zone_fetches WHERE id = ?`, id).
		Scan(&f.ID, &f.Zone, &f.Source, &f.Serial, &fetchedAt, &f.DelegationCount)
	if err != nil {
		return nil, err
	}
	f.FetchedAt, _ = time.Parse(time.RFC3339, fetchedAt)
	return &f, nil
}

// PendingDomains streams domains whose whois hasn't been queried yet for
// a given fetch, in batches. The returned channel is closed when the stream
// ends; any error is sent on errCh.
func (d *DB) PendingDomains(ctx context.Context, fetchID int64, batch int) (<-chan string, <-chan error) {
	out := make(chan string, batch)
	errCh := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errCh)

		var lastDomain string
		for {
			rows, err := d.conn.QueryContext(ctx,
				`SELECT domain FROM delegations
				 WHERE fetch_id = ? AND whois_queried_at IS NULL AND domain > ?
				 ORDER BY domain LIMIT ?`,
				fetchID, lastDomain, batch)
			if err != nil {
				errCh <- fmt.Errorf("pending query: %w", err)
				return
			}
			n := 0
			for rows.Next() {
				var dom string
				if err := rows.Scan(&dom); err != nil {
					rows.Close()
					errCh <- fmt.Errorf("scan: %w", err)
					return
				}
				lastDomain = dom
				n++
				select {
				case <-ctx.Done():
					rows.Close()
					return
				case out <- dom:
				}
			}
			rows.Close()
			if n == 0 {
				return
			}
		}
	}()
	return out, errCh
}

// RecordWhoisResult updates a delegation row with whois result + match flag.
func (d *DB) RecordWhoisResult(ctx context.Context, fetchID int64, domain string, queriedAt time.Time, whoisErr error, statuses []string, matched bool) error {
	var errStr *string
	if whoisErr != nil {
		s := whoisErr.Error()
		errStr = &s
	}
	var m int
	if matched {
		m = 1
	}
	_, err := d.conn.ExecContext(ctx,
		`UPDATE delegations
		 SET whois_queried_at = ?, whois_error = ?, status_codes = ?, matched = ?
		 WHERE fetch_id = ? AND domain = ?`,
		queriedAt.UTC().Format(time.RFC3339), errStr, strings.Join(statuses, ","), m,
		fetchID, domain)
	return err
}

// Counts returns summary counts for a fetch: total, queried, matched, errored.
type FetchCounts struct {
	Total   int
	Queried int
	Matched int
	Errored int
}

func (d *DB) Counts(ctx context.Context, fetchID int64) (FetchCounts, error) {
	var c FetchCounts
	err := d.conn.QueryRowContext(ctx,
		`SELECT
			COUNT(*),
			SUM(CASE WHEN whois_queried_at IS NOT NULL THEN 1 ELSE 0 END),
			SUM(CASE WHEN matched = 1 THEN 1 ELSE 0 END),
			SUM(CASE WHEN whois_error IS NOT NULL THEN 1 ELSE 0 END)
		FROM delegations WHERE fetch_id = ?`,
		fetchID).Scan(&c.Total, &c.Queried, &c.Matched, &c.Errored)
	return c, err
}

// MatchedRows streams matched delegations for reporting.
type MatchedRow struct {
	Domain      string
	QueriedAt   time.Time
	StatusCodes string
}

func (d *DB) MatchedRows(ctx context.Context, fetchID int64) ([]MatchedRow, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT domain, whois_queried_at, status_codes
		 FROM delegations WHERE fetch_id = ? AND matched = 1
		 ORDER BY domain`, fetchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MatchedRow
	for rows.Next() {
		var r MatchedRow
		var queriedAt string
		if err := rows.Scan(&r.Domain, &queriedAt, &r.StatusCodes); err != nil {
			return nil, err
		}
		r.QueriedAt, _ = time.Parse(time.RFC3339, queriedAt)
		out = append(out, r)
	}
	return out, rows.Err()
}
