/*
 * tdns-sewhois - fetch a zone via AXFR, whois every delegation, list
 * domains matching specified EPP status codes.
 *
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var configPath string

func main() {
	root := &cobra.Command{
		Use:   appName,
		Short: "AXFR a zone, whois every delegation, report on EPP status matches",
	}
	root.PersistentFlags().StringVarP(&configPath, "config", "c",
		"tdns-sewhois.yaml", "path to config file")

	root.AddCommand(fetchCmd())
	root.AddCommand(scanCmd())
	root.AddCommand(reportCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadAndOpen() (*Config, *DB, context.Context, context.CancelFunc) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	db, err := OpenDB(cfg.DB.Path)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %v, shutting down (progress is persistent; rerun scan to resume)", sig)
		cancel()
	}()
	return cfg, db, ctx, cancel
}

func fetchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fetch",
		Short: "AXFR the zone and record its delegations in the DB",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, ctx, cancel := loadAndOpen()
			defer cancel()
			defer db.Close()

			log.Printf("AXFR %s from %s", cfg.Zone.Name, cfg.Zone.Source)
			t0 := time.Now()
			serial, delegations, err := FetchDelegations(cfg.Zone.Name, cfg.Zone.Source)
			if err != nil {
				return err
			}
			log.Printf("AXFR complete in %s: serial=%d delegations=%d",
				time.Since(t0).Round(time.Second), serial, len(delegations))

			fetchID, err := db.StartFetch(ctx, cfg.Zone.Name, cfg.Zone.Source, serial)
			if err != nil {
				return err
			}
			log.Printf("inserting %d delegations under fetch_id=%d", len(delegations), fetchID)

			if err := db.InsertDelegations(ctx, fetchID, delegations); err != nil {
				return err
			}
			log.Printf("fetch_id=%d ready; run '%s scan' to start whois queries", fetchID, appName)
			return nil
		},
	}
}

func scanCmd() *cobra.Command {
	var fetchID int64
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run whois against pending delegations (resumable)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, ctx, cancel := loadAndOpen()
			defer cancel()
			defer db.Close()

			if fetchID == 0 {
				id, err := db.LatestFetchID(ctx, cfg.Zone.Name)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return fmt.Errorf("no fetch found for zone %s; run '%s fetch' first",
							cfg.Zone.Name, appName)
					}
					return err
				}
				fetchID = id
			}

			f, err := db.GetFetch(ctx, fetchID)
			if err != nil {
				return fmt.Errorf("fetch_id=%d: %w", fetchID, err)
			}
			counts, err := db.Counts(ctx, fetchID)
			if err != nil {
				return err
			}
			log.Printf("scanning fetch_id=%d zone=%s fetched_at=%s total=%d already_queried=%d",
				f.ID, f.Zone, f.FetchedAt.Format(time.RFC3339), counts.Total, counts.Queried)

			return ScanPending(ctx, cfg, db, fetchID)
		},
	}
	cmd.Flags().Int64Var(&fetchID, "fetch-id", 0, "specific fetch_id to scan (default: latest for zone)")
	return cmd
}

func reportCmd() *cobra.Command {
	var (
		fetchID int64
		outPath string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Print domains matching configured EPP status codes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, ctx, cancel := loadAndOpen()
			defer cancel()
			defer db.Close()

			if fetchID == 0 {
				id, err := db.LatestFetchID(ctx, cfg.Zone.Name)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return fmt.Errorf("no fetch found for zone %s", cfg.Zone.Name)
					}
					return err
				}
				fetchID = id
			}

			rows, err := db.MatchedRows(ctx, fetchID)
			if err != nil {
				return err
			}

			w := os.Stdout
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}

			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.Domain,
					r.QueriedAt.Format(time.RFC3339), r.StatusCodes)
			}
			log.Printf("%d matching domains for fetch_id=%d", len(rows), fetchID)
			return nil
		},
	}
	cmd.Flags().Int64Var(&fetchID, "fetch-id", 0, "specific fetch_id to report on (default: latest for zone)")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "write to file (default: stdout)")
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show fetch/scan progress for the latest fetch of configured zone",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, db, ctx, cancel := loadAndOpen()
			defer cancel()
			defer db.Close()

			id, err := db.LatestFetchID(ctx, cfg.Zone.Name)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					fmt.Printf("no fetches for zone %s yet\n", cfg.Zone.Name)
					return nil
				}
				return err
			}
			f, err := db.GetFetch(ctx, id)
			if err != nil {
				return err
			}
			counts, err := db.Counts(ctx, id)
			if err != nil {
				return err
			}
			pending := counts.Total - counts.Queried
			fmt.Printf("fetch_id:         %d\n", f.ID)
			fmt.Printf("zone:             %s\n", f.Zone)
			fmt.Printf("source:           %s\n", f.Source)
			fmt.Printf("serial:           %d\n", f.Serial)
			fmt.Printf("fetched_at:       %s\n", f.FetchedAt.Format(time.RFC3339))
			fmt.Printf("delegations:      %d\n", counts.Total)
			fmt.Printf("queried:          %d\n", counts.Queried)
			fmt.Printf("pending:          %d\n", pending)
			fmt.Printf("matched:          %d\n", counts.Matched)
			fmt.Printf("whois errors:     %d\n", counts.Errored)
			return nil
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s %s (built %s)\n", appName, appVersion, appDate)
		},
	}
}
