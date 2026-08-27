/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Record expansion and the atomic file write. The rendering that used to live
 * here moved to zoneset.go once more than one generator needed it.
 */

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/miekg/dns"
)

// expandRecord parses one config-supplied record against its zone origin and
// returns it fully qualified. Shared with config validation so the check and
// the output cannot disagree about what a record means.
func expandRecord(origin, rec string, ttl uint32) (string, error) {
	rr, err := dns.NewRR(fmt.Sprintf("$ORIGIN %s\n$TTL %d\n%s", origin, ttl, rec))
	if err != nil {
		return "", err
	}
	if rr == nil {
		return "", fmt.Errorf("no record")
	}
	return rr.String(), nil
}

// writeFile writes atomically via temp+rename, so a crash or a full disk
// cannot leave a half-written zone file that the server would happily load.
func writeFile(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating %s: %v", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("temp file in %s: %v", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func(e error) error { tmp.Close(); os.Remove(tmpPath); return e }
	if _, err := tmp.WriteString(content); err != nil {
		return cleanup(fmt.Errorf("writing %s: %v", tmpPath, err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("syncing %s: %v", tmpPath, err))
	}
	if err := tmp.Chmod(0644); err != nil {
		return cleanup(fmt.Errorf("chmod %s: %v", tmpPath, err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing %s: %v", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming to %s: %v", path, err)
	}
	return nil
}
