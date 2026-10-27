package benchmark

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

type resultKey struct {
	algorithm string
	mode      string
	file      string
	op        string
}

type resultGroup struct {
	key  resultKey
	rows []Row
}

// WriteCSV aggregates raw Row values by (Algorithm, Mode, File, Op) and writes
// one CSV row per group. Columns: algorithm,mode,file,op,ns/op,MB/s,
// ciphertext_size,tamper_detected,runs,ns_stdev.
//
// ns/op is the arithmetic mean over the group's runs; ns_stdev is the sample
// standard deviation (0 when runs==1). MB/s is the mean plaintext throughput.
// CiphertextSize, PlaintextSize, and TamperDetected must be constant within a
// group; if they are not, return an error (this indicates a harness bug).
func WriteCSV(w io.Writer, raw []Row) error {
	if w == nil {
		return errors.New("benchmark: WriteCSV: nil writer")
	}

	groupsByKey := make(map[resultKey]*resultGroup)
	for _, row := range raw {
		key := resultKey{
			algorithm: row.Algorithm,
			mode:      row.Mode,
			file:      row.File,
			op:        row.Op,
		}
		group := groupsByKey[key]
		if group == nil {
			group = &resultGroup{key: key}
			groupsByKey[key] = group
		} else {
			first := group.rows[0]
			if first.CiphertextSize != row.CiphertextSize ||
				first.PlaintextSize != row.PlaintextSize ||
				first.TamperDetected != row.TamperDetected {
				return fmt.Errorf(
					"benchmark: WriteCSV: inconsistent values for (%q, %q, %q, %q)",
					row.Algorithm, row.Mode, row.File, row.Op,
				)
			}
		}
		group.rows = append(group.rows, row)
	}

	groups := make([]*resultGroup, 0, len(groupsByKey))
	for _, group := range groupsByKey {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i].key, groups[j].key
		if a.algorithm != b.algorithm {
			return a.algorithm < b.algorithm
		}
		if a.mode != b.mode {
			return a.mode < b.mode
		}
		if a.file != b.file {
			return a.file < b.file
		}
		return a.op < b.op
	})

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"algorithm", "mode", "file", "op", "ns/op", "MB/s",
		"ciphertext_size", "tamper_detected", "runs", "ns_stdev",
	}); err != nil {
		return fmt.Errorf("benchmark: WriteCSV: write header: %w", err)
	}

	for _, group := range groups {
		first := group.rows[0]
		var nsMean, mbpsMean float64
		for _, row := range group.rows {
			nsMean += row.NsPerOp
			mbpsMean += row.MBPerSec
		}
		count := float64(len(group.rows))
		nsMean /= count
		mbpsMean /= count

		var squaredDiffs float64
		if len(group.rows) > 1 {
			for _, row := range group.rows {
				diff := row.NsPerOp - nsMean
				squaredDiffs += diff * diff
			}
			squaredDiffs /= float64(len(group.rows) - 1)
		}

		record := []string{
			first.Algorithm,
			first.Mode,
			first.File,
			first.Op,
			fmt.Sprintf("%.2f", nsMean),
			fmt.Sprintf("%.2f", mbpsMean),
			fmt.Sprintf("%d", first.CiphertextSize),
			fmt.Sprintf("%t", first.TamperDetected),
			fmt.Sprintf("%d", len(group.rows)),
			fmt.Sprintf("%.2f", squaredDiffsToStdev(squaredDiffs)),
		}
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("benchmark: WriteCSV: write record: %w", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("benchmark: WriteCSV: flush CSV: %w", err)
	}
	return nil
}

func squaredDiffsToStdev(variance float64) float64 {
	// Sqrt is kept local through a simple Newton iteration to avoid adding
	// imports beyond the report's standard-library contract.
	if variance <= 0 {
		return 0
	}
	x := variance
	for i := 0; i < 32; i++ {
		x = (x + variance/x) / 2
	}
	return x
}

// WriteCSVFile writes WriteCSV output to
// <this package dir>/results/<UTC timestamp>.csv and returns the path.
// It creates results/ if missing.
func WriteCSVFile(raw []Row) (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("benchmark: WriteCSVFile: locating package directory failed")
	}
	resultsDir := filepath.Join(filepath.Dir(thisFile), "results")
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return "", fmt.Errorf("benchmark: WriteCSVFile: create results directory: %w", err)
	}
	name := time.Now().UTC().Format("2006-01-02T15-04-05Z") + ".csv"
	path := filepath.Join(resultsDir, name)
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("benchmark: WriteCSVFile: create file: %w", err)
	}
	if err := WriteCSV(file, raw); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("benchmark: WriteCSVFile: close file: %w", err)
	}
	return path, nil
}
