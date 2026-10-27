package benchmark

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	rows := Results()
	if len(rows) > 0 {
		path, err := WriteCSVFile(rows)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "report: wrote %s (%d raw rows)\n", path, len(rows))
	}
	os.Exit(code)
}

func TestWriteCSVAggregatesAndSorts(t *testing.T) {
	raw := []Row{
		{Algorithm: "RC4", Mode: "stream", File: "doc", Op: "encrypt", NsPerOp: 30, MBPerSec: 3, CiphertextSize: 10, PlaintextSize: 10},
		{Algorithm: "AES-256", Mode: "GCM", File: "doc", Op: "decrypt", NsPerOp: 20, MBPerSec: 2, CiphertextSize: 26, PlaintextSize: 10, TamperDetected: true},
		{Algorithm: "AES-256", Mode: "GCM", File: "doc", Op: "decrypt", NsPerOp: 10, MBPerSec: 4, CiphertextSize: 26, PlaintextSize: 10, TamperDetected: true},
	}
	var output bytes.Buffer
	if err := WriteCSV(&output, raw); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&output).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("CSV rows = %d, want header plus 2 groups", len(records))
	}
	if got, want := strings.Join(records[0], ","), "algorithm,mode,file,op,ns/op,MB/s,ciphertext_size,tamper_detected,runs,ns_stdev"; got != want {
		t.Fatalf("CSV header = %q, want %q", got, want)
	}
	if records[1][0] != "AES-256" || records[1][1] != "GCM" {
		t.Fatalf("first group = %v, want AES-256/GCM", records[1][:2])
	}
	if records[1][4] != "15.00" || records[1][5] != "3.00" || records[1][8] != "2" || records[1][9] != "7.07" {
		t.Fatalf("aggregated values = %v, want mean ns/op 15, MB/s 3, 2 runs, sample stdev 7.07", records[1])
	}
	if records[2][0] != "RC4" || records[2][8] != "1" || records[2][9] != "0.00" {
		t.Fatalf("single-run group = %v, want RC4 with 1 run and zero stdev", records[2])
	}
}

func TestWriteCSVRejectsInconsistentGroup(t *testing.T) {
	rows := []Row{
		{Algorithm: "AES-256", Mode: "CBC", File: "doc", Op: "encrypt", CiphertextSize: 25, PlaintextSize: 10},
		{Algorithm: "AES-256", Mode: "CBC", File: "doc", Op: "encrypt", CiphertextSize: 26, PlaintextSize: 10},
	}
	if err := WriteCSV(io.Discard, rows); err == nil {
		t.Fatal("expected inconsistent ciphertext sizes to be rejected")
	}
}

func TestWriteCSVRejectsNilWriter(t *testing.T) {
	if err := WriteCSV(nil, nil); err == nil {
		t.Fatal("expected nil writer to be rejected")
	}
}
