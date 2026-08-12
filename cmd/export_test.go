package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/indigo-sadland/logy/internal/modules/exporter"
	"github.com/indigo-sadland/logy/internal/storage"
)

func TestLoadAnytypeExportDataAllowsPortScansWithoutSubdomains(t *testing.T) {
	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SavePortScans("example.com", []storage.PortScanRecord{
		{
			Domain:    "example.com",
			IP:        "203.0.113.10",
			Port:      443,
			Protocol:  "tcp",
			State:     "open",
			Service:   "https",
			ScannedAt: time.Now().UTC(),
		},
	}); err != nil {
		t.Fatalf("save port scans: %v", err)
	}

	data, err := loadAnytypeExportData(store, anytypeExportOptions{
		AnytypeOptions: exporter.AnytypeOptions{Domain: "example.com"},
	})
	if err != nil {
		t.Fatalf("loadAnytypeExportData: %v", err)
	}
	if len(data.subdomains) != 0 {
		t.Fatalf("subdomains=%v; want none", data.subdomains)
	}
	if len(data.scans) != 1 {
		t.Fatalf("scans=%v; want one scan", data.scans)
	}
	if data.scans[0].IP != "203.0.113.10" {
		t.Fatalf("scan IP=%q; want 203.0.113.10", data.scans[0].IP)
	}
}

func TestLoadAnytypeExportDataOnlyScansStillRequiresCommandRuns(t *testing.T) {
	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = loadAnytypeExportData(store, anytypeExportOptions{
		AnytypeOptions: exporter.AnytypeOptions{
			Domain:    "example.com",
			OnlyScans: true,
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no command run results for domain example.com") {
		t.Fatalf("error=%v; want missing command runs", err)
	}
}
