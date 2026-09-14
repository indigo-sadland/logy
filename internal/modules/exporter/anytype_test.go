package exporter

import (
	"testing"
	"time"

	"github.com/indigo-sadland/logy/internal/storage"
)

func TestNormalizeAnytypeOptionsDefaultsServiceAliasKeys(t *testing.T) {
	opts := NormalizeAnytypeOptions(AnytypeOptions{
		AliasPropertyKey: "alias",
	})

	if opts.AssetAliasPropertyKey != "alias" {
		t.Fatalf("asset alias=%q; want alias", opts.AssetAliasPropertyKey)
	}
	if opts.ServiceAliasPropertyKey != "hostnames,alias" {
		t.Fatalf("service alias=%q; want hostnames,alias", opts.ServiceAliasPropertyKey)
	}
	if opts.AssetPortScannedPropertyKey != "port_scanned" {
		t.Fatalf("asset port scanned property=%q; want port_scanned", opts.AssetPortScannedPropertyKey)
	}
	if opts.AssetLastPortScanPropertyKey != "last_port_scan" {
		t.Fatalf("asset last port scan property=%q; want last_port_scan", opts.AssetLastPortScanPropertyKey)
	}
}

func TestAnytypeServicePropertiesOmitAliasFromCreatePayload(t *testing.T) {
	properties := anytypeServiceProperties(AnytypeOptions{
		ServiceAliasPropertyKey: "hostnames,alias",
		PortPropertyKey:         "port",
		StatePropertyKey:        "state",
		ServicePropertyKey:      "service",
		BannerPropertyKey:       "banner",
		EngagementPropertyKey:   "engagement",
		AssetPropertyKey:        "asset",
	}, "eng-1", "asset-1", []string{"api.example.com"}, storage.PortScanRecord{
		Port:     443,
		Protocol: "tcp",
		State:    "open",
		Service:  "https",
		Version:  "nginx",
	})

	for _, property := range properties {
		if property["key"] == "hostnames" || property["key"] == "alias" {
			t.Fatalf("unexpected service alias property: %v", properties)
		}
	}
}

func TestAnytypeAssetPropertiesIncludePortScanStatus(t *testing.T) {
	scannedAt := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	properties := anytypeAssetProperties(AnytypeOptions{
		AssetAliasPropertyKey:        "alias",
		AssetPortScannedPropertyKey:  "port_scanned",
		AssetLastPortScanPropertyKey: "last_port_scan",
		EngagementPropertyKey:        "engagement",
	}, "eng-1", []string{"api.example.com"}, &storage.PortScanTargetRecord{
		IP:        "203.0.113.10",
		Status:    "scanned",
		ScannedAt: scannedAt,
	})

	if got := propertyText(properties, "port_scanned"); got != "yes" {
		t.Fatalf("port_scanned=%q; want yes", got)
	}
	if got := propertyText(properties, "last_port_scan"); got != "2026-09-13T12:00:00Z" {
		t.Fatalf("last_port_scan=%q; want timestamp", got)
	}
}

func TestAnytypeAssetRequiredPropertiesOmitOptionalPortScanStatus(t *testing.T) {
	properties := anytypeAssetRequiredProperties(AnytypeOptions{
		AssetAliasPropertyKey:        "alias",
		AssetPortScannedPropertyKey:  "port_scanned",
		AssetLastPortScanPropertyKey: "last_port_scan",
		EngagementPropertyKey:        "engagement",
	}, "eng-1", []string{"api.example.com"})

	if got := propertyText(properties, "alias"); got != "api.example.com" {
		t.Fatalf("alias=%q; want api.example.com", got)
	}
	if got := propertyText(properties, "port_scanned"); got != "" {
		t.Fatalf("port_scanned=%q; want omitted", got)
	}
	if got := propertyText(properties, "last_port_scan"); got != "" {
		t.Fatalf("last_port_scan=%q; want omitted", got)
	}
}

func TestBuildAnytypeAssetsIncludesPortScanTargetsWithoutOpenPorts(t *testing.T) {
	scannedAt := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	assets := buildAnytypeAssets(nil, nil, []storage.PortScanTargetRecord{
		{
			Domain:    "example.com",
			IP:        "203.0.113.20",
			Scanner:   "nmap",
			Status:    "scanned",
			ScannedAt: scannedAt,
		},
	})

	if len(assets) != 1 {
		t.Fatalf("assets=%v; want one scan-target asset", assets)
	}
	if assets[0].IP != "203.0.113.20" {
		t.Fatalf("asset IP=%q; want 203.0.113.20", assets[0].IP)
	}
	if assets[0].ScanTarget == nil || !assets[0].ScanTarget.ScannedAt.Equal(scannedAt) {
		t.Fatalf("scan target=%v; want latest target", assets[0].ScanTarget)
	}
}

func TestServiceAliasPropertyKeysSplitsAndDeduplicates(t *testing.T) {
	got := serviceAliasPropertyKeys(" hostnames, alias,hostnames ")
	want := []string{"hostnames", "alias"}

	if len(got) != len(want) {
		t.Fatalf("keys=%v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys=%v; want %v", got, want)
		}
	}
}

func propertyText(properties []anytypeProperty, key string) string {
	for _, property := range properties {
		if property["key"] == key {
			return anytypeString(property["text"])
		}
	}
	return ""
}
