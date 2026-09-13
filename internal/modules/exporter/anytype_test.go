package exporter

import (
	"testing"

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
