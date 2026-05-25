package resolver

import (
	"slices"
	"testing"
)

func TestParseVHostFinderOutputExtractsHostsAndIPs(t *testing.T) {
	raw := []byte(`
[200] api.example.com 1.1.1.1
found host=beta.example.com ip=2.2.2.2
noise that should be ignored
api.example.com duplicate 1.1.1.1
`)

	results := parseVHostFinderOutput(raw, []string{"api.example.com", "beta.example.com", "miss.example.com"}, []string{"1.1.1.1", "2.2.2.2"})
	if len(results) != 2 {
		t.Fatalf("results=%d; want 2", len(results))
	}
	if results[0].Subdomain != "api.example.com" {
		t.Fatalf("first subdomain=%q; want api.example.com", results[0].Subdomain)
	}
	if !slices.Equal(results[0].IPs, []string{"1.1.1.1"}) {
		t.Fatalf("api ips=%v; want [1.1.1.1]", results[0].IPs)
	}
	if results[1].Subdomain != "beta.example.com" {
		t.Fatalf("second subdomain=%q; want beta.example.com", results[1].Subdomain)
	}
	if !slices.Equal(results[1].IPs, []string{"2.2.2.2"}) {
		t.Fatalf("beta ips=%v; want [2.2.2.2]", results[1].IPs)
	}
}

func TestParseVHostFinderOutputMarksAliveWithoutIPsWhenOnlyHostAppears(t *testing.T) {
	raw := []byte("found only-host.example.com\n")

	results := parseVHostFinderOutput(raw, []string{"only-host.example.com"}, []string{"1.1.1.1"})
	if len(results) != 1 {
		t.Fatalf("results=%d; want 1", len(results))
	}
	if !results[0].Alive {
		t.Fatal("expected host to be marked alive")
	}
	if len(results[0].IPs) != 0 {
		t.Fatalf("ips=%v; want empty", results[0].IPs)
	}
}
