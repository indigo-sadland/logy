package cmd

import (
	"bytes"
	"github.com/indigo-sadland/logy/internal/modules/portscan"
	"github.com/indigo-sadland/logy/internal/storage"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildPortscanShowHostsGroupsByIP(t *testing.T) {
	t.Parallel()

	subdomains := []storage.SubdomainRecord{
		{Subdomain: "api.example.com", Resolved: true, IPs: []string{"1.1.1.1"}},
		{Subdomain: "www.example.com", Resolved: true, IPs: []string{"1.1.1.1"}},
		{Subdomain: "cdn.example.com", Resolved: true, IPs: []string{"2.2.2.2"}},
	}
	scans := []storage.PortScanRecord{
		{IP: "1.1.1.1", Port: 80, Protocol: "tcp", State: "open", Service: "http", Version: "nginx", ScannedAt: time.Now().UTC()},
		{IP: "2.2.2.2", Port: 443, Protocol: "tcp", State: "open", Service: "https", Version: "envoy", ScannedAt: time.Now().UTC()},
	}

	hosts := buildPortscanShowHosts(subdomains, scans)
	if len(hosts) != 2 {
		t.Fatalf("len(hosts)=%d; want 2", len(hosts))
	}
	if hosts[0].IP != "1.1.1.1" {
		t.Fatalf("first ip=%q; want 1.1.1.1", hosts[0].IP)
	}
	if !slices.Equal(hosts[0].Subdomains, []string{"api.example.com", "www.example.com"}) {
		t.Fatalf("subdomains=%v; want [api.example.com www.example.com]", hosts[0].Subdomains)
	}
	if len(hosts[0].Ports) != 1 || hosts[0].Ports[0].Port != 80 {
		t.Fatalf("ports=%v; want one port 80", hosts[0].Ports)
	}
}

func TestBuildPortscanShowHostsHandlesScansWithoutSubdomains(t *testing.T) {
	t.Parallel()

	scans := []storage.PortScanRecord{
		{IP: "1.1.1.1", Port: 443, Protocol: "tcp", State: "open", Service: "https", Version: "nginx", ScannedAt: time.Now().UTC()},
	}

	hosts := buildPortscanShowHosts(nil, scans)
	if len(hosts) != 1 {
		t.Fatalf("len(hosts)=%d; want 1", len(hosts))
	}
	if hosts[0].IP != "1.1.1.1" {
		t.Fatalf("ip=%q; want 1.1.1.1", hosts[0].IP)
	}
	if len(hosts[0].Subdomains) != 0 {
		t.Fatalf("subdomains=%v; want empty", hosts[0].Subdomains)
	}
}

func TestUniquePortscanIPsDeduplicatesAndSorts(t *testing.T) {
	t.Parallel()

	results := []portscan.Result{
		{IP: "2.2.2.2"},
		{IP: "1.1.1.1"},
		{IP: "2.2.2.2"},
		{IP: ""},
	}

	got := uniquePortscanIPs(results)
	want := []string{"1.1.1.1", "2.2.2.2"}
	if !slices.Equal(got, want) {
		t.Fatalf("ips=%v; want %v", got, want)
	}
}

func TestWritePortscanShowTextFormatsHosts(t *testing.T) {
	t.Parallel()

	hosts := []portscanShowHost{
		{
			IP: "172.20.17.192",
			Ports: []portscanShowPort{
				{Port: 135, Protocol: "tcp", Service: "msrpc", Version: "Microsoft Windows RPC"},
				{Port: 445, Protocol: "tcp", Service: "microsoft-ds?"},
				{Port: 5985, Protocol: "tcp", Service: "http", Version: "Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)"},
			},
		},
	}

	var buf bytes.Buffer
	if err := writePortscanShowText(&buf, hosts); err != nil {
		t.Fatalf("writePortscanShowText: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	want := "172.20.17.192\t135/tcp (msrpc Microsoft Windows RPC); 445/tcp (microsoft-ds?); 5985/tcp (http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP))"
	if got != want {
		t.Fatalf("got=%q; want %q", got, want)
	}
}

func TestWritePortscanShowTextFallsBackToState(t *testing.T) {
	t.Parallel()

	hosts := []portscanShowHost{
		{
			IP: "1.1.1.1",
			Ports: []portscanShowPort{
				{Port: 53, Protocol: "udp", State: "open"},
			},
		},
	}

	var buf bytes.Buffer
	if err := writePortscanShowText(&buf, hosts); err != nil {
		t.Fatalf("writePortscanShowText: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	want := "1.1.1.1\t53/udp (open)"
	if got != want {
		t.Fatalf("got=%q; want %q", got, want)
	}
}

func TestBuildPortscanPickCandidatesSkipsEmptyTargets(t *testing.T) {
	t.Parallel()

	targets := []storage.SavedScanTarget{
		{Label: "api.example.com", Kind: "hostname", IPs: []string{"1.1.1.1"}},
		{Label: "", Kind: "ip", IPs: []string{"2.2.2.2"}},
		{Label: "empty.example.com", Kind: "hostname"},
	}

	got := buildPortscanPickCandidates(targets)
	want := []portscanPickCandidate{
		{Label: "api.example.com", Kind: "hostname", IPs: []string{"1.1.1.1"}},
	}
	if !slices.EqualFunc(got, want, func(a portscanPickCandidate, b portscanPickCandidate) bool {
		return a.Label == b.Label && a.Kind == b.Kind && slices.Equal(a.IPs, b.IPs)
	}) {
		t.Fatalf("got=%v; want %v", got, want)
	}
}

func TestFilterPortscanPickCandidatesMatchesHostnameAndIP(t *testing.T) {
	t.Parallel()

	candidates := []portscanPickCandidate{
		{Label: "api.example.com", Kind: "hostname", IPs: []string{"1.1.1.1"}},
		{Label: "admin.example.com", Kind: "hostname", IPs: []string{"2.2.2.2"}},
		{Label: "10.20.30.40", Kind: "ip", IPs: []string{"10.20.30.40"}},
	}

	gotHost := filterPortscanPickCandidates(candidates, "adm")
	if len(gotHost) != 1 || gotHost[0].Label != "admin.example.com" {
		t.Fatalf("hostname filter result=%v", gotHost)
	}

	gotIP := filterPortscanPickCandidates(candidates, "20.30")
	if len(gotIP) != 1 || gotIP[0].Label != "10.20.30.40" {
		t.Fatalf("ip filter result=%v", gotIP)
	}

	gotAll := filterPortscanPickCandidates(candidates, "")
	if !slices.EqualFunc(gotAll, candidates, func(a portscanPickCandidate, b portscanPickCandidate) bool {
		return a.Label == b.Label && a.Kind == b.Kind && slices.Equal(a.IPs, b.IPs)
	}) {
		t.Fatalf("all result=%v; want %v", gotAll, candidates)
	}
}

func TestFindSavedScanTargetMatchesLabelCaseInsensitively(t *testing.T) {
	t.Parallel()

	targets := []storage.SavedScanTarget{
		{Label: "api.example.com", Kind: "hostname", IPs: []string{"1.1.1.1"}},
		{Label: "10.10.10.10", Kind: "ip", IPs: []string{"10.10.10.10"}},
	}

	got, err := findSavedScanTarget(targets, "API.EXAMPLE.COM")
	if err != nil {
		t.Fatalf("findSavedScanTarget hostname: %v", err)
	}
	if got.Label != "api.example.com" {
		t.Fatalf("label=%q; want api.example.com", got.Label)
	}

	got, err = findSavedScanTarget(targets, "10.10.10.10")
	if err != nil {
		t.Fatalf("findSavedScanTarget ip: %v", err)
	}
	if got.Kind != "ip" {
		t.Fatalf("kind=%q; want ip", got.Kind)
	}
}

func TestFindSavedScanTargetReturnsErrorWhenMissing(t *testing.T) {
	t.Parallel()

	_, err := findSavedScanTarget([]storage.SavedScanTarget{
		{Label: "api.example.com", Kind: "hostname", IPs: []string{"1.1.1.1"}},
	}, "missing.example.com")
	if err == nil {
		t.Fatal("expected error for missing target")
	}
}
