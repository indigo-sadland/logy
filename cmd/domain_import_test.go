package cmd

import (
	"encoding/json"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"github.com/indigo-sadland/logy/internal/storage"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestParseDomainImportSupportsHostsAndIPs(t *testing.T) {
	t.Parallel()

	input := strings.NewReader(`
# comment
api.example.com
1.2.3.4
cdn.example.com, 2.2.2.2, 2001:db8::1
api.other.com
`)

	got, err := parseDomainImport(input, "example.com", "import")
	if err != nil {
		t.Fatalf("parseDomainImport: %v", err)
	}

	if got.TotalLines != 6 {
		t.Fatalf("total lines=%d; want 6", got.TotalLines)
	}
	if got.Skipped != 2 {
		t.Fatalf("skipped=%d; want 2", got.Skipped)
	}
	if !reflect.DeepEqual(got.OutOfScope, []string{"api.other.com"}) {
		t.Fatalf("out_of_scope=%v; want [api.other.com]", got.OutOfScope)
	}

	wantEntries := []discovery.Entry{
		{Subdomain: "1.2.3.4", Sources: []string{"import"}},
		{Subdomain: "api.example.com", Sources: []string{"import"}},
		{Subdomain: "cdn.example.com", Sources: []string{"import"}},
	}
	if !reflect.DeepEqual(got.Entries, wantEntries) {
		t.Fatalf("entries=%v; want %v", got.Entries, wantEntries)
	}

	wantResolutions := []resolver.Result{
		{Subdomain: "1.2.3.4", IPs: []string{"1.2.3.4"}, Alive: true},
		{Subdomain: "cdn.example.com", IPs: []string{"2.2.2.2", "2001:db8::1"}, Alive: true},
	}
	if !reflect.DeepEqual(got.Resolutions, wantResolutions) {
		t.Fatalf("resolutions=%v; want %v", got.Resolutions, wantResolutions)
	}
}

func TestMergeImportedResolutionsPreservesExistingIPs(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"subfinder"}},
		{Subdomain: "1.2.3.4", Sources: []string{"manual"}},
	}); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
		{Subdomain: "1.2.3.4", IPs: []string{"1.2.3.4"}, Alive: true},
	}); err != nil {
		t.Fatalf("save resolutions: %v", err)
	}

	got, err := mergeImportedResolutions(store, "example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"2.2.2.2"}, Alive: true},
		{Subdomain: "1.2.3.4", IPs: []string{"1.2.3.4"}, Alive: true},
	})
	if err != nil {
		t.Fatalf("mergeImportedResolutions: %v", err)
	}

	want := []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1", "2.2.2.2"}, Alive: true},
		{Subdomain: "1.2.3.4", IPs: []string{"1.2.3.4"}, Alive: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("results=%v; want %v", got, want)
	}
}

func TestParseDomainImportLineSupportsBareIP(t *testing.T) {
	t.Parallel()

	host, ips := parseDomainImportLine(" 2001:db8::1 ")
	if host != "2001:db8::1" {
		t.Fatalf("host=%q; want 2001:db8::1", host)
	}
	if !reflect.DeepEqual(ips, []string{"2001:db8::1"}) {
		t.Fatalf("ips=%v; want [2001:db8::1]", ips)
	}
}

func TestImportedHostsNeedingResolutionSkipsIPsAndImportedResolvedHosts(t *testing.T) {
	t.Parallel()

	got := importedHostsNeedingResolution(domainImportResult{
		Entries: []discovery.Entry{
			{Subdomain: "api.example.com"},
			{Subdomain: "cdn.example.com"},
			{Subdomain: "1.2.3.4"},
		},
		Resolutions: []resolver.Result{
			{Subdomain: "cdn.example.com", IPs: []string{"2.2.2.2"}, Alive: true},
			{Subdomain: "1.2.3.4", IPs: []string{"1.2.3.4"}, Alive: true},
		},
	})

	want := []string{"api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts=%v; want %v", got, want)
	}
}

func TestRunDomainImportAutoResolvesPlainHosts(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "recon.db")
	importPath := filepath.Join(dir, "targets.txt")
	resolversPath := filepath.Join(dir, "resolvers.txt")
	dnsxPath := filepath.Join(dir, "fake-dnsx.sh")
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(importPath, []byte("api.example.com\ncdn.example.com,2.2.2.2\n"), 0o644); err != nil {
		t.Fatalf("write import file: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("write resolvers file: %v", err)
	}
	script := `#!/bin/sh
input=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-l" ]; then
    input="$2"
    shift 2
    continue
  fi
  shift
done
while IFS= read -r host; do
  case "$host" in
    api.example.com)
      printf '%s\n' '{"host":"api.example.com","a":["1.1.1.1"]}'
      ;;
  esac
done < "$input"
`
	if err := os.WriteFile(dnsxPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake dnsx: %v", err)
	}
	configYAML := `
database:
  path: ` + dbPath + `
discovery:
  tools:
    - subfinder
resolver:
  binary: ` + dnsxPath + `
  workers: 10
  timeout: 4s
  resolvers_file: ` + resolversPath + `
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	domainImportFile = importPath
	domainImportSource = "import"

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.Flags().String("domain", "example.com", "")
	cmd.Flags().String("config", configPath, "")
	if err := cmd.Flags().Set("domain", "example.com"); err != nil {
		t.Fatalf("set domain: %v", err)
	}
	if err := cmd.Flags().Set("config", configPath); err != nil {
		t.Fatalf("set config: %v", err)
	}

	stdoutPath := filepath.Join(dir, "stdout.json")
	stdoutFile, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	defer stdoutFile.Close()
	originalStdout := os.Stdout
	os.Stdout = stdoutFile
	defer func() { os.Stdout = originalStdout }()

	if err := runDomainImport(cmd); err != nil {
		t.Fatalf("runDomainImport: %v", err)
	}
	if err := stdoutFile.Close(); err != nil {
		t.Fatalf("close stdout file: %v", err)
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	records, err := store.SubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("subdomains by domain: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records)=%d; want 2", len(records))
	}
	if records[0].Subdomain != "api.example.com" || !records[0].Resolved || !reflect.DeepEqual(records[0].IPs, []string{"1.1.1.1"}) {
		t.Fatalf("api record=%+v", records[0])
	}
	if records[1].Subdomain != "cdn.example.com" || !records[1].Resolved || !reflect.DeepEqual(records[1].IPs, []string{"2.2.2.2"}) {
		t.Fatalf("cdn record=%+v", records[1])
	}

	rawSummary, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary struct {
		AutoResolved int `json:"auto_resolved"`
		Resolved     int `json:"resolved"`
		Unresolved   int `json:"unresolved"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("unmarshal summary: %v\nraw=%s", err, rawSummary)
	}
	if summary.AutoResolved != 1 || summary.Resolved != 2 || summary.Unresolved != 0 {
		t.Fatalf("summary=%+v; want auto_resolved=1 resolved=2 unresolved=0", summary)
	}
}
