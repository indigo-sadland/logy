package storage

import (
	"database/sql"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestSaveDiscoveriesAndResolutionsCountsResolvedAndUnresolved(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	entries := []discovery.Entry{
		{Subdomain: "a.example.com", Sources: []string{"subfinder"}},
		{Subdomain: "b.example.com", Sources: []string{"amass"}},
		{Subdomain: "c.example.com", Sources: []string{"subfinder", "amass"}},
	}
	if err := store.SaveDiscoveries("example.com", entries); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}

	results := []resolver.Result{
		{Subdomain: "a.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
		{Subdomain: "b.example.com", Error: "no such host"},
	}
	if err := store.SaveResolutions("example.com", results); err != nil {
		t.Fatalf("save resolutions: %v", err)
	}

	resolved, unresolved, err := store.CountByResolution("example.com")
	if err != nil {
		t.Fatalf("count by resolution: %v", err)
	}

	if resolved != 1 {
		t.Fatalf("resolved=%d; want 1", resolved)
	}
	if unresolved != 2 {
		t.Fatalf("unresolved=%d; want 2", unresolved)
	}
}

func TestSaveDiscoveriesPreservesFirstSeenAndUpdatesLastSeen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"subfinder"}},
	}); err != nil {
		t.Fatalf("save discoveries #1: %v", err)
	}

	firstRecords, err := store.SubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("subdomains by domain #1: %v", err)
	}

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"amass", "subfinder"}},
	}); err != nil {
		t.Fatalf("save discoveries #2: %v", err)
	}

	secondRecords, err := store.SubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("subdomains by domain #2: %v", err)
	}

	if !secondRecords[0].FirstSeenAt.Equal(firstRecords[0].FirstSeenAt) {
		t.Fatal("expected first_seen_at to remain stable")
	}
	if secondRecords[0].LastSeenAt.Before(firstRecords[0].LastSeenAt) {
		t.Fatal("expected last_seen_at to move forward")
	}
	if !slices.Equal(secondRecords[0].Sources, []string{"amass", "subfinder"}) {
		t.Fatalf("sources=%v; want [amass subfinder]", secondRecords[0].Sources)
	}
}

func TestSaveResolutionsKeepsLastKnownGoodState(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"subfinder"}},
	}); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
	}); err != nil {
		t.Fatalf("save resolutions success: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", Error: "timeout"},
	}); err != nil {
		t.Fatalf("save resolutions failure: %v", err)
	}

	records, err := store.SubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("subdomains by domain: %v", err)
	}
	if !records[0].Resolved {
		t.Fatal("expected resolved state to remain true")
	}
	if !slices.Equal(records[0].IPs, []string{"1.1.1.1"}) {
		t.Fatalf("ips=%v; want [1.1.1.1]", records[0].IPs)
	}
	if records[0].ResolveError != "" {
		t.Fatalf("resolve_error=%q; want empty", records[0].ResolveError)
	}
	if !records[0].LastResolvedAt.Valid {
		t.Fatal("expected last_resolved_at to be set")
	}
}

func TestDomainExistsAndSubdomainsByDomainMissing(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	exists, err := store.DomainExists("missing.example")
	if err != nil {
		t.Fatalf("domain exists: %v", err)
	}
	if exists {
		t.Fatal("expected missing domain to not exist")
	}

	_, err = store.SubdomainsByDomain("missing.example")
	if err != sql.ErrNoRows {
		t.Fatalf("err=%v; want sql.ErrNoRows", err)
	}
}

func TestDomainResolutionHelpersAndVHostSave(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"subfinder"}},
		{Subdomain: "beta.example.com", Sources: []string{"subfinder"}},
		{Subdomain: "resolved.example.com", Sources: []string{"amass"}},
	}); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "resolved.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
		{Subdomain: "api.example.com", Error: "no such host"},
		{Subdomain: "beta.example.com", Error: "no such host"},
	}); err != nil {
		t.Fatalf("save resolutions: %v", err)
	}

	hosts, err := store.UnresolvedSubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("unresolved subdomains: %v", err)
	}
	if !slices.Equal(hosts, []string{"api.example.com", "beta.example.com"}) {
		t.Fatalf("hosts=%v; want [api.example.com beta.example.com]", hosts)
	}

	allHosts, err := store.AllSubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("all subdomains: %v", err)
	}
	if !slices.Equal(allHosts, []string{"api.example.com", "beta.example.com", "resolved.example.com"}) {
		t.Fatalf("allHosts=%v; want [api.example.com beta.example.com resolved.example.com]", allHosts)
	}

	ips, err := store.ResolvedIPsByDomain("example.com")
	if err != nil {
		t.Fatalf("resolved ips: %v", err)
	}
	if !slices.Equal(ips, []string{"1.1.1.1"}) {
		t.Fatalf("ips=%v; want [1.1.1.1]", ips)
	}

	if err := store.SaveVHostResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
	}); err != nil {
		t.Fatalf("save vhost resolutions: %v", err)
	}

	records, err := store.SubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("subdomains by domain: %v", err)
	}
	if records[0].Subdomain != "api.example.com" {
		t.Fatalf("first subdomain=%q; want api.example.com", records[0].Subdomain)
	}
	if !records[0].Resolved {
		t.Fatal("expected api.example.com to become resolved")
	}
	if !slices.Equal(records[0].IPs, []string{"1.1.1.1"}) {
		t.Fatalf("api ips=%v; want [1.1.1.1]", records[0].IPs)
	}
	if records[0].ResolveError != "" {
		t.Fatalf("api resolve_error=%q; want empty", records[0].ResolveError)
	}
	if !records[0].LastResolvedAt.Valid {
		t.Fatal("expected api last_resolved_at to be set")
	}
}

func TestResolvedSubdomainTargetsByDomainReturnsUniqueIPv4Targets(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"subfinder"}},
		{Subdomain: "cdn.example.com", Sources: []string{"amass"}},
		{Subdomain: "dead.example.com", Sources: []string{"amass"}},
	}); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1", "1.1.1.1", "2001:db8::1"}, Alive: true},
		{Subdomain: "cdn.example.com", IPs: []string{"2.2.2.2"}, Alive: true},
		{Subdomain: "dead.example.com", Error: "no such host"},
	}); err != nil {
		t.Fatalf("save resolutions: %v", err)
	}

	targets, err := store.ResolvedSubdomainTargetsByDomain("example.com")
	if err != nil {
		t.Fatalf("resolved subdomain targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets)=%d; want 2", len(targets))
	}
	if targets[0].Subdomain != "api.example.com" || !slices.Equal(targets[0].IPs, []string{"1.1.1.1"}) {
		t.Fatalf("targets[0]=%+v", targets[0])
	}
	if targets[1].Subdomain != "cdn.example.com" || !slices.Equal(targets[1].IPs, []string{"2.2.2.2"}) {
		t.Fatalf("targets[1]=%+v", targets[1])
	}

	_, err = store.ResolvedSubdomainTargetsByDomain("missing.example")
	if err != sql.ErrNoRows {
		t.Fatalf("err=%v; want sql.ErrNoRows", err)
	}
}

func TestSavedScanTargetsByDomainIncludesIPOnlyAssets(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"subfinder"}},
	}); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
	}); err != nil {
		t.Fatalf("save resolutions: %v", err)
	}
	if err := store.SavePortScans("example.com", []PortScanRecord{
		{Domain: "example.com", IP: "1.1.1.1", Port: 443, Protocol: "tcp", State: "open", Service: "https", ScannedAt: time.Now().UTC()},
		{Domain: "example.com", IP: "10.10.10.10", Port: 3389, Protocol: "tcp", State: "open", Service: "ms-wbt-server", ScannedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("save port scans: %v", err)
	}

	targets, err := store.SavedScanTargetsByDomain("example.com")
	if err != nil {
		t.Fatalf("saved scan targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets)=%d; want 2", len(targets))
	}
	if targets[0].Label != "api.example.com" || targets[0].Kind != "hostname" || !slices.Equal(targets[0].IPs, []string{"1.1.1.1"}) {
		t.Fatalf("targets[0]=%+v", targets[0])
	}
	if targets[1].Label != "10.10.10.10" || targets[1].Kind != "ip" || !slices.Equal(targets[1].IPs, []string{"10.10.10.10"}) {
		t.Fatalf("targets[1]=%+v", targets[1])
	}
}

func TestPermutationCandidatesLifecycleAndVHostPromotion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "resolved.example.com", Sources: []string{"subfinder"}},
	}); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "resolved.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
	}); err != nil {
		t.Fatalf("save resolutions: %v", err)
	}

	candidates := []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"gotator"}},
		{Subdomain: "beta.example.com", Sources: []string{"gotator"}},
	}
	if err := store.SavePermutationCandidates("example.com", candidates); err != nil {
		t.Fatalf("save permutation candidates: %v", err)
	}

	candidateRecords, err := store.PermutationCandidatesByDomain("example.com")
	if err != nil {
		t.Fatalf("permutation candidates by domain: %v", err)
	}
	if len(candidateRecords) != 2 {
		t.Fatalf("len(candidateRecords)=%d; want 2", len(candidateRecords))
	}

	allHosts, err := store.AllSubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("all subdomains: %v", err)
	}
	if !slices.Equal(allHosts, []string{"resolved.example.com"}) {
		t.Fatalf("allHosts=%v; want [resolved.example.com]", allHosts)
	}

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"gotator"}},
	}); err != nil {
		t.Fatalf("save promoted discovery: %v", err)
	}
	if err := store.SaveVHostResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
	}); err != nil {
		t.Fatalf("save vhost resolutions: %v", err)
	}
	if err := store.DeletePermutationCandidates("example.com", []string{"api.example.com"}); err != nil {
		t.Fatalf("delete permutation candidates: %v", err)
	}

	records, err := store.SubdomainsByDomain("example.com")
	if err != nil {
		t.Fatalf("subdomains by domain: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records)=%d; want 2", len(records))
	}
	if records[0].Subdomain != "api.example.com" || !records[0].Resolved {
		t.Fatalf("api record=%+v; want resolved promoted record", records[0])
	}

	candidateRecords, err = store.PermutationCandidatesByDomain("example.com")
	if err != nil {
		t.Fatalf("permutation candidates by domain after delete: %v", err)
	}
	if len(candidateRecords) != 1 || candidateRecords[0].Subdomain != "beta.example.com" {
		t.Fatalf("candidateRecords=%v; want [beta.example.com]", candidateRecords)
	}
}

func TestDomainSummariesIncludeCandidateOnlyDomains(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SavePermutationCandidates("candidate-only.example", []discovery.Entry{
		{Subdomain: "api-dev.candidate-only.example", Sources: []string{"gotator"}},
	}); err != nil {
		t.Fatalf("save permutation candidates: %v", err)
	}

	domains, err := store.Domains()
	if err != nil {
		t.Fatalf("domains: %v", err)
	}
	if !slices.Equal(domains, []string{"candidate-only.example"}) {
		t.Fatalf("domains=%v; want [candidate-only.example]", domains)
	}

	summary, err := store.DomainSummary("candidate-only.example")
	if err != nil {
		t.Fatalf("domain summary: %v", err)
	}
	if summary.Candidates != 1 || summary.Subdomains != 0 {
		t.Fatalf("summary=%+v; want candidates=1 subdomains=0", summary)
	}
}

func TestFindingsCRUDWithLinks(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	created, err := store.CreateFinding(FindingInput{
		Domain:           "example.com",
		Title:            "Exposed WinRM",
		Severity:         "high",
		Status:           "open",
		DescriptionHTML:  "<p>WinRM exposed on internal hosts.</p>",
		LinkedSubdomains: []string{"admin.example.com", "portal.example.com"},
		LinkedHosts:      []string{"172.20.17.192", "172.20.17.193"},
		AffectedService: &FindingServiceInput{
			Hostname: "admin.example.com",
			HostIP:   "172.20.17.192",
			Port:     5985,
			Protocol: "tcp",
			Service:  "winrm",
		},
	})
	if err != nil {
		t.Fatalf("create finding: %v", err)
	}
	if created.ID == 0 {
		t.Fatal("expected created finding ID")
	}
	if !slices.Equal(created.LinkedHosts, []string{"172.20.17.192", "172.20.17.193"}) {
		t.Fatalf("linked hosts=%v", created.LinkedHosts)
	}
	if created.AffectedService == nil || created.AffectedService.Port != 5985 || created.AffectedService.Service != "winrm" {
		t.Fatalf("affected service=%+v", created.AffectedService)
	}

	records, err := store.FindingsByDomain("example.com")
	if err != nil {
		t.Fatalf("findings by domain: %v", err)
	}
	if len(records) != 1 || records[0].Title != "Exposed WinRM" {
		t.Fatalf("records=%v", records)
	}

	updated, err := store.UpdateFinding(created.ID, FindingInput{
		Domain:           "example.com",
		Title:            "Exposed WinRM Management Surface",
		Severity:         "critical",
		Status:           "verified",
		DescriptionHTML:  "<p>Validated manually.</p>",
		LinkedSubdomains: []string{"admin.example.com"},
		LinkedHosts:      []string{"172.20.17.193"},
		AffectedService: &FindingServiceInput{
			Hostname: "admin.example.com",
			HostIP:   "172.20.17.193",
			Port:     5986,
			Protocol: "tcp",
			Service:  "winrm-ssl",
		},
	})
	if err != nil {
		t.Fatalf("update finding: %v", err)
	}
	if updated.Title != "Exposed WinRM Management Surface" || updated.Severity != "critical" || updated.Status != "verified" {
		t.Fatalf("updated=%+v", updated)
	}
	if !slices.Equal(updated.LinkedSubdomains, []string{"admin.example.com"}) {
		t.Fatalf("linked subdomains=%v", updated.LinkedSubdomains)
	}
	if updated.AffectedService == nil || updated.AffectedService.HostIP != "172.20.17.193" || updated.AffectedService.Port != 5986 {
		t.Fatalf("updated affected service=%+v", updated.AffectedService)
	}

	summary, err := store.DomainSummary("example.com")
	if err != nil {
		t.Fatalf("domain summary: %v", err)
	}
	if summary.Findings != 1 {
		t.Fatalf("findings count=%d; want 1", summary.Findings)
	}

	if err := store.DeleteFinding(created.ID); err != nil {
		t.Fatalf("delete finding: %v", err)
	}
	if _, err := store.FindingsByDomain("example.com"); err != sql.ErrNoRows {
		t.Fatalf("err=%v; want sql.ErrNoRows", err)
	}
}

func TestSavePortScansUpsertsLatestState(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	firstScan := PortScanRecord{
		Domain:    "example.com",
		IP:        "1.1.1.1",
		Port:      443,
		Protocol:  "tcp",
		State:     "open",
		Service:   "https",
		Version:   "nginx 1.0",
		ScannedAt: time.Now().UTC().Add(-time.Hour),
	}
	secondScan := firstScan
	secondScan.Version = "nginx 1.1"
	secondScan.ScannedAt = time.Now().UTC()

	if err := store.SavePortScans("example.com", []PortScanRecord{firstScan}); err != nil {
		t.Fatalf("save port scans #1: %v", err)
	}
	if err := store.SavePortScans("example.com", []PortScanRecord{secondScan}); err != nil {
		t.Fatalf("save port scans #2: %v", err)
	}

	records, err := store.PortScansByDomain("example.com")
	if err != nil {
		t.Fatalf("port scans by domain: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records)=%d; want 1", len(records))
	}
	if records[0].Version != "nginx 1.1" {
		t.Fatalf("version=%q; want nginx 1.1", records[0].Version)
	}
}

func TestCommandRunsLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	startedAt := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	runID, err := store.CreateCommandRun(CommandRunRecord{
		Domain:    "example.com",
		Target:    "https://app.example.com/FUZZ",
		Tool:      "ffuf",
		Command:   "ffuf -u https://app.example.com/FUZZ -w words.txt",
		Wordlist:  "words.txt",
		Status:    "running",
		StartedAt: startedAt,
		Notes:     "content discovery",
	})
	if err != nil {
		t.Fatalf("create command run: %v", err)
	}

	finishedAt := startedAt.Add(time.Minute)
	if err := store.FinishCommandRun(runID, "completed", 0, finishedAt, "", sql.NullInt64{}, ""); err != nil {
		t.Fatalf("finish command run: %v", err)
	}

	records, err := store.CommandRunsByDomain("example.com")
	if err != nil {
		t.Fatalf("command runs by domain: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records)=%d; want 1", len(records))
	}
	got := records[0]
	if got.ID != runID {
		t.Fatalf("id=%d; want %d", got.ID, runID)
	}
	if got.Status != "completed" {
		t.Fatalf("status=%q; want completed", got.Status)
	}
	if !got.ExitCode.Valid || got.ExitCode.Int64 != 0 {
		t.Fatalf("exit_code=%v; want 0", got.ExitCode)
	}
	if !got.FinishedAt.Valid || !got.FinishedAt.Time.Equal(finishedAt) {
		t.Fatalf("finished_at=%v; want %v", got.FinishedAt, finishedAt)
	}
	if got.Wordlist != "words.txt" {
		t.Fatalf("wordlist=%q; want words.txt", got.Wordlist)
	}
	if got.TranscriptPath != "" {
		t.Fatalf("transcript_path=%q; want empty", got.TranscriptPath)
	}

	_, err = store.CommandRunsByDomain("missing.example")
	if err != sql.ErrNoRows {
		t.Fatalf("err=%v; want sql.ErrNoRows", err)
	}
}

func TestCommandRunsLifecyclePersistsTranscriptMetadata(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	startedAt := time.Date(2026, 5, 24, 8, 30, 0, 0, time.UTC)
	runID, err := store.CreateCommandRun(CommandRunRecord{
		Domain:    "example.com",
		Target:    "10.20.30.40",
		Tool:      "nmap",
		Command:   "nmap -Pn 10.20.30.40",
		Status:    "running",
		StartedAt: startedAt,
	})
	if err != nil {
		t.Fatalf("create command run: %v", err)
	}

	finishedAt := startedAt.Add(2 * time.Minute)
	transcriptBytes := sql.NullInt64{Int64: 512, Valid: true}
	if err := store.FinishCommandRun(runID, "completed", 0, finishedAt, "/tmp/logy.typescript", transcriptBytes, "pty-script"); err != nil {
		t.Fatalf("finish command run: %v", err)
	}

	records, err := store.CommandRunsByDomain("example.com")
	if err != nil {
		t.Fatalf("command runs by domain: %v", err)
	}
	got := records[0]
	if got.TranscriptPath != "/tmp/logy.typescript" {
		t.Fatalf("transcript_path=%q; want /tmp/logy.typescript", got.TranscriptPath)
	}
	if !got.TranscriptBytes.Valid || got.TranscriptBytes.Int64 != 512 {
		t.Fatalf("transcript_bytes=%v; want 512", got.TranscriptBytes)
	}
	if got.TranscriptMode != "pty-script" {
		t.Fatalf("transcript_mode=%q; want pty-script", got.TranscriptMode)
	}
}

func TestSaveWebProbesAppendsHistory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	first := WebProbeRecord{
		Domain:       "example.com",
		Target:       "https://api.example.com",
		URL:          "https://api.example.com",
		FinalURL:     "https://api.example.com/login",
		Scheme:       "https",
		Port:         443,
		StatusCode:   200,
		Title:        "Login",
		Technologies: []string{"nginx"},
		ProbedAt:     time.Now().UTC().Add(-time.Hour),
	}
	second := first
	second.FinalURL = "https://api.example.com/dashboard"
	second.Title = "Dashboard"
	second.ProbedAt = time.Now().UTC()

	if err := store.SaveWebProbes("example.com", []WebProbeRecord{first}); err != nil {
		t.Fatalf("save web probes #1: %v", err)
	}
	if err := store.SaveWebProbes("example.com", []WebProbeRecord{second}); err != nil {
		t.Fatalf("save web probes #2: %v", err)
	}

	var count int
	row := store.db.QueryRow(`SELECT COUNT(*) FROM web_probes WHERE domain=?`, "example.com")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("count web probes: %v", err)
	}
	if count != 2 {
		t.Fatalf("count=%d; want 2", count)
	}
}

func TestWebProbesByDomainReturnsHistoryNewestFirst(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	older := WebProbeRecord{
		Domain:       "example.com",
		Target:       "https://api.example.com",
		URL:          "https://api.example.com",
		FinalURL:     "https://api.example.com/status",
		Scheme:       "https",
		Port:         443,
		StatusCode:   200,
		Title:        "Status",
		Technologies: []string{"Go", "nginx"},
		ProbedAt:     time.Date(2026, 4, 26, 8, 0, 0, 0, time.UTC),
	}
	newer := older
	newer.Target = "https://app.example.com"
	newer.URL = "https://app.example.com"
	newer.FinalURL = "https://app.example.com/login"
	newer.Title = "Login"
	newer.Technologies = []string{"React", "nginx"}
	newer.ProbedAt = time.Date(2026, 4, 26, 9, 0, 0, 0, time.UTC)

	if err := store.SaveWebProbes("example.com", []WebProbeRecord{older, newer}); err != nil {
		t.Fatalf("save web probes: %v", err)
	}

	records, err := store.WebProbesByDomain("example.com")
	if err != nil {
		t.Fatalf("web probes by domain: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records)=%d; want 2", len(records))
	}
	if records[0].Target != newer.Target {
		t.Fatalf("first target=%q; want %q", records[0].Target, newer.Target)
	}
	if !slices.Equal(records[0].Technologies, []string{"React", "nginx"}) {
		t.Fatalf("technologies=%v; want [React nginx]", records[0].Technologies)
	}

	_, err = store.WebProbesByDomain("missing.example")
	if err != sql.ErrNoRows {
		t.Fatalf("err=%v; want sql.ErrNoRows", err)
	}
}

func TestWebProbeTargetsByDomainBuildsHostnameURLs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recon.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.SaveDiscoveries("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"subfinder"}},
		{Subdomain: "alt.example.com", Sources: []string{"amass"}},
	}); err != nil {
		t.Fatalf("save discoveries: %v", err)
	}
	if err := store.SaveResolutions("example.com", []resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
		{Subdomain: "alt.example.com", IPs: []string{"1.1.1.1", "2.2.2.2"}, Alive: true},
	}); err != nil {
		t.Fatalf("save resolutions: %v", err)
	}
	if err := store.SavePortScans("example.com", []PortScanRecord{
		{Domain: "example.com", IP: "1.1.1.1", Port: 80, Protocol: "tcp", State: "open", Service: "http", ScannedAt: time.Now().UTC()},
		{Domain: "example.com", IP: "1.1.1.1", Port: 8443, Protocol: "tcp", State: "open", Service: "https-alt", ScannedAt: time.Now().UTC()},
		{Domain: "example.com", IP: "1.1.1.1", Port: 443, Protocol: "udp", State: "open", Service: "https", ScannedAt: time.Now().UTC()},
		{Domain: "example.com", IP: "2.2.2.2", Port: 22, Protocol: "tcp", State: "open", Service: "ssh", ScannedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatalf("save port scans: %v", err)
	}

	targets, err := store.WebProbeTargetsByDomain("example.com")
	if err != nil {
		t.Fatalf("web probe targets: %v", err)
	}

	got := make([]string, 0, len(targets))
	for _, target := range targets {
		got = append(got, target.URL)
	}
	want := []string{
		"http://alt.example.com",
		"https://alt.example.com:8443",
		"http://api.example.com",
		"https://api.example.com:8443",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got=%v; want %v", got, want)
	}
}
