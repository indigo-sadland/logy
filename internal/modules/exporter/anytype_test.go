package exporter

import (
	"github.com/indigo-sadland/logy/internal/storage"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAnytypeCommandRunStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   string
	}{
		{name: "completed", status: "completed", want: "completed"},
		{name: "completed case insensitive", status: "Completed", want: "completed"},
		{name: "failed", status: "failed", want: "failed"},
		{name: "running", status: "running", want: "failed"},
		{name: "empty", status: "", want: "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := anytypeCommandRunStatus(tt.status); got != tt.want {
				t.Fatalf("status=%q got %q; want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestAnytypePropertyStringReadsTimestamp(t *testing.T) {
	object := map[string]any{
		"properties": []any{
			map[string]any{
				"key":  "timestamp",
				"text": "2026-05-18T10:00:00Z",
			},
		},
	}

	if got := anytypePropertyString(object, "timestamp"); got != "2026-05-18T10:00:00Z" {
		t.Fatalf("timestamp=%q", got)
	}
}

func TestAnytypePropertyStringReadsNestedTextValue(t *testing.T) {
	object := map[string]any{
		"properties": map[string]any{
			"timestamp": map[string]any{
				"text": "2026-05-18T10:00:00Z",
			},
		},
	}

	if got := anytypePropertyString(object, "timestamp"); got != "2026-05-18T10:00:00Z" {
		t.Fatalf("timestamp=%q", got)
	}
}

func TestAnytypePropertyStringIgnoresPropertyDisplayName(t *testing.T) {
	object := map[string]any{
		"properties": []any{
			map[string]any{
				"key":  "alias",
				"name": "Alias",
			},
		},
	}

	if got := anytypePropertyString(object, "alias"); got != "" {
		t.Fatalf("alias=%q; want empty", got)
	}
}

func TestMergeAliasValuesPreservesExistingAliases(t *testing.T) {
	got := mergeAliasValues(
		splitAliasText("api.example.com, admin.example.com"),
		[]string{"api.example.com", "portal.example.com"},
	)
	want := []string{"admin.example.com", "api.example.com", "portal.example.com"}
	if len(got) != len(want) {
		t.Fatalf("aliases=%v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("aliases=%v; want %v", got, want)
		}
	}
}

func TestAnytypeAssetPropertiesIncludeAliases(t *testing.T) {
	properties := anytypeAssetProperties(AnytypeOptions{
		AliasPropertyKey:      "alias",
		EngagementPropertyKey: "engagement",
	}, "eng-1", []string{"api.example.com", "admin.example.com"})

	if len(properties) != 2 {
		t.Fatalf("len(properties)=%d; want 2", len(properties))
	}
	if got := properties[0]["text"]; got != "api.example.com, admin.example.com" {
		t.Fatalf("alias=%v; want api.example.com, admin.example.com", got)
	}
}

func TestAnytypeServiceObjectNameUsesIPIdentity(t *testing.T) {
	got := anytypeServiceObjectName(testPortScan("203.0.113.20", 443, "tcp", "https"))
	want := "443 HTTPS - 203.0.113.20"
	if got != want {
		t.Fatalf("name=%q; want %q", got, want)
	}
}

func TestAnytypeServiceReuseNamesPreferIPAndKeepLegacyAliases(t *testing.T) {
	got := anytypeServiceReuseNames(testPortScan("203.0.113.20", 443, "tcp", "https"), []string{"app.example.com", "admin.example.com"})
	want := []string{"443 HTTPS - 203.0.113.20", "443 HTTPS - app.example.com", "443 HTTPS - admin.example.com"}
	if len(got) != len(want) {
		t.Fatalf("names=%v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names=%v; want %v", got, want)
		}
	}
}

func TestAnytypeHistoricalObservationNameUsesServiceNameAndTimestamp(t *testing.T) {
	observation := storage.ServiceHistoricalObservationRecord{
		ObservedAt: time.Date(2026, 5, 24, 19, 12, 44, 0, time.UTC),
	}

	got := anytypeHistoricalObservationName(observation, "443 HTTPS - 10.20.30.40")
	want := "443 HTTPS - 10.20.30.40"
	if got != want {
		t.Fatalf("name=%q; want %q", got, want)
	}
}

func TestAnytypeHistoricalObservationNameFallsBackToObservationShape(t *testing.T) {
	observation := storage.ServiceHistoricalObservationRecord{
		HostIP:          "172.16.10.50",
		Port:            3389,
		Protocol:        "tcp",
		ObservedService: "ms-wbt-server",
		ObservedAt:      time.Date(2026, 5, 24, 19, 33, 42, 0, time.UTC),
	}

	got := anytypeHistoricalObservationName(observation, "")
	want := "3389 MS-WBT-SERVER - 172.16.10.50"
	if got != want {
		t.Fatalf("name=%q; want %q", got, want)
	}
}

func TestAnytypeServicePropertiesIncludeAliases(t *testing.T) {
	properties := anytypeServiceProperties(AnytypeOptions{
		AliasPropertyKey:      "alias",
		PortPropertyKey:       "port",
		StatePropertyKey:      "state",
		ServicePropertyKey:    "service",
		BannerPropertyKey:     "banner",
		EngagementPropertyKey: "engagement",
		AssetPropertyKey:      "asset",
	}, "eng-1", "asset-1", []string{"api.example.com", "admin.example.com"}, storage.PortScanRecord{
		Port:     443,
		Protocol: "tcp",
		State:    "open",
		Service:  "https",
		Version:  "nginx",
	})

	if len(properties) != 7 {
		t.Fatalf("len(properties)=%d; want 7", len(properties))
	}
	if got := properties[0]["text"]; got != "api.example.com, admin.example.com" {
		t.Fatalf("alias=%v; want api.example.com, admin.example.com", got)
	}
}

func TestCollidesWithCurrentServiceMatchesStateServiceOrBannerChanges(t *testing.T) {
	scans := []storage.PortScanRecord{{
		IP:       "10.20.30.40",
		Port:     443,
		Protocol: "tcp",
		State:    "open",
		Service:  "https",
		Version:  "nginx 1.27.0",
	}}

	tests := []struct {
		name        string
		observation storage.ServiceHistoricalObservationRecord
		want        bool
	}{
		{
			name: "same values",
			observation: storage.ServiceHistoricalObservationRecord{
				HostIP:          "10.20.30.40",
				Port:            443,
				Protocol:        "tcp",
				ObservedState:   "open",
				ObservedService: "https",
				ObservedBanner:  "nginx 1.27.0",
			},
			want: false,
		},
		{
			name: "banner changed",
			observation: storage.ServiceHistoricalObservationRecord{
				HostIP:          "10.20.30.40",
				Port:            443,
				Protocol:        "tcp",
				ObservedState:   "open",
				ObservedService: "https",
				ObservedBanner:  "envoy 1.31.2",
			},
			want: true,
		},
		{
			name: "state changed",
			observation: storage.ServiceHistoricalObservationRecord{
				HostIP:          "10.20.30.40",
				Port:            443,
				Protocol:        "tcp",
				ObservedState:   "filtered",
				ObservedService: "https",
				ObservedBanner:  "nginx 1.27.0",
			},
			want: true,
		},
		{
			name: "no current service match",
			observation: storage.ServiceHistoricalObservationRecord{
				HostIP:          "10.20.30.99",
				Port:            443,
				Protocol:        "tcp",
				ObservedState:   "open",
				ObservedService: "https",
				ObservedBanner:  "nginx 1.27.0",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := collidesWithCurrentService(tt.observation, scans); got != tt.want {
				t.Fatalf("collides=%t; want %t", got, tt.want)
			}
		})
	}
}

func TestAnytypeWebAppObservationPropertiesStringifyStatusAndJoinTechnologies(t *testing.T) {
	properties := anytypeWebAppObservationProperties(AnytypeOptions{
		WebAppObservationTitlePropertyKey:        "title",
		WebAppObservationStatusCodePropertyKey:   "status_code",
		WebAppObservationTechnologiesPropertyKey: "technologies",
		EngagementPropertyKey:                    "engagement",
	}, "eng-1", storage.WebProbeRecord{
		Title:        "Demo Login",
		StatusCode:   200,
		Technologies: []string{"nginx", "react"},
	})

	if len(properties) != 4 {
		t.Fatalf("len(properties)=%d; want 4", len(properties))
	}
	if got := properties[0]["text"]; got != "Demo Login" {
		t.Fatalf("title=%v; want Demo Login", got)
	}
	if got := properties[1]["text"]; got != "200" {
		t.Fatalf("status_code=%v; want 200", got)
	}
	if got := properties[2]["text"]; got != "nginx,react" {
		t.Fatalf("technologies=%v; want nginx,react", got)
	}
}

func TestSuspiciousPortscanIPsMarksHostsAtThreshold(t *testing.T) {
	scans := []storage.PortScanRecord{
		{IP: "10.0.0.1", Port: 80},
		{IP: "10.0.0.1", Port: 443},
		{IP: "10.0.0.2", Port: 22},
	}

	got := suspiciousPortscanIPs(scans, 2)
	if _, ok := got["10.0.0.1"]; !ok {
		t.Fatal("expected 10.0.0.1 to be suspicious")
	}
	if _, ok := got["10.0.0.2"]; ok {
		t.Fatal("expected 10.0.0.2 to stay below threshold")
	}

	if disabled := suspiciousPortscanIPs(scans, 0); disabled != nil {
		t.Fatalf("disabled filtering=%v; want nil", disabled)
	}
}

func TestNewAnytypeProgressStateCountsExportableWork(t *testing.T) {
	suspicious := map[string]struct{}{"10.0.0.2": {}}
	progress := newAnytypeProgressState(AnytypeOptions{
		OnlyScans: false,
		Progress:  func(AnytypeProgress) {},
	}, []storage.PortScanRecord{
		{IP: "10.0.0.1", Port: 80, Protocol: "tcp", State: "open", Service: "http", Version: "nginx"},
		{IP: "10.0.0.2", Port: 1, Protocol: "tcp", State: "open", Service: "tcpwrapped", Version: ""},
	}, []storage.ServiceHistoricalObservationRecord{
		{HostIP: "10.0.0.1", Port: 80, Protocol: "tcp", ObservedState: "open", ObservedService: "http", ObservedBanner: "Apache"},
		{HostIP: "10.0.0.2", Port: 1, Protocol: "tcp", ObservedState: "open", ObservedService: "tcpwrapped", ObservedBanner: ""},
	}, []storage.WebProbeRecord{
		{URL: "https://app.example.com"},
	}, []storage.CommandRunRecord{
		{Command: "nmap -Pn app.example.com"},
	}, suspicious)

	// engagement lookup + 1 service + 1 historical observation + 1 web app + 1 scan
	if progress.total != 5 {
		t.Fatalf("progress.total=%d; want 5", progress.total)
	}
}

func TestObjectLinkedToEngagementVerifiesRelationWhenPresent(t *testing.T) {
	object := map[string]any{
		"properties": []any{
			map[string]any{
				"key":     "engagement",
				"objects": []any{"eng-1"},
			},
		},
	}
	if !objectLinkedToEngagement(object, "engagement", "eng-1") {
		t.Fatal("expected engagement relation to match")
	}
	if objectLinkedToEngagement(object, "engagement", "eng-2") {
		t.Fatal("expected engagement relation mismatch")
	}
}

func TestCommandRunTranscriptTextReadsRecordedOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.typescript")
	if err := os.WriteFile(path, []byte("hello from transcript\n"), 0o600); err != nil {
		t.Fatalf("write transcript: %v", err)
	}

	got, ok, err := commandRunTranscriptText(storage.CommandRunRecord{TranscriptPath: path}, "")
	if err != nil {
		t.Fatalf("commandRunTranscriptText: %v", err)
	}
	if !ok {
		t.Fatal("expected transcript to be present")
	}
	if got != "hello from transcript\n" {
		t.Fatalf("transcript=%q", got)
	}
}

func TestCommandRunMarkdownWrapsTranscriptInCodeFence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.typescript")
	if err := os.WriteFile(path, []byte("captured output"), 0o600); err != nil {
		t.Fatalf("write transcript: %v", err)
	}

	run := storage.CommandRunRecord{
		TranscriptPath: path,
	}
	markdown, err := commandRunMarkdown(run, "")
	if err != nil {
		t.Fatalf("commandRunMarkdown: %v", err)
	}
	want := "````text\ncaptured output\n````"
	if markdown != want {
		t.Fatalf("markdown=%q; want %q", markdown, want)
	}
}

func TestCommandRunMarkdownResolvesRelativePathAgainstDatabaseDirectory(t *testing.T) {
	dir := t.TempDir()
	transcriptDir := filepath.Join(dir, "transcripts")
	if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
		t.Fatalf("mkdir transcript dir: %v", err)
	}
	path := filepath.Join(transcriptDir, "session.typescript")
	if err := os.WriteFile(path, []byte("portable output"), 0o600); err != nil {
		t.Fatalf("write transcript: %v", err)
	}

	run := storage.CommandRunRecord{TranscriptPath: filepath.Join("transcripts", "session.typescript")}
	markdown, err := commandRunMarkdown(run, filepath.Join(dir, "demo.db"))
	if err != nil {
		t.Fatalf("commandRunMarkdown: %v", err)
	}
	want := "````text\nportable output\n````"
	if markdown != want {
		t.Fatalf("markdown=%q; want %q", markdown, want)
	}
}

func TestAnytypeCommandRunPropertiesExcludeTranscriptBody(t *testing.T) {
	run := storage.CommandRunRecord{
		Command:   "ffuf -u https://app.example.com/FUZZ -w words.txt",
		Status:    "completed",
		StartedAt: time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC),
	}
	properties := anytypeCommandRunProperties(AnytypeOptions{
		ScanStatusPropertyKey: "scan_status",
		TimestampPropertyKey:  "timestamp",
		EngagementPropertyKey: "engagement",
	}, "eng-1", run)
	if len(properties) != 3 {
		t.Fatalf("len(properties)=%d; want 3", len(properties))
	}
}

func testPortScan(ip string, port int, protocol string, service string) storage.PortScanRecord {
	return storage.PortScanRecord{
		IP:       ip,
		Port:     port,
		Protocol: protocol,
		Service:  service,
	}
}
