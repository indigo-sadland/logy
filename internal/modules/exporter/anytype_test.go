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

func TestAnytypeServiceObjectNamesIncludesAliasAndIPFallback(t *testing.T) {
	got := anytypeServiceObjectNames(testPortScan("203.0.113.20", 443, "tcp", "https"), []string{"app.example.com"})
	want := []string{"443 HTTPS - 203.0.113.20", "443 HTTPS - app.example.com"}
	if len(got) != len(want) {
		t.Fatalf("names=%v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names=%v; want %v", got, want)
		}
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

	got, ok, err := commandRunTranscriptText(storage.CommandRunRecord{TranscriptPath: path})
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
	markdown, err := commandRunMarkdown(run)
	if err != nil {
		t.Fatalf("commandRunMarkdown: %v", err)
	}
	want := "````text\ncaptured output\n````"
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
