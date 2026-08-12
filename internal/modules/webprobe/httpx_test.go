package webprobe

import (
	"slices"
	"strings"
	"testing"
)

func TestParseJSONL(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"input":"https://api.example.com","url":"https://api.example.com","final_url":"https://api.example.com/login","scheme":"https","port":"443","status_code":200,"title":"Login","tech":["nginx","next.js"]}
{"input":"http://blog.example.com:8080","url":"http://blog.example.com:8080","scheme":"http","port":8080,"status_code":302,"title":"","technologies":"apache,php"}`)

	results, err := parseJSONL(raw)
	if err != nil {
		t.Fatalf("parseJSONL: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results)=%d; want 2", len(results))
	}

	if results[0].Target != "http://blog.example.com:8080" {
		t.Fatalf("first target=%q", results[0].Target)
	}
	if results[0].Port != 8080 || results[0].StatusCode != 302 {
		t.Fatalf("first result=%+v", results[0])
	}
	if !slices.Equal(results[0].Technologies, []string{"apache", "php"}) {
		t.Fatalf("first tech=%v", results[0].Technologies)
	}

	if results[1].FinalURL != "https://api.example.com/login" {
		t.Fatalf("second final_url=%q", results[1].FinalURL)
	}
	if !slices.Equal(results[1].Technologies, []string{"next.js", "nginx"}) {
		t.Fatalf("second tech=%v", results[1].Technologies)
	}
}

func TestNormalizeTargetsDeduplicates(t *testing.T) {
	t.Parallel()

	got := normalizeTargets([]string{" https://a.example.com ", "https://a.example.com", "", "http://b.example.com"})
	want := []string{"http://b.example.com", "https://a.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("got=%v; want %v", got, want)
	}
}

func TestBuildProbeArgsIncludeResolvers(t *testing.T) {
	t.Parallel()

	got := buildProbeArgs(Config{
		Resolvers: []string{" 1.1.1.1 ", "8.8.8.8", "1.1.1.1"},
	})
	want := []string{
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-follow-redirects",
		"-r", "1.1.1.1,8.8.8.8",
		"-json",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got=%v; want %v", got, want)
	}
}

func TestScanResultsReportsProgress(t *testing.T) {
	t.Parallel()

	var updates []Progress
	tracker := newProgressTracker(2, func(progress Progress) {
		updates = append(updates, progress)
	}, 0)

	raw := strings.NewReader(`{"input":"https://api.example.com","url":"https://api.example.com","final_url":"https://api.example.com/login","scheme":"https","port":"443","status_code":200,"title":"Login","tech":["nginx"]}
{"input":"http://blog.example.com:8080","url":"http://blog.example.com:8080","scheme":"http","port":8080,"status_code":404,"title":"","technologies":"apache,php"}`)

	results, err := scanResults(raw, tracker)
	if err != nil {
		t.Fatalf("scanResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results)=%d; want 2", len(results))
	}
	if len(updates) != 2 {
		t.Fatalf("len(updates)=%d; want 2", len(updates))
	}

	last := updates[len(updates)-1]
	if last.Completed != 2 || last.Total != 2 {
		t.Fatalf("progress=%+v; want completed=2 total=2", last)
	}
	if last.Status2xx != 1 || last.Status4xx != 1 {
		t.Fatalf("progress=%+v; want 2xx=1 4xx=1", last)
	}
	if last.LastTarget != "http://blog.example.com:8080" {
		t.Fatalf("last target=%q; want http://blog.example.com:8080", last.LastTarget)
	}
}

func TestProgressTrackerHeartbeatCarriesCurrentTotals(t *testing.T) {
	t.Parallel()

	var updates []Progress
	tracker := newProgressTracker(3, func(progress Progress) {
		updates = append(updates, progress)
	}, 0)

	tracker.record(Result{Target: "https://a.example.com", URL: "https://a.example.com", StatusCode: 302})
	tracker.report(true)

	if len(updates) != 2 {
		t.Fatalf("len(updates)=%d; want 2", len(updates))
	}

	heartbeat := updates[len(updates)-1]
	if !heartbeat.Heartbeat {
		t.Fatalf("heartbeat=%+v; want heartbeat update", heartbeat)
	}
	if heartbeat.Completed != 1 || heartbeat.Status3xx != 1 {
		t.Fatalf("heartbeat=%+v; want completed=1 3xx=1", heartbeat)
	}
}
