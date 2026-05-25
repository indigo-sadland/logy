package webprobe

import (
	"slices"
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
