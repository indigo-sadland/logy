package discovery

import (
	"context"
	"fmt"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"slices"
	"testing"
)

type stubProvider struct {
	name  string
	items []string
	err   error
}

func (p stubProvider) Name() string {
	return p.name
}

func (p stubProvider) Discover(context.Context, string) ([]string, error) {
	return p.items, p.err
}

func TestRunAllFiltersResultsOutsideMatchDomain(t *testing.T) {
	t.Parallel()

	entries, statuses, warnings, err := RunAll(context.Background(), RunOptions{
		Target:      "AS3333",
		MatchDomain: "target.com",
	}, []provider.Provider{
		stubProvider{
			name:  "ripestat",
			items: []string{"api.target.com", "nottarget.com", "site.nottarget.com", "target.com"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}

	gotHosts := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotHosts = append(gotHosts, entry.Subdomain)
	}
	expectedHosts := []string{"api.target.com", "target.com"}
	if !slices.Equal(gotHosts, expectedHosts) {
		t.Fatalf("hosts=%v; want %v", gotHosts, expectedHosts)
	}

	if len(statuses) != 1 || statuses[0].Name != "ripestat" || statuses[0].RawResults != 4 {
		t.Fatalf("unexpected statuses: %+v", statuses)
	}

	expectedWarnings := []string{
		"ripestat: excluded 2 host(s) that do not match target.com: nottarget.com, site.nottarget.com",
	}
	if !slices.Equal(warnings, expectedWarnings) {
		t.Fatalf("warnings=%v; want %v", warnings, expectedWarnings)
	}
}

func TestRunAllKeepsRipeStatResultsWithoutMatchDomain(t *testing.T) {
	t.Parallel()

	entries, _, warnings, err := RunAll(context.Background(), RunOptions{
		Target: "AS3333",
	}, []provider.Provider{
		stubProvider{
			name:  "ripestat",
			items: []string{"api.target.com", "nottarget.com"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}

	gotHosts := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotHosts = append(gotHosts, entry.Subdomain)
	}
	expectedHosts := []string{"api.target.com", "nottarget.com"}
	if !slices.Equal(gotHosts, expectedHosts) {
		t.Fatalf("hosts=%v; want %v", gotHosts, expectedHosts)
	}

	if len(warnings) != 0 {
		t.Fatalf("warnings=%v; want none", warnings)
	}
}

func TestRunAllLogsUniqueDiscoveredHostsWhenEnabled(t *testing.T) {
	t.Parallel()

	var logs []string
	entries, _, _, err := RunAll(context.Background(), RunOptions{
		Target:        "example.com",
		MatchDomain:   "example.com",
		LogDiscovered: true,
	}, []provider.Provider{
		stubProvider{
			name:  "tool-a",
			items: []string{"api.example.com", "api.example.com", "bad.net", "www.example.com"},
		},
	}, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}

	gotHosts := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotHosts = append(gotHosts, entry.Subdomain)
	}
	expectedHosts := []string{"api.example.com", "www.example.com"}
	if !slices.Equal(gotHosts, expectedHosts) {
		t.Fatalf("hosts=%v; want %v", gotHosts, expectedHosts)
	}

	expectedLogs := []string{
		"[*] discovery/tool-a: started\n",
		"[+] discovery/tool-a: completed, raw_results=4\n",
		"[*] discovery/tool-a: found api.example.com\n",
		"[*] discovery/tool-a: found www.example.com\n",
	}
	if !slices.Equal(logs, expectedLogs) {
		t.Fatalf("logs=%v; want %v", logs, expectedLogs)
	}
}
