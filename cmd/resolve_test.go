package cmd

import (
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"github.com/indigo-sadland/logy/internal/storage"
	"reflect"
	"testing"
)

func TestSplitPermutationResultsSeparatesResolvedAndCandidates(t *testing.T) {
	t.Parallel()

	resolvedEntries, resolvedResults, unresolvedEntries := splitPermutationResults([]resolver.Result{
		{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
		{Subdomain: "beta.example.com", Error: "no records", Alive: false},
	})

	if !reflect.DeepEqual(resolvedEntries, []discovery.Entry{{Subdomain: "api.example.com", Sources: []string{"gotator"}}}) {
		t.Fatalf("resolvedEntries=%v", resolvedEntries)
	}
	if !reflect.DeepEqual(resolvedResults, []resolver.Result{{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true}}) {
		t.Fatalf("resolvedResults=%v", resolvedResults)
	}
	if !reflect.DeepEqual(unresolvedEntries, []discovery.Entry{{Subdomain: "beta.example.com", Sources: []string{"gotator"}}}) {
		t.Fatalf("unresolvedEntries=%v", unresolvedEntries)
	}
}

func TestPromoteCandidateEntriesSelectsOnlyResolvedCandidates(t *testing.T) {
	t.Parallel()

	got := promoteCandidateEntries(
		[]resolver.Result{
			{Subdomain: "api.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
			{Subdomain: "existing.example.com", IPs: []string{"1.1.1.1"}, Alive: true},
		},
		[]storage.PermutationCandidateRecord{
			{Subdomain: "api.example.com", Sources: []string{"gotator"}},
		},
	)

	want := []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"gotator"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries=%v; want %v", got, want)
	}
}

func TestMergeUniqueHostsSortsAndDeduplicates(t *testing.T) {
	t.Parallel()

	got := mergeUniqueHosts([]string{"beta.example.com", "api.example.com"}, []string{"api.example.com", "gamma.example.com"})
	want := []string{"api.example.com", "beta.example.com", "gamma.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts=%v; want %v", got, want)
	}
}
