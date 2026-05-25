package discovery

import (
	"context"
	"errors"
	"fmt"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"github.com/indigo-sadland/logy/internal/utils/dedup"
	"sort"
	"strings"
	"sync"
)

type Entry struct {
	Subdomain string
	Sources   []string
}

type ToolStatus struct {
	Name       string
	RawResults int
	Status     string
	Error      string
}

type RunOptions struct {
	Target        string
	MatchDomain   string
	LogDiscovered bool
}

// RunAll executes all providers, normalizes and deduplicates their results, and returns per-tool status data.
func RunAll(ctx context.Context, opts RunOptions, providers []provider.Provider, logf func(string, ...any)) ([]Entry, []ToolStatus, []string, error) {
	target := provider.NormalizeCandidate(opts.Target)
	matchDomain := provider.NormalizeCandidate(opts.MatchDomain)
	type providerResult struct {
		source string
		items  []string
		err    error
	}

	results := make(chan providerResult, len(providers))
	var wg sync.WaitGroup
	for _, p := range providers {
		wg.Add(1)
		go func(provider provider.Provider) {
			defer wg.Done()
			if logf != nil {
				logf("[*] discovery/%s: started\n", provider.Name())
			}
			items, err := provider.Discover(ctx, target)
			if logf != nil {
				if err != nil {
					logf("[!] discovery/%s: failed: %v\n", provider.Name(), err)
				} else {
					logf("[+] discovery/%s: completed, raw_results=%d\n", provider.Name(), len(items))
				}
			}
			results <- providerResult{source: provider.Name(), items: items, err: err}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	seen := dedup.New()
	sourceByHost := make(map[string]map[string]struct{}, 1024)
	statuses := make([]ToolStatus, 0, len(providers))
	droppedBySource := make(map[string]map[string]struct{}, len(providers))
	var errs []error

	for result := range results {
		if result.err != nil {
			statuses = append(statuses, ToolStatus{
				Name:   result.source,
				Status: "failed",
				Error:  result.err.Error(),
			})
			errs = append(errs, fmt.Errorf("%s: %w", result.source, result.err))
			continue
		}
		status := ToolStatus{
			Name:       result.source,
			RawResults: len(result.items),
			Status:     "ok",
		}
		if len(result.items) == 0 {
			status.Status = "empty"
		}
		statuses = append(statuses, status)
		for _, host := range result.items {
			host = provider.NormalizeCandidate(host)
			if host == "" {
				continue
			}
			if !matchesDomain(host, matchDomain) {
				if _, ok := droppedBySource[result.source]; !ok {
					droppedBySource[result.source] = make(map[string]struct{}, 8)
				}
				droppedBySource[result.source][host] = struct{}{}
				continue
			}
			if added := seen.Add(host); added && opts.LogDiscovered && logf != nil {
				logf("[*] discovery/%s: found %s\n", result.source, host)
			}
			if _, ok := sourceByHost[host]; !ok {
				sourceByHost[host] = make(map[string]struct{}, 2)
			}
			sourceByHost[host][result.source] = struct{}{}
		}
	}

	hosts := seen.Slice()
	sort.Strings(hosts)
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Name < statuses[j].Name
	})
	out := make([]Entry, 0, len(hosts))
	for _, host := range hosts {
		srcSet := sourceByHost[host]
		sources := make([]string, 0, len(srcSet))
		for source := range srcSet {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		out = append(out, Entry{Subdomain: host, Sources: sources})
	}

	warnings := buildMismatchWarnings(droppedBySource, matchDomain)
	return out, statuses, warnings, errorsJoin(errs)
}

// errorsJoin collapses multiple provider failures into a single readable error.
func errorsJoin(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		var b strings.Builder
		b.WriteString("multiple discovery providers failed:")
		for _, err := range errs {
			b.WriteString(" ")
			b.WriteString(err.Error())
			b.WriteString(";")
		}
		return errors.New(strings.TrimSuffix(b.String(), ";"))
	}
}

// matchesDomain reports whether a host belongs to the requested domain scope.
func matchesDomain(host string, domain string) bool {
	if domain == "" {
		return true
	}
	return strings.HasSuffix(host, "."+domain) || host == domain
}

// buildMismatchWarnings explains which provider results were dropped by domain filtering.
func buildMismatchWarnings(droppedBySource map[string]map[string]struct{}, matchDomain string) []string {
	if matchDomain == "" || len(droppedBySource) == 0 {
		return nil
	}

	sources := make([]string, 0, len(droppedBySource))
	for source := range droppedBySource {
		sources = append(sources, source)
	}
	sort.Strings(sources)

	warnings := make([]string, 0, len(sources))
	for _, source := range sources {
		items := droppedBySource[source]
		if len(items) == 0 {
			continue
		}

		hosts := make([]string, 0, len(items))
		for host := range items {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)

		warnings = append(warnings, fmt.Sprintf(
			"%s: excluded %d host(s) that do not match %s: %s",
			source,
			len(hosts),
			matchDomain,
			strings.Join(hosts, ", "),
		))
	}
	return warnings
}
