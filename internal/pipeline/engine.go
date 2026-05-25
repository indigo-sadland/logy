package pipeline

import (
	"context"

	discovery2 "github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"github.com/indigo-sadland/logy/internal/storage"
)

type Engine struct {
	Discovery []provider.Provider
	Resolver  resolver.Config
	Store     *storage.Store
	Logf      func(string, ...any)
	Verbose   bool
}

type Report struct {
	Discovered  int
	Resolved    int
	Unresolved  int
	ToolStatus  []discovery2.ToolStatus
	ResolveData []resolver.Result
	Warnings    []string
	Warning     error
}

// Run executes provider discovery, persists new entries, resolves them, and returns a combined report.
func (e Engine) Run(ctx context.Context, target string, matchDomain string) (Report, error) {
	if e.Logf != nil {
		e.Logf("[*] discovery: running %d tool(s)\n", len(e.Discovery))
	}
	entries, toolStatus, warnings, discoverErr := discovery2.RunAll(ctx, discovery2.RunOptions{
		Target:        target,
		MatchDomain:   matchDomain,
		LogDiscovered: e.Verbose,
	}, e.Discovery, e.Logf)
	if e.Logf != nil {
		e.Logf("[+] discovery: unique_subdomains=%d\n", len(entries))
		for _, status := range toolStatus {
			switch status.Status {
			case "failed":
				e.Logf("[!] discovery-summary/%s: status=failed error=%s\n", status.Name, status.Error)
			case "empty":
				e.Logf("[!] discovery-summary/%s: status=empty raw_results=0\n", status.Name)
			default:
				e.Logf("[+] discovery-summary/%s: status=ok raw_results=%d\n", status.Name, status.RawResults)
			}
		}
	}
	report, err := e.IngestAndResolve(ctx, matchDomain, entries)
	if err != nil {
		return Report{}, err
	}
	report.ToolStatus = toolStatus
	report.Warnings = warnings
	report.Warning = discoverErr
	return report, nil
}

// IngestAndResolve saves prebuilt discovery entries, resolves them, and refreshes resolution counters from storage.
func (e Engine) IngestAndResolve(ctx context.Context, matchDomain string, entries []discovery2.Entry) (Report, error) {
	if err := e.Store.SaveDiscoveries(matchDomain, entries); err != nil {
		return Report{}, err
	}
	if e.Logf != nil {
		e.Logf("[+] storage: discoveries saved for domain=%s\n", matchDomain)
	}

	hosts := make([]string, 0, len(entries))
	for _, entry := range entries {
		hosts = append(hosts, entry.Subdomain)
	}

	if e.Logf != nil {
		e.Logf("[*] resolution: resolving %d host(s) with %s\n", len(hosts), e.Resolver.Binary)
	}
	resolveResults, err := resolver.ResolveAll(ctx, hosts, e.Resolver, e.Logf)
	if err != nil {
		return Report{}, err
	}
	if err := e.Store.SaveResolutions(matchDomain, resolveResults); err != nil {
		return Report{}, err
	}
	if e.Logf != nil {
		e.Logf("[+] storage: resolutions saved for domain=%s\n", matchDomain)
	}

	resolved, unresolved, err := e.Store.CountByResolution(matchDomain)
	if err != nil {
		return Report{}, err
	}
	if e.Logf != nil {
		e.Logf("[+] resolution: resolved=%d unresolved=%d\n", resolved, unresolved)
	}

	report := Report{
		Discovered:  len(entries),
		Resolved:    resolved,
		Unresolved:  unresolved,
		ResolveData: resolveResults,
	}
	return report, nil
}
