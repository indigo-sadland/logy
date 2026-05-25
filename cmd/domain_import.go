package cmd

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"github.com/indigo-sadland/logy/internal/storage"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var domainImportFile string
var domainImportSource string

var importCmd = &cobra.Command{
	Use:   "import --domain example.com --file subdomains.txt",
	Short: "Import subdomains from a line-delimited file. Import also triggers automatic resolving for new subdomains",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDomainImport(cmd)
	},
}

type domainImportResult struct {
	Entries     []discovery.Entry
	Resolutions []resolver.Result
	TotalLines  int
	Skipped     int
	OutOfScope  []string
}

func init() {
	domainCmd.AddCommand(importCmd)
	importCmd.Flags().StringP("domain", "d", "", "root domain to associate imported subdomains with")
	importCmd.Flags().StringVarP(&domainImportFile, "file", "f", "", "line-delimited file containing subdomains")
	importCmd.Flags().StringVar(&domainImportSource, "source", "import", "source label to attach to imported subdomains")
	importCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
}

func runDomainImport(cmd *cobra.Command) error {
	domain, _ := cmd.Flags().GetString("domain")
	configPath, _ := cmd.Flags().GetString("config")
	resolvedDomain, err := requireDomainLabel(domain)
	if err != nil {
		return err
	}
	domain = provider.NormalizeCandidate(resolvedDomain)
	source := strings.TrimSpace(domainImportSource)
	filePath := strings.TrimSpace(domainImportFile)

	if filePath == "" {
		return fmt.Errorf("--file is required")
	}
	if source == "" {
		return fmt.Errorf("--source must not be empty")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	imported, err := parseDomainImport(file, domain, source)
	if err != nil {
		return err
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	entries, err := mergeImportedSources(store, domain, imported.Entries)
	if err != nil {
		return err
	}
	if err := store.SaveDiscoveries(domain, entries); err != nil {
		return err
	}
	resolutions, err := mergeImportedResolutions(store, domain, imported.Resolutions)
	if err != nil {
		return err
	}
	if err := store.SaveResolutions(domain, resolutions); err != nil {
		return err
	}
	autoResolved, err := autoResolveImportedHosts(cmd, cfg, store, domain, imported)
	if err != nil {
		return err
	}
	resolved, unresolved, err := store.CountByResolution(domain)
	if err != nil {
		return err
	}

	summary := struct {
		Domain          string   `json:"domain"`
		File            string   `json:"file"`
		Source          string   `json:"source"`
		TotalLines      int      `json:"total_lines"`
		Imported        int      `json:"imported"`
		ImportedWithIPs int      `json:"imported_with_ips"`
		AutoResolved    int      `json:"auto_resolved"`
		Resolved        int      `json:"resolved"`
		Unresolved      int      `json:"unresolved"`
		Skipped         int      `json:"skipped"`
		OutOfScope      int      `json:"out_of_scope"`
		OutOfScopeHosts []string `json:"out_of_scope_hosts,omitempty"`
		Database        string   `json:"database"`
	}{
		Domain:          domain,
		File:            filePath,
		Source:          source,
		TotalLines:      imported.TotalLines,
		Imported:        len(entries),
		ImportedWithIPs: len(resolutions),
		AutoResolved:    countAliveResults(autoResolved),
		Resolved:        resolved,
		Unresolved:      unresolved,
		Skipped:         imported.Skipped,
		OutOfScope:      len(imported.OutOfScope),
		OutOfScopeHosts: imported.OutOfScope,
		Database:        cfg.Database.Path,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func parseDomainImport(reader io.Reader, domain string, source string) (domainImportResult, error) {
	seen := make(map[string]struct{}, 128)
	sourceByHost := make(map[string][]string, 128)
	ipsByHost := make(map[string]map[string]struct{}, 128)
	result := domainImportResult{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		result.TotalLines++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			result.Skipped++
			continue
		}

		host, ips := parseDomainImportLine(line)
		if host == "" {
			result.Skipped++
			continue
		}
		if !isImportRecordInScope(host, ips, domain) {
			if _, ok := seen["out:"+host]; !ok {
				result.OutOfScope = append(result.OutOfScope, host)
				seen["out:"+host] = struct{}{}
			}
			continue
		}
		if _, ok := sourceByHost[host]; !ok {
			sourceByHost[host] = []string{source}
		}
		if len(ips) == 0 {
			continue
		}
		if _, ok := ipsByHost[host]; !ok {
			ipsByHost[host] = make(map[string]struct{}, len(ips))
		}
		for _, ip := range ips {
			ipsByHost[host][ip] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return domainImportResult{}, err
	}

	hosts := make([]string, 0, len(sourceByHost))
	for host := range sourceByHost {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	result.Entries = make([]discovery.Entry, 0, len(hosts))
	result.Resolutions = make([]resolver.Result, 0, len(ipsByHost))
	for _, host := range hosts {
		result.Entries = append(result.Entries, discovery.Entry{
			Subdomain: host,
			Sources:   sourceByHost[host],
		})
		if len(ipsByHost[host]) == 0 {
			continue
		}
		ips := make([]string, 0, len(ipsByHost[host]))
		for ip := range ipsByHost[host] {
			ips = append(ips, ip)
		}
		slices.Sort(ips)
		result.Resolutions = append(result.Resolutions, resolver.Result{
			Subdomain: host,
			IPs:       ips,
			Alive:     true,
		})
	}
	slices.Sort(result.OutOfScope)
	return result, nil
}

func mergeImportedSources(store *storage.Store, domain string, entries []discovery.Entry) ([]discovery.Entry, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	existing, err := store.SubdomainsByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	sourcesByHost := make(map[string][]string, len(existing))
	for _, record := range existing {
		sourcesByHost[record.Subdomain] = record.Sources
	}

	out := make([]discovery.Entry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, discovery.Entry{
			Subdomain: entry.Subdomain,
			Sources:   mergeSources(sourcesByHost[entry.Subdomain], entry.Sources),
		})
	}
	return out, nil
}

func mergeImportedResolutions(store *storage.Store, domain string, results []resolver.Result) ([]resolver.Result, error) {
	if len(results) == 0 {
		return nil, nil
	}

	existing, err := store.SubdomainsByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	ipsByHost := make(map[string][]string, len(existing))
	for _, record := range existing {
		ipsByHost[record.Subdomain] = record.IPs
	}

	out := make([]resolver.Result, 0, len(results))
	for _, result := range results {
		out = append(out, resolver.Result{
			Subdomain: result.Subdomain,
			IPs:       mergeIPs(ipsByHost[result.Subdomain], result.IPs),
			Alive:     len(result.IPs) > 0,
		})
	}
	return out, nil
}

func autoResolveImportedHosts(cmd *cobra.Command, cfg config.Config, store *storage.Store, domain string, imported domainImportResult) ([]resolver.Result, error) {
	hosts := importedHostsNeedingResolution(imported)
	if len(hosts) == 0 {
		return nil, nil
	}

	timeout, err := cfg.ResolverTimeout()
	if err != nil {
		return nil, err
	}

	resolveResults, err := resolver.ResolveAll(cmd.Context(), hosts, resolver.Config{
		Binary:        cfg.Resolver.Binary,
		Workers:       cfg.Resolver.Workers,
		Timeout:       timeout,
		ResolversFile: cfg.Resolver.ResolversFile,
	}, nil)
	if err != nil {
		return nil, err
	}
	if err := store.SaveResolutions(domain, resolveResults); err != nil {
		return nil, err
	}
	return resolveResults, nil
}

func importedHostsNeedingResolution(imported domainImportResult) []string {
	if len(imported.Entries) == 0 {
		return nil
	}

	resolvedByImport := make(map[string]struct{}, len(imported.Resolutions))
	for _, result := range imported.Resolutions {
		if result.Alive {
			resolvedByImport[result.Subdomain] = struct{}{}
		}
	}

	out := make([]string, 0, len(imported.Entries))
	for _, entry := range imported.Entries {
		if _, ok := resolvedByImport[entry.Subdomain]; ok {
			continue
		}
		if net.ParseIP(entry.Subdomain) != nil {
			continue
		}
		out = append(out, entry.Subdomain)
	}
	return out
}

func countAliveResults(results []resolver.Result) int {
	count := 0
	for _, result := range results {
		if result.Alive {
			count++
		}
	}
	return count
}

func mergeSources(values ...[]string) []string {
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for _, group := range values {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return out
}

func mergeIPs(values ...[]string) []string {
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for _, group := range values {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if net.ParseIP(value) == nil {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	slices.Sort(out)
	return out
}

func hostMatchesDomain(host string, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func parseDomainImportLine(line string) (string, []string) {
	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return "", nil
	}

	var host string
	ips := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			ips = append(ips, ip.String())
			continue
		}
		if host == "" {
			host = provider.NormalizeCandidate(part)
		}
	}
	if host == "" && len(ips) > 0 {
		host = ips[0]
	}
	return host, mergeIPs(ips)
}

func isImportRecordInScope(host string, ips []string, domain string) bool {
	if hostMatchesDomain(host, domain) {
		return true
	}
	return len(ips) > 0 && net.ParseIP(host) != nil
}
