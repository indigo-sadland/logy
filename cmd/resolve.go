package cmd

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/permutation"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"github.com/indigo-sadland/logy/internal/storage"
	"github.com/indigo-sadland/logy/internal/utils/output"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var resolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Resolve domains",
}

var resolveVHostBinary string
var resolvePermutationsFile string
var resolvePermutationBinary string
var resolvePermutationDepth int
var resolvePermutationNumbers int
var resolvePermutationMinDup bool
var resolvePermutationMD bool

var resolveVHostCmd = &cobra.Command{
	Use:   "vhost --domain example.com",
	Short: "Resolve unresolved subdomains using virtual host detection",
	RunE: func(cmd *cobra.Command, args []string) error {

		domain, _ := cmd.Flags().GetString("domain")
		configPath, _ := cmd.Flags().GetString("config")
		domain, err := requireDomainLabel(domain)
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

		exists, err := store.DomainExists(domain)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("no data found for domain %s\n", domain)
		}

		unresolvedDomains, err := store.UnresolvedSubdomainsByDomain(domain)
		if err != nil && !isNoRows(err) {
			return err
		}
		if isNoRows(err) {
			unresolvedDomains = nil
		}

		candidates, err := store.PermutationCandidatesByDomain(domain)
		if err != nil && !isNoRows(err) {
			return err
		}
		if isNoRows(err) {
			candidates = nil
		}

		ips, err := store.ResolvedIPsByDomain(domain)
		if err != nil {
			return err
		}

		vhostHosts := mergeUniqueHosts(unresolvedDomains, permutationCandidateHosts(candidates))
		results, err := resolver.ResolveVHosts(cmd.Context(), vhostHosts, ips, resolver.VHostConfig{
			Binary: resolveVHostBinary,
		}, output.Print)
		if err != nil {
			return err
		}

		promotedEntries := promoteCandidateEntries(results, candidates)
		if err := store.SaveDiscoveries(domain, promotedEntries); err != nil {
			return err
		}
		if err := store.SaveVHostResolutions(domain, results); err != nil {
			return err
		}
		if err := store.DeletePermutationCandidates(domain, resolvedResultHosts(results)); err != nil {
			return err
		}

		resolvedRecords := make([]struct {
			Subdomain string   `json:"subdomain"`
			IPs       []string `json:"ips,omitempty"`
		}, 0, len(results))
		for _, result := range results {
			if !result.Alive {
				continue
			}
			resolvedRecords = append(resolvedRecords, struct {
				Subdomain string   `json:"subdomain"`
				IPs       []string `json:"ips,omitempty"`
			}{
				Subdomain: result.Subdomain,
				IPs:       result.IPs,
			})
		}

		data := struct {
			Domain            string `json:"domain"`
			UnresolvedInput   int    `json:"unresolved_input"`
			CandidateInput    int    `json:"candidate_input"`
			HostInput         int    `json:"host_input"`
			ResolvedIPsInput  int    `json:"resolved_ips_input"`
			NewlyResolved     int    `json:"newly_resolved"`
			ResolvedSubdomain []struct {
				Subdomain string   `json:"subdomain"`
				IPs       []string `json:"ips,omitempty"`
			} `json:"resolved_subdomains"`
		}{
			Domain:            domain,
			UnresolvedInput:   len(unresolvedDomains),
			CandidateInput:    len(candidates),
			HostInput:         len(vhostHosts),
			ResolvedIPsInput:  len(ips),
			NewlyResolved:     len(resolvedRecords),
			ResolvedSubdomain: resolvedRecords,
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	},
}

var resolvePermuteCmd = &cobra.Command{
	Use:   "permute --domain example.com --permutations-file permutations.txt",
	Short: "Generate and resolve subdomain permutations from discovered domain state",
	RunE: func(cmd *cobra.Command, args []string) error {

		domain, _ := cmd.Flags().GetString("domain")
		configPath, _ := cmd.Flags().GetString("config")
		domain, err := requireDomainLabel(domain)
		if err != nil {
			return err
		}
		resolvePermutationsFile = strings.TrimSpace(resolvePermutationsFile)
		if resolvePermutationsFile == "" {
			return fmt.Errorf("--permutations-file is required\n")
		}

		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}

		timeout, err := cfg.ResolverTimeout()
		if err != nil {
			return err
		}

		store, err := storage.Open(cfg.Database.Path)
		if err != nil {
			return err
		}
		defer store.Close()

		exists, err := store.DomainExists(domain)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("no data found for domain %s\n", domain)
		}

		knownSubdomains, err := store.AllSubdomainsByDomain(domain)
		if err != nil {
			return err
		}

		generated, err := permutation.Generate(cmd.Context(), knownSubdomains, domain, permutation.Config{
			Binary:           resolvePermutationBinary,
			PermutationsFile: resolvePermutationsFile,
			Depth:            resolvePermutationDepth,
			Numbers:          resolvePermutationNumbers,
			MinDup:           resolvePermutationMinDup,
			MD:               resolvePermutationMD,
		}, output.Print)
		if err != nil {
			return err
		}

		newCandidates := filterNewSubdomains(generated, knownSubdomains)
		resolveResults, err := resolver.ResolveAll(cmd.Context(), newCandidates, resolver.Config{
			Binary:        cfg.Resolver.Binary,
			Workers:       cfg.Resolver.Workers,
			Timeout:       timeout,
			ResolversFile: cfg.Resolver.ResolversFile,
		}, output.Print)
		if err != nil {
			return err
		}

		resolvedEntries, resolvedResults, unresolvedEntries := splitPermutationResults(resolveResults)
		if err := store.SaveDiscoveries(domain, resolvedEntries); err != nil {
			return err
		}
		if err := store.SaveResolutions(domain, resolvedResults); err != nil {
			return err
		}
		if err := store.SavePermutationCandidates(domain, unresolvedEntries); err != nil {
			return err
		}

		data := struct {
			Domain           string `json:"domain"`
			SeedSubdomains   int    `json:"seed_subdomains"`
			Generated        int    `json:"generated"`
			NewCandidates    int    `json:"new_candidates"`
			StoredCandidates int    `json:"stored_candidates"`
			Resolved         int    `json:"resolved"`
			Unresolved       int    `json:"unresolved"`
			ResolverBinary   string `json:"resolver_binary"`
			PermutationTool  string `json:"permutation_tool"`
			PermutationsFile string `json:"permutations_file"`
			Database         string `json:"database"`
		}{
			Domain:           domain,
			SeedSubdomains:   len(knownSubdomains),
			Generated:        len(generated),
			NewCandidates:    len(newCandidates),
			StoredCandidates: len(unresolvedEntries),
			Resolved:         len(resolvedResults),
			Unresolved:       len(unresolvedEntries),
			ResolverBinary:   cfg.Resolver.Binary,
			PermutationTool:  normalizePermutationBinary(resolvePermutationBinary),
			PermutationsFile: resolvePermutationsFile,
			Database:         cfg.Database.Path,
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	},
}

func init() {
	domainCmd.AddCommand(resolveCmd)
	resolveCmd.AddCommand(resolveVHostCmd)
	resolveCmd.AddCommand(resolvePermuteCmd)
	resolveVHostCmd.Flags().StringP("domain", "d", "", "target root domain to resolve using virtual host detection")
	resolveVHostCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
	resolvePermuteCmd.Flags().StringP("domain", "d", "", "target domain to generate permutations for")
	resolvePermuteCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
	resolvePermuteCmd.Flags().StringVarP(&resolvePermutationsFile, "permutations-file", "p", "", "permutation list file for gotator")
	resolvePermuteCmd.Flags().IntVar(&resolvePermutationDepth, "depth", 1, "permutation depth for gotator")
	resolvePermuteCmd.Flags().IntVar(&resolvePermutationNumbers, "numbers", 10, "maximum appended numbers for gotator")
	resolvePermuteCmd.Flags().BoolVar(&resolvePermutationMinDup, "mindup", true, "enable gotator mindup mode")
	resolvePermuteCmd.Flags().BoolVar(&resolvePermutationMD, "md", true, "enable gotator md mode")
}

func normalizeDomainValue(domain string) string {
	return strings.TrimSpace(domain)
}

func mergeUniqueHosts(groups ...[]string) []string {
	seen := make(map[string]struct{}, 128)
	out := make([]string, 0, 128)
	for _, group := range groups {
		for _, host := range group {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}
	slices.Sort(out)
	return out
}

func permutationCandidateHosts(records []storage.PermutationCandidateRecord) []string {
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, record.Subdomain)
	}
	return out
}

func promoteCandidateEntries(results []resolver.Result, candidates []storage.PermutationCandidateRecord) []discovery.Entry {
	if len(results) == 0 || len(candidates) == 0 {
		return nil
	}
	sourcesByHost := make(map[string][]string, len(candidates))
	for _, candidate := range candidates {
		sourcesByHost[candidate.Subdomain] = slices.Clone(candidate.Sources)
	}
	out := make([]discovery.Entry, 0, len(results))
	for _, result := range results {
		if !result.Alive {
			continue
		}
		sources, ok := sourcesByHost[result.Subdomain]
		if !ok {
			continue
		}
		out = append(out, discovery.Entry{
			Subdomain: result.Subdomain,
			Sources:   sources,
		})
	}
	return out
}

func resolvedResultHosts(results []resolver.Result) []string {
	out := make([]string, 0, len(results))
	for _, result := range results {
		if result.Alive {
			out = append(out, result.Subdomain)
		}
	}
	return out
}

func splitPermutationResults(results []resolver.Result) ([]discovery.Entry, []resolver.Result, []discovery.Entry) {
	resolvedEntries := make([]discovery.Entry, 0, len(results))
	resolvedResults := make([]resolver.Result, 0, len(results))
	unresolvedEntries := make([]discovery.Entry, 0, len(results))
	for _, result := range results {
		entry := discovery.Entry{
			Subdomain: result.Subdomain,
			Sources:   []string{"gotator"},
		}
		if result.Alive {
			resolvedEntries = append(resolvedEntries, entry)
			resolvedResults = append(resolvedResults, result)
			continue
		}
		unresolvedEntries = append(unresolvedEntries, entry)
	}
	return resolvedEntries, resolvedResults, unresolvedEntries
}

func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

func filterNewSubdomains(candidates []string, known []string) []string {

	if len(candidates) == 0 {
		return nil
	}
	knownSet := make(map[string]struct{}, len(known))
	for _, host := range known {
		knownSet[host] = struct{}{}
	}

	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := knownSet[candidate]; ok {
			continue
		}
		out = append(out, candidate)
	}
	slices.Sort(out)
	return out
}

func normalizePermutationBinary(binary string) string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return "gotator"
	}
	return binary
}
