package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"github.com/indigo-sadland/logy/internal/pipeline"
	"github.com/indigo-sadland/logy/internal/storage"
	"github.com/indigo-sadland/logy/internal/utils/output"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var runVerbose bool

var domainCmd = &cobra.Command{
	Use:     "domain",
	Short:   "Domain-focused reconnaissance commands",
	GroupID: "domain",
}

var enumCmd = &cobra.Command{
	Use:   "enum --domain example.com | enum --asn AS3333 [--domain-filter example.com]",
	Short: "Discover subdomains, resolve them and save the results",
	RunE: func(cmd *cobra.Command, args []string) error {

		domain, _ := cmd.Flags().GetString("domain")
		asn, _ := cmd.Flags().GetString("asn")
		domainFilter, _ := cmd.Flags().GetString("domain-filter")
		configPath, _ := cmd.Flags().GetString("config")
		ctx := context.Background()

		if strings.TrimSpace(domain) == "" && strings.TrimSpace(asn) == "" {
			resolvedDomain, err := resolveDomainLabel(domain)
			if err != nil {
				return err
			}
			domain = resolvedDomain
		}

		// Detect type of provided target (domain or asn)
		target, targetType, matchDomain, err := resolveEnumTarget(domain, asn, domainFilter)
		if err != nil {
			return err
		}

		// Check if user's terminal supports colored output
		stdoutSupportsColor := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
		output.Init(stdoutSupportsColor)

		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}

		if cfg.Discovery.ToolConfig["bufferover"].APIKey == "" && discoveryToolEnabled(cfg.Discovery.EnabledTools(), "bufferover") {
			values, err := loadEncryptedSecretsIfNeeded()
			if err != nil {
				return err
			}
			if values.BufferOver != nil {
				toolCfg := cfg.Discovery.ToolConfig["bufferover"]
				toolCfg.APIKey = values.BufferOver.APIKey
				cfg.Discovery.ToolConfig["bufferover"] = toolCfg
			}
			if cfg.Discovery.ToolConfig["bufferover"].APIKey == "" {
				return fmt.Errorf("bufferover api key is required; run `logy secrets set bufferover` or set discovery.tool_config.bufferover.api_key")
			}
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

		discoveryCfg := discovery.Config{
			ToolConfig: make(map[string]discovery.ToolConfig, len(cfg.Discovery.ToolConfig)),
			Logf:       output.Print,
		}
		for name, toolCfg := range cfg.Discovery.ToolConfig {
			normalized := strings.ToLower(strings.TrimSpace(name))
			if normalized == "puredns" {
				continue
			}
			discoveryCfg.ToolConfig[normalized] = discovery.ToolConfig{
				ResolversFile: toolCfg.ResolversFile,
				ConfigFile:    toolCfg.ConfigFile,
				APIKey:        toolCfg.APIKey,
				BaseURL:       toolCfg.BaseURL,
			}
		}

		enabledTools := make([]string, 0, len(cfg.Discovery.EnabledTools()))
		for _, tool := range cfg.Discovery.EnabledTools() {
			if strings.EqualFold(strings.TrimSpace(tool), "puredns") {
				continue
			}
			enabledTools = append(enabledTools, tool)
		}

		// Build provider instances
		providers := discovery.ProvidersFromNames(enabledTools, discoveryCfg)
		if len(providers) == 0 {
			return fmt.Errorf("no valid tools selected in %s\n", configPath)
		}
		if err := validateEnumProviders(providers, targetType); err != nil {
			return err
		}

		engine := pipeline.Engine{
			Discovery: providers,
			Resolver: resolver.Config{
				Binary:        cfg.Resolver.Binary,
				Workers:       cfg.Resolver.Workers,
				Timeout:       timeout,
				ResolversFile: cfg.Resolver.ResolversFile,
			},
			Store:   store,
			Logf:    output.Print,
			Verbose: runVerbose,
		}

		report, err := engine.Run(ctx, target, matchDomain)
		if err != nil {
			return err
		}
		for _, warning := range report.Warnings {
			output.Print("[!] warning: %s\n", warning)
		}
		if report.Warning != nil {
			output.Print("[!] warning: %v\n", report.Warning)
		}

		summary := struct {
			Target       string `json:"target"`
			TargetType   string `json:"target_type"`
			DomainFilter string `json:"domain_filter,omitempty"`
			Discovered   int    `json:"discovered"`
			Resolved     int    `json:"resolved"`
			Unresolved   int    `json:"unresolved"`
			Database     string `json:"database"`
		}{
			Target:       target,
			TargetType:   targetType,
			DomainFilter: domainFilter,
			Discovered:   report.Discovered,
			Resolved:     report.Resolved,
			Unresolved:   report.Unresolved,
			Database:     cfg.Database.Path,
		}

		enc := json.NewEncoder(os.Stdout)
		return enc.Encode(summary)
	},
}

var showCmd = &cobra.Command{
	Use:   "show --domain example.com",
	Short: "Show discovered subdomains",
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

		records, err := store.SubdomainsByDomain(domain)
		if err != nil {
			return err
		}

		type outputRecord struct {
			Subdomain      string   `json:"subdomain"`
			Sources        []string `json:"sources"`
			Resolved       bool     `json:"resolved"`
			IPs            []string `json:"ips,omitempty"`
			ResolveError   string   `json:"resolve_error,omitempty"`
			FirstSeenAt    string   `json:"first_seen_at"`
			LastSeenAt     string   `json:"last_seen_at"`
			LastResolvedAt string   `json:"last_resolved_at,omitempty"`
			UpdatedAt      string   `json:"updated_at"`
		}

		data := struct {
			Domain     string         `json:"domain"`
			Subdomains []outputRecord `json:"subdomains"`
		}{
			Domain:     domain,
			Subdomains: make([]outputRecord, 0, len(records)),
		}

		for _, record := range records {
			lastResolvedAt := ""
			if record.LastResolvedAt.Valid {
				lastResolvedAt = record.LastResolvedAt.Time.Format("2006-01-02T15:04:05Z07:00")
			}
			data.Subdomains = append(data.Subdomains, outputRecord{
				Subdomain:      record.Subdomain,
				Sources:        record.Sources,
				Resolved:       record.Resolved,
				IPs:            record.IPs,
				ResolveError:   record.ResolveError,
				FirstSeenAt:    record.FirstSeenAt.Format("2006-01-02T15:04:05Z07:00"),
				LastSeenAt:     record.LastSeenAt.Format("2006-01-02T15:04:05Z07:00"),
				LastResolvedAt: lastResolvedAt,
				UpdatedAt:      record.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	},
}

func init() {
	rootCmd.AddCommand(domainCmd)
	domainCmd.AddCommand(enumCmd)
	enumCmd.Flags().StringP("domain", "d", "", "target domain for subdomain enumeration")
	enumCmd.Flags().String("asn", "", "target autonomous system number, for example AS3333")
	enumCmd.Flags().String("domain-filter", "", "keep only ASN discoveries that match this domain")
	enumCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
	enumCmd.Flags().BoolVarP(&runVerbose, "verbose", "v", false, "print each discovered subdomain during discovery")

	domainCmd.AddCommand(showCmd)
	showCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
	showCmd.Flags().StringP("domain", "d", "", "target domain to show from the database")
}

func resolveEnumTarget(domain string, asn string, domainFilter string) (target string, targetType string, matchDomain string, err error) {
	domain = strings.TrimSpace(domain)
	asn = strings.TrimSpace(asn)
	domainFilter = strings.TrimSpace(domainFilter)

	switch {
	case domainFilter != "" && asn == "":
		return "", "", "", fmt.Errorf("--domain-filter requires --asn")
	case domain == "" && asn == "":
		return "", "", "", fmt.Errorf("at least one of --domain or --asn is required")
	case domain != "" && asn != "":
		return "", "", "", fmt.Errorf("--domain and --asn are mutually exclusive; use --domain-filter with --asn")
	case asn != "":
		return asn, "asn", domainFilter, nil
	default:
		return domain, "domain", domain, nil
	}
}

func validateEnumProviders(providers []provider.Provider, targetType string) error {
	for _, pr := range providers {
		switch {
		case targetType == "asn" && pr.Name() != "ripestat":
			return fmt.Errorf("--asn scans support only the ripestat discovery provider; disable %s in your config file", pr.Name())
		case targetType == "domain" && pr.Name() == "ripestat":
			return fmt.Errorf("ripestat requires --asn; remove it from enabled discovery tools or run with --asn")
		}
	}
	return nil
}

func discoveryToolEnabled(tools []string, want string) bool {
	for _, tool := range tools {
		if strings.EqualFold(strings.TrimSpace(tool), want) {
			return true
		}
	}
	return false
}
