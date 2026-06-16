package cmd

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/modules/exporter"
	"github.com/indigo-sadland/logy/internal/storage"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

const defaultAnytypeVersion = "2025-11-08"

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export saved recon data to Anytype",
}

var exportAnytypeCmd = &cobra.Command{
	Use:   "anytype --domain example.com --engagement \"Client Pentest\"",
	Short: "Push saved assets and services into Anytype",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExportAnytype(cmd)
	},
}

var anytypeExport anytypeExportOptions

type anytypeExportOptions struct {
	exporter.AnytypeOptions
	ConfigPath string
	Yes        bool
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.AddCommand(exportAnytypeCmd)

	exportAnytypeCmd.Flags().StringVarP(&anytypeExport.Domain, "domain", "d", "", "root domain to export from the database")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.EngagementName, "engagement", "", "Anytype Engagement object name to link exported objects to")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.SpaceID, "space", envOrDefault("ANYTYPE_SPACE_ID", ""), "Anytype space id")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.BaseURL, "url", envOrDefault("ANYTYPE_URL", "http://127.0.0.1:31009"), "Anytype Local API base URL")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.Token, "token", envOrDefault("ANYTYPE_TOKEN", ""), "Anytype API token")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.Version, "anytype-version", envOrDefault("ANYTYPE_VERSION", defaultAnytypeVersion), "Anytype API version header")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ConfigPath, "config", defaultConfigPath(), "path to logy's config yaml")
	exportAnytypeCmd.Flags().BoolVar(&anytypeExport.OnlyScans, "only-scans", false, "export only Scan objects")
	// Suspicious hosts keep scan evidence, but skip structured service inventory.
	exportAnytypeCmd.Flags().IntVar(&anytypeExport.SuspiciousOpenPorts, "suspicious-open-ports", 256, "skip Service and Service historical observation export for hosts with at least this many open ports; 0 disables filtering")
	exportAnytypeCmd.Flags().BoolVar(&anytypeExport.Yes, "yes", false, "skip interactive export confirmation")

	exportAnytypeCmd.Flags().StringVar(&anytypeExport.EngagementTypeKey, "engagement-type", "engagement", "Anytype type key for Engagement objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.AssetTypeKey, "asset-type", "asset", "Anytype type key for Asset objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ServiceTypeKey, "service-type", "service", "Anytype type key for Service objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ScanTypeKey, "scan-type", "scan", "Anytype type key for Scan objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.WebAppObservationTypeKey, "web-app-observation-type", "web_app_observation", "Anytype type key for Web app observation objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ServiceHistoricalObservationTypeKey, "service-historical-observation-type", "historical_observation", "Anytype type key for Service historical observation objects")

	exportAnytypeCmd.Flags().StringVar(&anytypeExport.AliasPropertyKey, "alias-property", "alias", "Anytype property key for Asset aliases")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.EngagementPropertyKey, "engagement-property", "engagement", "Anytype property key for Engagement object links")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.AssetPropertyKey, "asset-property", "asset", "Anytype property key for Asset object links")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.PortPropertyKey, "port-property", "port", "Anytype property key for Service port")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.StatePropertyKey, "state-property", "state", "Anytype property key for Service state")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ServicePropertyKey, "service-property", "service_type", "Anytype property key for Service name/type")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.BannerPropertyKey, "banner-property", "banner", "Anytype property key for Service banner/version")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ScanStatusPropertyKey, "scan-status-property", "scan_status", "Anytype select property key for Scan status")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.TimestampPropertyKey, "timestamp-property", "timestamp", "Anytype text property key for Scan start timestamp")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.WebAppObservationTitlePropertyKey, "web-app-observation-title-property", "title", "Anytype property key for web app observation title")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.WebAppObservationStatusCodePropertyKey, "web-app-observation-status-code-property", "status_code", "Anytype property key for web app observation status code")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.WebAppObservationTechnologiesPropertyKey, "web-app-observation-technologies-property", "technologies", "Anytype property key for web app observation technologies")

	exportAnytypeCmd.Flags().StringVar(&anytypeExport.HistoricalObservationServiceLinkPropertyKey, "service-historical-observation-service-link-property", "service_link", "Anytype property key for historical observation service link")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.HistoricalObservationPortPropertyKey, "service-historical-observation-port-property", "port", "Anytype property key for historical observation port")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.HistoricalObservationObservedStatePropertyKey, "service-historical-observation-state-property", "observed_state", "Anytype property key for historical observation state")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.HistoricalObservationObservedBannerPropertyKey, "service-historical-observation-banner-property", "observed_banner", "Anytype property key for historical observation banner")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.HistoricalObservationObservedServicePropertyKey, "service-historical-observation-service-property", "observed_service", "Anytype property key for historical observation service")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.HistoricalObservationTimestampPropertyKey, "service-historical-observation-timestamp-property", "timestamp", "Anytype property key for historical observation timestamp")

	hideAnytypeAdvancedFlags(exportAnytypeCmd)
}

func hideAnytypeAdvancedFlags(cmd *cobra.Command) {
	for _, name := range []string{
		"engagement-type",
		"asset-type",
		"service-type",
		"scan-type",
		"web-app-observation-type",
		"service-historical-observation-type",
		"alias-property",
		"engagement-property",
		"asset-property",
		"port-property",
		"state-property",
		"service-property",
		"banner-property",
		"scan-status-property",
		"timestamp-property",
		"web-app-observation-title-property",
		"web-app-observation-status-code-property",
		"web-app-observation-technologies-property",
		"service-historical-observation-service-link-property",
		"service-historical-observation-port-property",
		"service-historical-observation-state-property",
		"service-historical-observation-banner-property",
		"service-historical-observation-service-property",
		"service-historical-observation-timestamp-property",
	} {
		_ = cmd.Flags().MarkHidden(name)
	}
}

func runExportAnytype(cmd *cobra.Command) error {
	opts := normalizeAnytypeExportOptions(anytypeExport)
	if opts.SpaceID == "" || opts.Token == "" {
		values, err := loadEncryptedSecretsIfNeeded()
		if err != nil {
			return err
		}
		if values.Anytype != nil {
			if opts.SpaceID == "" {
				opts.SpaceID = values.Anytype.SpaceID
			}
			if opts.Token == "" {
				opts.Token = values.Anytype.Token
			}
		}
		opts = normalizeAnytypeExportOptions(opts)
	}
	if err := exporter.ValidateAnytypeOptions(opts.AnytypeOptions); err != nil {
		return err
	}
	if opts.ConfigPath == "" {
		return fmt.Errorf("--config is required\n")
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	opts.DatabasePath = cfg.Database.Path

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	var subdomains []storage.SubdomainRecord
	if !opts.OnlyScans {
		subdomains, err = store.SubdomainsByDomain(opts.Domain)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("no subdomain results for domain %s\n", opts.Domain)
			}
			return err
		}
	}

	scans, err := store.PortScansByDomain(opts.Domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			scans = nil
		} else {
			return err
		}
	}

	runs, err := store.CommandRunsByDomain(opts.Domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if opts.OnlyScans {
				return fmt.Errorf("no command run results for domain %s\n", opts.Domain)
			}
			runs = nil
		} else {
			return err
		}
	}
	// Historical observations are optional; older domains may not have any yet.
	var observations []storage.ServiceHistoricalObservationRecord
	if !opts.OnlyScans {
		observations, err = store.ServiceHistoricalObservationsByDomain(opts.Domain)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				observations = nil
			} else {
				return err
			}
		}
	}
	// Web probe history exports independently from the service graph.
	var webProbes []storage.WebProbeRecord
	if !opts.OnlyScans {
		webProbes, err = store.WebProbesByDomain(opts.Domain)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				webProbes = nil
			} else {
				return err
			}
		}
	}
	preview, err := exporter.PreviewAnytype(cmd.Context(), opts.AnytypeOptions, subdomains, scans, observations, webProbes, runs)
	if err != nil {
		return err
	}
	if !opts.Yes {
		if err := confirmAnytypeExport(preview); err != nil {
			return err
		}
	}

	progress := newAnytypeProgressBar()
	defer progress.finish()
	if progress.enabled {
		opts.Progress = progress.report
	}

	// Export uses the same preview inputs so suspicious-host counts stay aligned.
	result, err := exporter.ExportAnytype(cmd.Context(), opts.AnytypeOptions, subdomains, scans, observations, webProbes, runs)
	if err != nil {
		return err
	}

	summary := struct {
		Domain                                       string `json:"domain"`
		Engagement                                   string `json:"engagement"`
		EngagementID                                 string `json:"engagement_id"`
		Database                                     string `json:"database"`
		AssetsCreated                                int    `json:"assets_created"`
		AssetsReused                                 int    `json:"assets_reused"`
		AssetsUpdated                                int    `json:"assets_updated"`
		ServicesCreated                              int    `json:"services_created"`
		ServicesReused                               int    `json:"services_reused"`
		SuspiciousHosts                              int    `json:"suspicious_hosts"`
		ServicesSkippedSuspiciousHosts               int    `json:"services_skipped_suspicious_hosts"`
		WebAppObservationsCreated                    int    `json:"web_app_observations_created"`
		WebAppObservationsSkipped                    int    `json:"web_app_observations_skipped"`
		ServiceHistoricalObservationsCreated         int    `json:"service_historical_observations_created"`
		ServiceHistoricalObservationsSkipped         int    `json:"service_historical_observations_skipped"`
		HistoricalObservationsSkippedSuspiciousHosts int    `json:"historical_observations_skipped_suspicious_hosts"`
		ScansCreated                                 int    `json:"scans_created"`
		ScansSkipped                                 int    `json:"scans_skipped"`
		AnytypeSpace                                 string `json:"anytype_space"`
		AnytypeURL                                   string `json:"anytype_url"`
	}{
		Domain:                               result.Domain,
		Engagement:                           result.Engagement,
		EngagementID:                         result.EngagementID,
		Database:                             cfg.Database.Path,
		AssetsCreated:                        result.AssetsCreated,
		AssetsReused:                         result.AssetsReused,
		AssetsUpdated:                        result.AssetsUpdated,
		ServicesCreated:                      result.ServicesCreated,
		ServicesReused:                       result.ServicesReused,
		SuspiciousHosts:                      result.SuspiciousHosts,
		ServicesSkippedSuspiciousHosts:       result.ServicesSkippedSuspiciousHosts,
		WebAppObservationsCreated:            result.WebAppObservationsCreated,
		WebAppObservationsSkipped:            result.WebAppObservationsSkipped,
		ServiceHistoricalObservationsCreated: result.ServiceHistoricalObservationsCreated,
		ServiceHistoricalObservationsSkipped: result.ServiceHistoricalObservationsSkipped,
		HistoricalObservationsSkippedSuspiciousHosts: result.HistoricalObservationsSkippedSuspiciousHosts,
		ScansCreated: result.ScansCreated,
		ScansSkipped: result.ScansSkipped,
		AnytypeSpace: result.AnytypeSpace,
		AnytypeURL:   result.AnytypeURL,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func normalizeAnytypeExportOptions(opts anytypeExportOptions) anytypeExportOptions {
	opts.AnytypeOptions = exporter.NormalizeAnytypeOptions(opts.AnytypeOptions)
	opts.ConfigPath = strings.TrimSpace(opts.ConfigPath)
	return opts
}

func confirmAnytypeExport(preview exporter.AnytypePreview) error {
	fmt.Fprintf(os.Stderr, "Anytype export preview:\n")
	fmt.Fprintf(os.Stderr, "  domain:        %s\n", preview.Domain)
	fmt.Fprintf(os.Stderr, "  engagement:    %s\n", preview.Engagement)
	fmt.Fprintf(os.Stderr, "  engagement id: %s\n", preview.EngagementID)
	fmt.Fprintf(os.Stderr, "  space id:      %s\n", preview.AnytypeSpace)
	fmt.Fprintf(os.Stderr, "  url:           %s\n", preview.AnytypeURL)
	fmt.Fprintf(os.Stderr, "  assets:        %d\n", preview.Assets)
	fmt.Fprintf(os.Stderr, "  services:      %d\n", preview.Services)
	fmt.Fprintf(os.Stderr, "  suspicious hosts: %d\n", preview.SuspiciousHosts)
	fmt.Fprintf(os.Stderr, "  services skipped: %d\n", preview.ServicesSkippedSuspiciousHosts)
	fmt.Fprintf(os.Stderr, "  web apps:      %d\n", preview.WebAppObservations)
	fmt.Fprintf(os.Stderr, "  history:       %d\n", preview.ServiceHistoricalObservations)
	fmt.Fprintf(os.Stderr, "  history skipped: %d\n", preview.HistoricalObservationsSkippedSuspiciousHosts)
	fmt.Fprintf(os.Stderr, "  scans:         %d\n", preview.Scans)
	answer, err := promptLine("Proceed with export? [y/N]: ")
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return fmt.Errorf("export cancelled")
	}
	return nil
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

type anytypeProgressBar struct {
	enabled bool
	lastLen int
}

// Render live progress only in interactive terminals so JSON output stays clean.
func newAnytypeProgressBar() *anytypeProgressBar {
	return &anytypeProgressBar{
		enabled: isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd()),
	}
}

// Rewrite one stderr line in place as each exporter step completes.
func (p *anytypeProgressBar) report(progress exporter.AnytypeProgress) {
	if !p.enabled {
		return
	}

	total := progress.Total
	if total <= 0 {
		total = 1
	}
	completed := progress.Completed
	if completed > total {
		completed = total
	}

	const width = 24
	filled := completed * width / total
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	line := fmt.Sprintf("\r[*] anytype export: [%s] %d/%d phase=%s", bar, completed, total, progress.Phase)
	if pad := p.lastLen - len(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	fmt.Fprint(os.Stderr, line)
	p.lastLen = len(line)
}

// Finish the in-place line so later stderr or shell output starts cleanly.
func (p *anytypeProgressBar) finish() {
	if !p.enabled || p.lastLen == 0 {
		return
	}
	fmt.Fprint(os.Stderr, "\n")
	p.lastLen = 0
}
