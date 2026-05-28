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
	exportAnytypeCmd.Flags().BoolVar(&anytypeExport.Yes, "yes", false, "skip interactive export confirmation")

	exportAnytypeCmd.Flags().StringVar(&anytypeExport.EngagementTypeKey, "engagement-type", "engagement", "Anytype type key for Engagement objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.AssetTypeKey, "asset-type", "asset", "Anytype type key for Asset objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ServiceTypeKey, "service-type", "service", "Anytype type key for Service objects")
	exportAnytypeCmd.Flags().StringVar(&anytypeExport.ScanTypeKey, "scan-type", "scan", "Anytype type key for Scan objects")
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
		"service-historical-observation-name-property",
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
	preview, err := exporter.PreviewAnytype(cmd.Context(), opts.AnytypeOptions, subdomains, scans, observations, runs)
	if err != nil {
		return err
	}
	if !opts.Yes {
		if err := confirmAnytypeExport(preview); err != nil {
			return err
		}
	}

	result, err := exporter.ExportAnytype(cmd.Context(), opts.AnytypeOptions, subdomains, scans, observations, runs)
	if err != nil {
		return err
	}

	summary := struct {
		Domain                               string `json:"domain"`
		Engagement                           string `json:"engagement"`
		EngagementID                         string `json:"engagement_id"`
		Database                             string `json:"database"`
		AssetsCreated                        int    `json:"assets_created"`
		AssetsReused                         int    `json:"assets_reused"`
		AssetsUpdated                        int    `json:"assets_updated"`
		ServicesCreated                      int    `json:"services_created"`
		ServicesReused                       int    `json:"services_reused"`
		ServiceHistoricalObservationsCreated int    `json:"service_historical_observations_created"`
		ServiceHistoricalObservationsSkipped int    `json:"service_historical_observations_skipped"`
		ScansCreated                         int    `json:"scans_created"`
		ScansSkipped                         int    `json:"scans_skipped"`
		AnytypeSpace                         string `json:"anytype_space"`
		AnytypeURL                           string `json:"anytype_url"`
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
		ServiceHistoricalObservationsCreated: result.ServiceHistoricalObservationsCreated,
		ServiceHistoricalObservationsSkipped: result.ServiceHistoricalObservationsSkipped,
		ScansCreated:                         result.ScansCreated,
		ScansSkipped:                         result.ScansSkipped,
		AnytypeSpace:                         result.AnytypeSpace,
		AnytypeURL:                           result.AnytypeURL,
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
	fmt.Fprintf(os.Stderr, "  history:       %d\n", preview.ServiceHistoricalObservations)
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
