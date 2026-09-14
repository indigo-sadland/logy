package cmd

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/portscan"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"github.com/indigo-sadland/logy/internal/storage"

	"github.com/spf13/cobra"
)

var portscanBinary string
var portscanFromDB bool
var portscanSaveDomain string
var portscanSaveTempFile bool
var portscanShowFormat string
var portscanPickDomain string
var portscanTargetDomain string
var portscanTargetLabel string
var portscanImportDomain string
var portscanImportFile string
var portscanImportIncludeNonOpen bool

var portscanCmd = &cobra.Command{
	Use:     "portscan [--from-db domain] -- [nmap args]",
	Short:   "Run nmap directly or scan resolved targets from the database",
	GroupID: "service",
	RunE: func(cmd *cobra.Command, args []string) error {

		if portscanFromDB {
			return runPortscanFromDB(cmd, args)
		}
		if strings.TrimSpace(portscanTargetDomain) != "" || strings.TrimSpace(portscanTargetLabel) != "" {
			return runPortscanSavedTarget(cmd, args)
		}
		if strings.TrimSpace(portscanSaveDomain) != "" {
			return runPortscanRawAndSave(cmd, args)
		}
		if portscanSaveTempFile {
			return fmt.Errorf("--save-temp-file requires --save-domain, --from-db, or --domain with --target")
		}
		return portscan.Run(cmd.Context(), portscan.Config{Binary: portscanBinary}, args)
	},
}

var portscanShowCmd = &cobra.Command{
	Use:   "show --domain example.com",
	Short: "Show stored port scan results",
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

		scans, err := store.PortScansByDomain(domain)
		if err != nil && errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no portscan results for the target root domain found in DB\n")
		}
		subdomains, err := store.SubdomainsByDomain(domain)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if errors.Is(err, sql.ErrNoRows) {
			subdomains = nil
		}

		hosts := buildPortscanShowHosts(subdomains, scans)
		switch strings.TrimSpace(strings.ToLower(portscanShowFormat)) {
		case "", "json":
			data := struct {
				Domain string             `json:"domain"`
				Hosts  []portscanShowHost `json:"hosts"`
			}{
				Domain: domain,
				Hosts:  hosts,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(data)
		case "text":
			return writePortscanShowText(os.Stdout, hosts)
		default:
			return fmt.Errorf("unsupported --format %q; use json or text\n", portscanShowFormat)
		}
	},
}

var portscanPickCmd = &cobra.Command{
	Use:   "pick --domain example.com -- [nmap args]",
	Short: "Interactively pick one saved target from the database and scan its resolved IPs",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPortscanPick(cmd, args)
	},
}

var portscanImportCmd = &cobra.Command{
	Use:   "import --domain example.com --file scan.xml",
	Short: "Import saved nmap XML port scan results",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPortscanImport(cmd)
	},
}

func init() {
	rootCmd.AddCommand(portscanCmd)
	portscanCmd.AddCommand(portscanShowCmd)
	portscanCmd.AddCommand(portscanPickCmd)
	portscanCmd.AddCommand(portscanImportCmd)

	portscanCmd.Flags().BoolVar(&portscanFromDB, "from-db", false, "scan unique resolved targets from the database")
	portscanCmd.Flags().StringVarP(&portscanTargetDomain, "domain", "d", "", "target domain to load saved scan targets from")
	portscanCmd.Flags().StringVarP(&portscanTargetLabel, "target", "t", "", "saved target label to scan from the database")
	portscanCmd.Flags().StringVar(&portscanSaveDomain, "save-domain", "", "persist raw scan results under the provided domain label")
	portscanCmd.Flags().BoolVar(&portscanSaveTempFile, "save-temp-file", false, "persist captured nmap XML output to a temporary file. Use for debug purposes and if run scans with -sC flags")
	portscanCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
	portscanShowCmd.Flags().StringP("domain", "d", "", "target domain to show stored port scan results for")
	portscanShowCmd.Flags().StringVar(&portscanShowFormat, "format", "json", "output format: json or text")
	portscanShowCmd.Flags().String("config", defaultConfigPath(), "path to config yaml")
	portscanPickCmd.Flags().StringVarP(&portscanPickDomain, "domain", "d", "", "target domain to load saved scan candidates from")
	portscanPickCmd.Flags().BoolVar(&portscanSaveTempFile, "save-temp-file", false, "persist captured nmap XML output to a temporary file. Use for debug purposes and if run scans with -sC flags")
	portscanPickCmd.Flags().String("config", defaultConfigPath(), "path to config yaml")
	portscanImportCmd.Flags().StringVarP(&portscanImportDomain, "domain", "d", "", "target root domain for imported results")
	portscanImportCmd.Flags().StringVarP(&portscanImportFile, "file", "f", "", "path to nmap XML output")
	portscanImportCmd.Flags().BoolVar(&portscanImportIncludeNonOpen, "include-non-open", false, "import closed and filtered ports in addition to open ports")
	portscanImportCmd.Flags().String("config", defaultConfigPath(), "path to config yaml")
}

func runPortscanImport(cmd *cobra.Command) error {
	domain, err := requireDomainLabel(portscanImportDomain)
	if err != nil {
		return err
	}
	path := strings.TrimSpace(portscanImportFile)
	if path == "" {
		return fmt.Errorf("--file is required\n")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory\n", path)
	}

	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read nmap xml %s: %w", path, err)
	}
	imported, err := portscan.ParseNmapXMLImport(raw, portscan.ImportOptions{
		IncludeNonOpen: portscanImportIncludeNonOpen,
	})
	if err != nil {
		return err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	// Imported XML uses the same current-service table as live nmap scans.
	records := make([]storage.PortScanRecord, 0, len(imported.Results))
	for _, result := range imported.Results {
		records = append(records, storage.PortScanRecord{
			Domain:    domain,
			IP:        result.IP,
			Port:      result.Port,
			Protocol:  result.Protocol,
			State:     result.State,
			Service:   result.Service,
			Version:   result.Version,
			ScannedAt: result.ScannedAt,
		})
	}
	if err := store.SavePortScans(domain, records); err != nil {
		return err
	}

	hostnamesSaved, err := saveImportedNmapHostnames(store, domain, imported.Hostnames)
	if err != nil {
		return err
	}

	// Track the import as a completed Scan so Anytype export can show the evidence source.
	startedAt := imported.ScannedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	finishedAt := time.Now().UTC()
	command := "nmap xml import: " + path
	runID, err := store.CreateCommandRun(storage.CommandRunRecord{
		Domain:    domain,
		Target:    path,
		Tool:      "nmap",
		Command:   command,
		Status:    "running",
		StartedAt: startedAt,
	})
	if err != nil {
		return err
	}
	if err := store.FinishCommandRun(runID, "completed", 0, finishedAt, "", sql.NullInt64{}, ""); err != nil {
		return err
	}
	if err := store.SavePortScanTargets(domain, buildPortScanTargetRecords(domain, imported.ScannedIPs, nil, imported.ScannedAt, sql.NullInt64{Int64: runID, Valid: true})); err != nil {
		return err
	}

	summary := struct {
		Domain         string `json:"domain"`
		File           string `json:"file"`
		Database       string `json:"database"`
		HostsSeen      int    `json:"hosts_seen"`
		HostnamesSaved int    `json:"hostnames_saved"`
		PortsImported  int    `json:"ports_imported"`
		PortsSkipped   int    `json:"ports_skipped"`
		CommandRunID   int64  `json:"command_run_id"`
	}{
		Domain:         domain,
		File:           path,
		Database:       cfg.Database.Path,
		HostsSeen:      imported.HostsSeen,
		HostnamesSaved: hostnamesSaved,
		PortsImported:  len(records),
		PortsSkipped:   imported.PortsSkipped,
		CommandRunID:   runID,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func saveImportedNmapHostnames(store *storage.Store, domain string, hostnames []portscan.ImportedHostname) (int, error) {
	if len(hostnames) == 0 {
		return 0, nil
	}

	ipsByHost := make(map[string][]string, len(hostnames))
	for _, hostname := range hostnames {
		host := normalizeImportedNmapHostname(domain, hostname.Hostname)
		if host == "" {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(hostname.IP))
		if ip == nil || ip.To4() == nil {
			continue
		}
		ipsByHost[host] = append(ipsByHost[host], ip.To4().String())
	}
	if len(ipsByHost) == 0 {
		return 0, nil
	}

	hosts := make([]string, 0, len(ipsByHost))
	for host := range ipsByHost {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)

	entries := make([]discovery.Entry, 0, len(hosts))
	resolutions := make([]resolver.Result, 0, len(hosts))
	for _, host := range hosts {
		ips := uniqueIPv4Targets(ipsByHost[host])
		if len(ips) == 0 {
			continue
		}
		entries = append(entries, discovery.Entry{
			Subdomain: host,
			Sources:   []string{"nmap-xml"},
		})
		resolutions = append(resolutions, resolver.Result{
			Subdomain: host,
			IPs:       ips,
			Alive:     true,
		})
	}
	if len(entries) == 0 {
		return 0, nil
	}
	// Save discoveries before resolutions because resolution updates target existing subdomain rows.
	if err := store.SaveDiscoveries(domain, entries); err != nil {
		return 0, err
	}
	if err := store.SaveResolutions(domain, resolutions); err != nil {
		return 0, err
	}
	return len(entries), nil
}

func normalizeImportedNmapHostname(domain string, hostname string) string {
	host := strings.Trim(strings.ToLower(strings.TrimSpace(hostname)), ".")
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if host == "" || domain == "" {
		return ""
	}
	if host == domain || strings.HasSuffix(host, "."+domain) {
		return host
	}
	return ""
}

// runPortscanRawAndSave handles raw nmap scans that takes target input from user's input and not from DB
// Example: logy portscan --save-domain misc-infra -- -sV -Pn 10.10.10.10
func runPortscanRawAndSave(cmd *cobra.Command, args []string) error {

	domain, err := requireDomainLabel(portscanSaveDomain)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("at least one nmap argument is required\n")
	}

	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	scanOutput, err := portscan.ScanDetailed(cmd.Context(), portscan.Config{
		Binary:       portscanBinary,
		SaveTempFile: portscanSaveTempFile,
	}, args)
	if err != nil {
		return err
	}

	records := make([]storage.PortScanRecord, 0, len(scanOutput.Results))
	for _, result := range scanOutput.Results {
		records = append(records, storage.PortScanRecord{
			Domain:    domain,
			IP:        result.IP,
			Port:      result.Port,
			Protocol:  result.Protocol,
			State:     result.State,
			Service:   result.Service,
			Version:   result.Version,
			ScannedAt: result.ScannedAt,
		})
	}
	if err := store.SavePortScans(domain, records); err != nil {
		return err
	}
	if err := store.SavePortScanTargets(domain, buildPortScanTargetRecords(domain, scanOutput.ScannedIPs, nil, scanTimeFromResults(scanOutput.Results), sql.NullInt64{})); err != nil {
		return err
	}

	summary := struct {
		Domain       string   `json:"domain"`
		OpenPorts    int      `json:"open_ports"`
		NmapArgs     []string `json:"nmap_args"`
		Database     string   `json:"database"`
		NmapBinary   string   `json:"nmap_binary"`
		StoredRows   int      `json:"stored_rows"`
		ScannedIPs   []string `json:"scanned_ips"`
		TempFilePath string   `json:"temp_file_path,omitempty"`
	}{
		Domain:       domain,
		OpenPorts:    len(scanOutput.Results),
		NmapArgs:     slices.Clone(args),
		Database:     cfg.Database.Path,
		NmapBinary:   normalizePortscanBinary(portscanBinary),
		StoredRows:   len(records),
		ScannedIPs:   uniquePortscanIPs(scanOutput.Results),
		TempFilePath: scanOutput.TempFilePath,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func runPortscanFromDB(cmd *cobra.Command, args []string) error {
	domain, nmapArgs, err := resolvePortscanFromDBInput(args)
	if err != nil {
		return err
	}
	if len(nmapArgs) == 0 {
		return fmt.Errorf("at least one nmap argument is required\n")
	}

	configPath, _ := cmd.Flags().GetString("config")
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

	targets, err := store.ResolvedIPsByDomain(domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no resolved IPs targets found for domain %s\n", domain)
		}
		return err
	}

	scanOutput, err := portscan.ScanIPsDetailed(cmd.Context(), targets, portscan.Config{
		Binary:       portscanBinary,
		SaveTempFile: portscanSaveTempFile,
	}, nmapArgs)
	if err != nil {
		return err
	}
	scannedTargets := uniqueIPv4Targets(targets)

	records := make([]storage.PortScanRecord, 0, len(scanOutput.Results))
	for _, result := range scanOutput.Results {
		records = append(records, storage.PortScanRecord{
			Domain:    domain,
			IP:        result.IP,
			Port:      result.Port,
			Protocol:  result.Protocol,
			State:     result.State,
			Service:   result.Service,
			Version:   result.Version,
			ScannedAt: result.ScannedAt,
		})
	}
	if err := store.SavePortScans(domain, records); err != nil {
		return err
	}
	if err := store.SavePortScanTargets(domain, buildPortScanTargetRecords(domain, scanOutput.ScannedIPs, nil, scanTimeFromResults(scanOutput.Results), sql.NullInt64{})); err != nil {
		return err
	}

	summary := struct {
		Domain       string   `json:"domain"`
		Targets      []string `json:"targets"`
		OpenPorts    int      `json:"open_ports"`
		NmapArgs     []string `json:"nmap_args"`
		Database     string   `json:"database"`
		NmapBinary   string   `json:"nmap_binary"`
		StoredRows   int      `json:"stored_rows"`
		TargetCount  int      `json:"target_count"`
		TempFilePath string   `json:"temp_file_path,omitempty"`
	}{
		Domain:       domain,
		Targets:      scannedTargets,
		OpenPorts:    len(scanOutput.Results),
		NmapArgs:     nmapArgs,
		Database:     cfg.Database.Path,
		NmapBinary:   normalizePortscanBinary(portscanBinary),
		StoredRows:   len(records),
		TargetCount:  len(scannedTargets),
		TempFilePath: scanOutput.TempFilePath,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func runPortscanPick(cmd *cobra.Command, args []string) error {
	domain, err := requireDomainLabel(portscanPickDomain)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("at least one nmap argument is required\n")
	}
	if !isInteractiveTerminal(os.Stdin) || !isInteractiveTerminal(os.Stdout) {
		return fmt.Errorf("portscan pick requires an interactive terminal\n")
	}

	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	// Pick from saved scan targets so internal IP-only assets stay selectable.
	targets, err := store.SavedScanTargetsByDomain(domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no saved scan targets found for domain %s\n", domain)
		}
		return err
	}

	candidates := buildPortscanPickCandidates(targets)
	selected, err := runPortscanPicker(os.Stdin, os.Stdout, domain, candidates)
	if err != nil {
		return err
	}

	return runSavedTargetScan(cmd, cfg, store, domain, selected, args)
}

func runPortscanSavedTarget(cmd *cobra.Command, args []string) error {
	domain, err := requireDomainLabel(portscanTargetDomain)
	target := strings.TrimSpace(portscanTargetLabel)
	if err != nil {
		return err
	}
	if target == "" {
		return fmt.Errorf("--target is required\n")
	}
	if len(args) == 0 {
		return fmt.Errorf("at least one nmap argument is required\n")
	}

	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	targets, err := store.SavedScanTargetsByDomain(domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no saved scan targets found for domain %s\n", domain)
		}
		return err
	}

	selected, err := findSavedScanTarget(targets, target)
	if err != nil {
		return err
	}
	return runSavedTargetScan(cmd, cfg, store, domain, toPortscanPickCandidate(selected), args)
}

// runSavedTargetScan executes a DB-backed scan for one selected saved target.
func runSavedTargetScan(cmd *cobra.Command, cfg config.Config, store *storage.Store, domain string, selected portscanPickCandidate, args []string) error {
	scanOutput, err := portscan.ScanIPsDetailed(cmd.Context(), selected.IPs, portscan.Config{
		Binary:       portscanBinary,
		SaveTempFile: portscanSaveTempFile,
	}, args)
	if err != nil {
		return err
	}

	records := make([]storage.PortScanRecord, 0, len(scanOutput.Results))
	for _, result := range scanOutput.Results {
		records = append(records, storage.PortScanRecord{
			Domain:    domain,
			IP:        result.IP,
			Port:      result.Port,
			Protocol:  result.Protocol,
			State:     result.State,
			Service:   result.Service,
			Version:   result.Version,
			ScannedAt: result.ScannedAt,
		})
	}
	if err := store.SavePortScans(domain, records); err != nil {
		return err
	}
	if err := store.SavePortScanTargets(domain, buildPortScanTargetRecords(domain, scanOutput.ScannedIPs, selectedLabelByIP(selected), scanTimeFromResults(scanOutput.Results), sql.NullInt64{})); err != nil {
		return err
	}

	summary := struct {
		Domain         string   `json:"domain"`
		SelectedTarget string   `json:"selected_target"`
		Targets        []string `json:"targets"`
		OpenPorts      int      `json:"open_ports"`
		NmapArgs       []string `json:"nmap_args"`
		Database       string   `json:"database"`
		NmapBinary     string   `json:"nmap_binary"`
		StoredRows     int      `json:"stored_rows"`
		TargetCount    int      `json:"target_count"`
		TempFilePath   string   `json:"temp_file_path,omitempty"`
	}{
		Domain:         domain,
		SelectedTarget: selected.Label,
		Targets:        slices.Clone(selected.IPs),
		OpenPorts:      len(scanOutput.Results),
		NmapArgs:       slices.Clone(args),
		Database:       cfg.Database.Path,
		NmapBinary:     normalizePortscanBinary(portscanBinary),
		StoredRows:     len(records),
		TargetCount:    len(selected.IPs),
		TempFilePath:   scanOutput.TempFilePath,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

// findSavedScanTarget resolves an exact saved-target label for non-interactive scans.
func findSavedScanTarget(targets []storage.SavedScanTarget, target string) (storage.SavedScanTarget, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return storage.SavedScanTarget{}, fmt.Errorf("target must not be empty")
	}
	for _, candidate := range targets {
		if strings.EqualFold(strings.TrimSpace(candidate.Label), target) {
			return candidate, nil
		}
	}
	return storage.SavedScanTarget{}, fmt.Errorf("saved target %q not found", target)
}

func toPortscanPickCandidate(target storage.SavedScanTarget) portscanPickCandidate {
	return portscanPickCandidate{
		Label: target.Label,
		Kind:  target.Kind,
		IPs:   target.IPs,
	}
}

func resolvePortscanFromDBInput(args []string) (string, []string, error) {
	if len(args) == 0 {
		domain, err := requireDomainLabel("")
		if err != nil {
			return "", nil, err
		}
		return domain, nil, nil
	}
	first := strings.TrimSpace(args[0])
	if first != "" && !strings.HasPrefix(first, "-") {
		return first, slices.Clone(args[1:]), nil
	}
	domain, err := requireDomainLabel("")
	if err != nil {
		return "", nil, err
	}
	return domain, slices.Clone(args), nil
}

const timeRFC3339 = "2006-01-02T15:04:05Z07:00"

type portscanShowPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Service   string `json:"service,omitempty"`
	Version   string `json:"version,omitempty"`
	ScannedAt string `json:"scanned_at"`
}

type portscanShowHost struct {
	IP         string             `json:"ip"`
	Subdomains []string           `json:"subdomains"`
	Ports      []portscanShowPort `json:"ports"`
}

func buildPortscanShowHosts(subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord) []portscanShowHost {

	ipToSubdomains := make(map[string][]string, 128)
	for _, record := range subdomains {
		if !record.Resolved {
			continue
		}
		for _, ip := range record.IPs {
			if strings.Contains(ip, ":") {
				continue
			}
			ipToSubdomains[ip] = append(ipToSubdomains[ip], record.Subdomain)
		}
	}
	for ip := range ipToSubdomains {
		slices.Sort(ipToSubdomains[ip])
	}

	hosts := make([]portscanShowHost, 0, len(scans))
	indexByIP := make(map[string]int, len(scans))
	for _, scan := range scans {
		idx, ok := indexByIP[scan.IP]
		if !ok {
			idx = len(hosts)
			indexByIP[scan.IP] = idx
			hosts = append(hosts, portscanShowHost{
				IP:         scan.IP,
				Subdomains: slices.Clone(ipToSubdomains[scan.IP]),
				Ports:      make([]portscanShowPort, 0, 8),
			})
		}
		hosts[idx].Ports = append(hosts[idx].Ports, portscanShowPort{
			Port:      scan.Port,
			Protocol:  scan.Protocol,
			State:     scan.State,
			Service:   scan.Service,
			Version:   scan.Version,
			ScannedAt: scan.ScannedAt.Format(timeRFC3339),
		})
	}

	return hosts
}

func writePortscanShowText(out io.Writer, hosts []portscanShowHost) error {
	for _, host := range hosts {
		parts := make([]string, 0, len(host.Ports))
		for _, port := range host.Ports {
			desc := strings.TrimSpace(strings.Join([]string{
				strings.TrimSpace(port.Service),
				strings.TrimSpace(port.Version),
			}, " "))
			if desc == "" {
				desc = strings.TrimSpace(port.State)
			}
			parts = append(parts, fmt.Sprintf("%d/%s (%s)", port.Port, port.Protocol, desc))
		}
		if _, err := fmt.Fprintf(out, "%s\t%s\n", host.IP, strings.Join(parts, "; ")); err != nil {
			return err
		}
	}
	return nil
}

func buildPortScanTargetRecords(domain string, ips []string, hostnamesByIP map[string]string, scannedAt time.Time, commandRunID sql.NullInt64) []storage.PortScanTargetRecord {
	ips = uniqueIPv4Targets(ips)
	if scannedAt.IsZero() {
		scannedAt = time.Now().UTC()
	}
	records := make([]storage.PortScanTargetRecord, 0, len(ips))
	for _, ip := range ips {
		records = append(records, storage.PortScanTargetRecord{
			Domain:       domain,
			IP:           ip,
			Hostname:     strings.TrimSpace(hostnamesByIP[ip]),
			Scanner:      "nmap",
			Status:       "scanned",
			ScannedAt:    scannedAt,
			CommandRunID: commandRunID,
		})
	}
	return records
}

func selectedLabelByIP(selected portscanPickCandidate) map[string]string {
	out := make(map[string]string, len(selected.IPs))
	label := strings.TrimSpace(selected.Label)
	if label == "" || strings.EqualFold(selected.Kind, "ip") {
		return out
	}
	for _, ip := range selected.IPs {
		out[ip] = label
	}
	return out
}

func scanTimeFromResults(results []portscan.Result) time.Time {
	for _, result := range results {
		if !result.ScannedAt.IsZero() {
			return result.ScannedAt
		}
	}
	return time.Now().UTC()
}

func uniqueIPv4Targets(targets []string) []string {

	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		ip := net.ParseIP(strings.TrimSpace(target))
		if ip == nil || ip.To4() == nil {
			continue
		}
		value := ip.To4().String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func uniquePortscanIPs(results []portscan.Result) []string {

	seen := make(map[string]struct{}, len(results))
	out := make([]string, 0, len(results))
	for _, result := range results {
		value := strings.TrimSpace(result.IP)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func normalizePortscanBinary(binary string) string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return "nmap"
	}
	return binary
}
