package cmd

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/modules/webprobe"
	"github.com/indigo-sadland/logy/internal/storage"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var probeInputFile string
var probeDomain string
var probeSave bool
var probeResolvers []string

var probeCmd = &cobra.Command{
	Use:     "probe",
	Short:   "Probe web services with httpx",
	GroupID: "service",
	RunE: func(cmd *cobra.Command, args []string) error {
		hasFile := strings.TrimSpace(probeInputFile) != ""
		hasPipedStdin := stdinHasData()
		resolvedDomain, err := resolveDomainLabel(probeDomain)
		if err != nil {
			return err
		}
		probeDomain = resolvedDomain

		switch {
		case hasFile && hasPipedStdin:
			return fmt.Errorf("use either --file or piped stdin, not both\n")
		case hasFile || hasPipedStdin:
			return runProbeRaw(cmd, hasFile)
		case strings.TrimSpace(probeDomain) != "":
			return runProbeAutomatic(cmd)
		default:
			return fmt.Errorf("provide --file, piped stdin, or --domain\n")
		}
	},
}

var probeShowCmd = &cobra.Command{
	Use:   "show --domain example.com",
	Short: "Show stored web probe results",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProbeShow(cmd)
	},
}

func init() {
	rootCmd.AddCommand(probeCmd)
	probeCmd.AddCommand(probeShowCmd)
	probeCmd.Flags().StringVarP(&probeInputFile, "file", "f", "", "path to a file containing probe targets")
	probeCmd.Flags().StringVarP(&probeDomain, "domain", "d", "", "root domain to probe from stored subdomains and port scan results")
	probeCmd.Flags().StringSliceVarP(&probeResolvers, "resolver", "r", nil, "custom DNS resolvers to pass to httpx")
	probeCmd.Flags().BoolVar(&probeSave, "save", false, "save raw-mode probe results in the database under --domain")
	probeCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
	probeShowCmd.Flags().StringVarP(&probeDomain, "domain", "d", "", "root domain to show stored probe results for")
	probeShowCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
}

func runProbeRaw(cmd *cobra.Command, hasFile bool) error {
	domain := strings.TrimSpace(probeDomain)
	if domain != "" && !probeSave {
		return fmt.Errorf("--domain in raw mode requires --save\n")
	}
	if probeSave && domain == "" {
		return fmt.Errorf("--save requires --domain in raw mode\n")
	}

	inputFile := ""
	if hasFile {
		inputFile = strings.TrimSpace(probeInputFile)
		info, err := os.Stat(inputFile)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s is a directory\n", inputFile)
		}
	}

	if !probeSave {
		return webprobe.RunRaw(cmd.Context(), webprobe.Config{Resolvers: probeResolvers}, inputFile, os.Stdin, os.Stdout, os.Stderr)
	}

	configPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	results, err := webprobe.RunRawAndCapture(cmd.Context(), webprobe.Config{Resolvers: probeResolvers}, inputFile, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.SaveWebProbes(domain, toWebProbeRecords(domain, results)); err != nil {
		return err
	}
	return nil
}

func runProbeAutomatic(cmd *cobra.Command) error {
	domain := strings.TrimSpace(probeDomain)
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

	targets, err := store.WebProbeTargetsByDomain(domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no http/https-capable port scan results found for domain %s\n", domain)
		}
		return err
	}

	urls := make([]string, 0, len(targets))
	for _, target := range targets {
		urls = append(urls, target.URL)
	}

	// Automatic probing owns stdout JSON, so live status goes to stderr only.
	progress := newProbeProgressPrinter(len(urls))
	defer progress.finish()

	results, err := webprobe.ProbeTargetsWithProgress(cmd.Context(), webprobe.Config{
		Progress:  progress.report,
		Resolvers: probeResolvers,
	}, urls)
	if err != nil {
		return err
	}

	if err := store.SaveWebProbes(domain, toWebProbeRecords(domain, results)); err != nil {
		return err
	}

	output := struct {
		Domain      string `json:"domain"`
		Database    string `json:"database"`
		TargetCount int    `json:"target_count"`
		ResultCount int    `json:"result_count"`
		Results     []struct {
			Target       string   `json:"target"`
			URL          string   `json:"url"`
			FinalURL     string   `json:"final_url,omitempty"`
			Scheme       string   `json:"scheme"`
			Port         int      `json:"port"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title,omitempty"`
			Technologies []string `json:"technologies,omitempty"`
			ProbedAt     string   `json:"probed_at"`
		} `json:"results"`
	}{
		Domain:      domain,
		Database:    cfg.Database.Path,
		TargetCount: len(urls),
		ResultCount: len(results),
		Results: make([]struct {
			Target       string   `json:"target"`
			URL          string   `json:"url"`
			FinalURL     string   `json:"final_url,omitempty"`
			Scheme       string   `json:"scheme"`
			Port         int      `json:"port"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title,omitempty"`
			Technologies []string `json:"technologies,omitempty"`
			ProbedAt     string   `json:"probed_at"`
		}, 0, len(results)),
	}

	for _, result := range results {
		output.Results = append(output.Results, struct {
			Target       string   `json:"target"`
			URL          string   `json:"url"`
			FinalURL     string   `json:"final_url,omitempty"`
			Scheme       string   `json:"scheme"`
			Port         int      `json:"port"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title,omitempty"`
			Technologies []string `json:"technologies,omitempty"`
			ProbedAt     string   `json:"probed_at"`
		}{
			Target:       result.Target,
			URL:          result.URL,
			FinalURL:     result.FinalURL,
			Scheme:       result.Scheme,
			Port:         result.Port,
			StatusCode:   result.StatusCode,
			Title:        result.Title,
			Technologies: result.Technologies,
			ProbedAt:     result.ProbedAt.Format(timeRFC3339),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func runProbeShow(cmd *cobra.Command) error {
	domain, err := requireDomainLabel(probeDomain)
	if err != nil {
		return err
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

	results, err := store.WebProbesByDomain(domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no web probe results for domain %s\n", domain)
		}
		return err
	}

	output := struct {
		Domain   string `json:"domain"`
		Database string `json:"database"`
		Count    int    `json:"count"`
		Results  []struct {
			Target       string   `json:"target"`
			URL          string   `json:"url"`
			FinalURL     string   `json:"final_url,omitempty"`
			Scheme       string   `json:"scheme"`
			Port         int      `json:"port"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title,omitempty"`
			Technologies []string `json:"technologies,omitempty"`
			ProbedAt     string   `json:"probed_at"`
		} `json:"results"`
	}{
		Domain:   domain,
		Database: cfg.Database.Path,
		Count:    len(results),
		Results: make([]struct {
			Target       string   `json:"target"`
			URL          string   `json:"url"`
			FinalURL     string   `json:"final_url,omitempty"`
			Scheme       string   `json:"scheme"`
			Port         int      `json:"port"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title,omitempty"`
			Technologies []string `json:"technologies,omitempty"`
			ProbedAt     string   `json:"probed_at"`
		}, 0, len(results)),
	}

	for _, result := range results {
		output.Results = append(output.Results, struct {
			Target       string   `json:"target"`
			URL          string   `json:"url"`
			FinalURL     string   `json:"final_url,omitempty"`
			Scheme       string   `json:"scheme"`
			Port         int      `json:"port"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title,omitempty"`
			Technologies []string `json:"technologies,omitempty"`
			ProbedAt     string   `json:"probed_at"`
		}{
			Target:       result.Target,
			URL:          result.URL,
			FinalURL:     result.FinalURL,
			Scheme:       result.Scheme,
			Port:         result.Port,
			StatusCode:   result.StatusCode,
			Title:        result.Title,
			Technologies: result.Technologies,
			ProbedAt:     result.ProbedAt.Format(timeRFC3339),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

type probeProgressPrinter struct {
	enabled bool
	lastLen int
	total   int
}

// Automatic probing prints progress on stderr so stdout can stay machine-readable.
func newProbeProgressPrinter(total int) *probeProgressPrinter {
	return &probeProgressPrinter{
		enabled: isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd()),
		total:   total,
	}
}

func (p *probeProgressPrinter) report(progress webprobe.Progress) {
	if !p.enabled {
		return
	}

	total := progress.Total
	if total <= 0 {
		total = p.total
	}
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
	line := fmt.Sprintf(
		"\r[*] probe/httpx: [%s] %d/%d 2xx=%d 3xx=%d 4xx=%d 5xx=%d elapsed=%s",
		bar,
		completed,
		total,
		progress.Status2xx,
		progress.Status3xx,
		progress.Status4xx,
		progress.Status5xx,
		progress.Elapsed,
	)
	if progress.LastTarget != "" {
		line += " last=" + progress.LastTarget
	}
	// Heartbeats mark long quiet stretches when httpx has not emitted a new JSON line yet.
	if progress.Heartbeat {
		line += " waiting"
	}
	if pad := p.lastLen - len(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	fmt.Fprint(os.Stderr, line)
	p.lastLen = len(line)
}

// Finish the in-place progress line before the command prints anything else.
func (p *probeProgressPrinter) finish() {
	if !p.enabled || p.lastLen == 0 {
		return
	}
	fmt.Fprint(os.Stderr, "\n")
	p.lastLen = 0
}

func toWebProbeRecords(domain string, results []webprobe.Result) []storage.WebProbeRecord {
	records := make([]storage.WebProbeRecord, 0, len(results))
	for _, result := range results {
		records = append(records, storage.WebProbeRecord{
			Domain:       domain,
			Target:       result.Target,
			URL:          result.URL,
			FinalURL:     result.FinalURL,
			Scheme:       result.Scheme,
			Port:         result.Port,
			StatusCode:   result.StatusCode,
			Title:        result.Title,
			Technologies: result.Technologies,
			ProbedAt:     result.ProbedAt,
		})
	}
	return records
}

func stdinHasData() bool {
	return !(isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd()))
}
