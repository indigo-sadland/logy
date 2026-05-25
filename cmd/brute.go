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
	"github.com/indigo-sadland/logy/internal/utils/puredns"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var bruteWordlist string
var bruteResolvers string

var bruteCmd = &cobra.Command{
	Use:   "brute --domain example.com --wordlist words.txt --public-resolvers resolvers.txt",
	Short: "Bruteforce subdomains with puredns",
	RunE: func(cmd *cobra.Command, args []string) error {

		domain, _ := cmd.Flags().GetString("domain")
		configPath, _ := cmd.Flags().GetString("config")
		domain, err := requireDomainLabel(domain)
		if err != nil {
			return err
		}

		bruteWordlist = strings.TrimSpace(bruteWordlist)
		bruteResolvers = strings.TrimSpace(bruteResolvers)
		if bruteWordlist == "" {
			return fmt.Errorf("--wordlist is required\n")
		}
		if bruteResolvers == "" {
			return fmt.Errorf("--public-resolvers is required\n")
		}

		// Check if user's terminal supports colored output
		stdoutSupportsColor := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
		output.Init(stdoutSupportsColor)

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

		discoveryCfg := discovery.Config{
			ToolConfig: map[string]discovery.ToolConfig{
				"puredns": {
					WordlistFile:  bruteWordlist,
					ResolversFile: bruteResolvers,
				},
			},
			Logf: output.Print,
		}

		output.Print("[*] puredns: bruteforce mode enabled\n")

		engine := pipeline.Engine{
			Discovery: []provider.Provider{
				provider.NewCommandProviderWithProgress("puredns", func(domain string) []string {
					return []string{"bruteforce", bruteWordlist, domain, "-r", bruteResolvers, "-l", "500"}
				}, puredns.ProgressDoneFactory(discoveryCfg.ToolConfig["puredns"])),
			},
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

		report, err := engine.Run(context.Background(), domain, domain)
		if err != nil {
			return err
		}

		summary := struct {
			Target     string `json:"target"`
			Mode       string `json:"mode"`
			Discovered int    `json:"discovered"`
			Resolved   int    `json:"resolved"`
			Unresolved int    `json:"unresolved"`
			Database   string `json:"database"`
		}{
			Target:     domain,
			Mode:       "bruteforce",
			Discovered: report.Discovered,
			Resolved:   report.Resolved,
			Unresolved: report.Unresolved,
			Database:   cfg.Database.Path,
		}

		enc := json.NewEncoder(os.Stdout)
		return enc.Encode(summary)
	},
}

func init() {
	domainCmd.AddCommand(bruteCmd)
	bruteCmd.Flags().StringP("domain", "d", "", "target domain for subdomain bruteforce")
	bruteCmd.Flags().StringVarP(&bruteWordlist, "wordlist", "w", "", "wordlist for bruteforce mode")
	bruteCmd.Flags().StringVarP(&bruteResolvers, "public-resolvers", "r", "", "resolver list for bruteforce mode")
	bruteCmd.Flags().String("config", defaultConfigPath(), "path to config yaml")
}
