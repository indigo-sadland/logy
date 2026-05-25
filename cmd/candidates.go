package cmd

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/storage"

	"github.com/spf13/cobra"
)

var candidatesCmd = &cobra.Command{
	Use:   "candidates",
	Short: "Inspect unresolved hostnames from permutation process. These can be used in VHost resolving process",
}

var candidatesShowCmd = &cobra.Command{
	Use:   "show --domain example.com",
	Short: "Show unresolved permutation candidates",
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

		records, err := store.PermutationCandidatesByDomain(domain)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("no permutation candidates found for domain %s\n", domain)
			}
			return err
		}

		type outputRecord struct {
			Subdomain   string   `json:"subdomain"`
			Sources     []string `json:"sources"`
			FirstSeenAt string   `json:"first_seen_at"`
			LastSeenAt  string   `json:"last_seen_at"`
			UpdatedAt   string   `json:"updated_at"`
		}

		data := struct {
			Domain     string         `json:"domain"`
			Candidates []outputRecord `json:"candidates"`
		}{
			Domain:     domain,
			Candidates: make([]outputRecord, 0, len(records)),
		}

		for _, record := range records {
			data.Candidates = append(data.Candidates, outputRecord{
				Subdomain:   record.Subdomain,
				Sources:     record.Sources,
				FirstSeenAt: record.FirstSeenAt.Format(timeRFC3339),
				LastSeenAt:  record.LastSeenAt.Format(timeRFC3339),
				UpdatedAt:   record.UpdatedAt.Format(timeRFC3339),
			})
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	},
}

func init() {
	domainCmd.AddCommand(candidatesCmd)
	candidatesCmd.AddCommand(candidatesShowCmd)
	candidatesShowCmd.Flags().String("config", defaultConfigPath(), "path to logy's config yaml")
	candidatesShowCmd.Flags().StringP("domain", "d", "", "target domain to show permutation candidates for")
}
