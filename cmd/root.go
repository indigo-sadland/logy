package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "logy <mode> [options]",
	Short: "Automate recon and data collection",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddGroup(&cobra.Group{
		ID:    "domain",
		Title: "Subdomain Discovery:",
	})

	rootCmd.AddGroup(&cobra.Group{
		ID:    "service",
		Title: "Service Discovery:",
	})

	rootCmd.AddGroup(&cobra.Group{
		ID:    "tracking",
		Title: "Commands Tracking:",
	})

}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "config.yaml"
	}
	return filepath.Join(home, ".config", "logy", "config.yaml")
}

func defaultStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "state.yaml"
	}
	return filepath.Join(home, ".config", "logy", "state.yaml")
}

func defaultTranscriptDirPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "transcripts"
	}
	return filepath.Join(home, ".config", "logy", "transcripts")
}
