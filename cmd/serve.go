package cmd

import (
	"fmt"
	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/storage"
	logyweb "github.com/indigo-sadland/logy/internal/web"

	"github.com/spf13/cobra"
)

var serveAddr string
var serveConfigPath string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve a read-only web UI for the local Logy database",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServe(cmd)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1:8080", "HTTP listen address")
	serveCmd.Flags().StringVar(&serveConfigPath, "config", defaultConfigPath(), "path to logy's config yaml")
}

func runServe(cmd *cobra.Command) error {
	cfg, err := config.Load(serveConfigPath)
	if err != nil {
		return err
	}
	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer store.Close()

	fmt.Printf("[*] web ui: http://%s\n", serveAddr)
	server := logyweb.NewServer(store)
	return server.ListenAndServe(cmd.Context(), serveAddr)
}
