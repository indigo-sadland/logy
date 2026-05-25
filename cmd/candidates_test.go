package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/storage"

	"github.com/spf13/cobra"
)

func TestCandidatesShowCommandOutputsStoredCandidates(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "recon.db")
	configPath := filepath.Join(dir, "config.yaml")

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.SavePermutationCandidates("example.com", []discovery.Entry{
		{Subdomain: "api.example.com", Sources: []string{"gotator"}},
	}); err != nil {
		t.Fatalf("save permutation candidates: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	configYAML := "database:\n  path: " + dbPath + "\ndiscovery:\n  tools:\n    - subfinder\nresolver:\n  binary: dnsx\n  workers: 10\n  timeout: 4s\n"
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("domain", "example.com", "")
	cmd.Flags().String("config", configPath, "")
	if err := cmd.Flags().Set("domain", "example.com"); err != nil {
		t.Fatalf("set domain: %v", err)
	}
	if err := cmd.Flags().Set("config", configPath); err != nil {
		t.Fatalf("set config: %v", err)
	}

	stdoutPath := filepath.Join(dir, "stdout.json")
	stdoutFile, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatalf("create stdout file: %v", err)
	}
	originalStdout := os.Stdout
	os.Stdout = stdoutFile
	defer func() { os.Stdout = originalStdout }()

	if err := candidatesShowCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("run candidates show: %v", err)
	}
	if err := stdoutFile.Close(); err != nil {
		t.Fatalf("close stdout file: %v", err)
	}

	raw, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	var got struct {
		Domain     string `json:"domain"`
		Candidates []struct {
			Subdomain string   `json:"subdomain"`
			Sources   []string `json:"sources"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal output: %v\nraw=%s", err, raw)
	}
	if got.Domain != "example.com" {
		t.Fatalf("domain=%q; want example.com", got.Domain)
	}
	if len(got.Candidates) != 1 || got.Candidates[0].Subdomain != "api.example.com" {
		t.Fatalf("candidates=%v; want api.example.com", got.Candidates)
	}
}
