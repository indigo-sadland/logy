package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadNormalizesDiscoveryToolConfigKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	resolversPath := filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("write resolvers file: %v", err)
	}
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - amass
  tool_config:
    Amass:
      resolvers_file: " ` + resolversPath + ` "
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	toolCfg, ok := cfg.Discovery.ToolConfig["amass"]
	if !ok {
		t.Fatalf("expected normalized amass tool config key, got %#v", cfg.Discovery.ToolConfig)
	}
	if toolCfg.ResolversFile != resolversPath {
		t.Fatalf("expected trimmed resolvers file, got %q", toolCfg.ResolversFile)
	}
}

func TestLoadResolvesRelativeDatabasePathAgainstConfigDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: demo.db
discovery:
  tools:
    - subfinder
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	want := filepath.Join(dir, "demo.db")
	if cfg.Database.Path != want {
		t.Fatalf("database.path=%q; want %q", cfg.Database.Path, want)
	}
}

func TestDiscoveryEnabledToolsHonorsDisabledFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - subfinder
    - amass
  tool_config:
    amass:
      enabled: false
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	enabled := cfg.Discovery.EnabledTools()
	if len(enabled) != 1 || enabled[0] != "subfinder" {
		t.Fatalf("expected only subfinder enabled, got %v", enabled)
	}
}

func TestLoadRequiresAtLeastOneEnabledDiscoveryTool(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - subfinder
  tool_config:
    subfinder:
      enabled: false
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error when all discovery tools are disabled")
	}
}

func TestLoadAllowsBufferOverAPIKeyFromEncryptedSecrets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - bufferover
  tool_config:
    bufferover:
      enabled: true
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("load config: %v", err)
	}
}

func TestLoadRequiresExistingResolverResolversFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - subfinder
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
  resolvers_file: ` + filepath.Join(dir, "missing.txt") + `
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error when resolver resolvers_file is missing")
	}
	if !strings.Contains(err.Error(), "config.resolver.resolvers_file is invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAcceptsExistingResolverResolversFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	resolversPath := filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("write resolvers file: %v", err)
	}

	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - subfinder
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
  resolvers_file: " ` + resolversPath + ` "
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Resolver.ResolversFile != resolversPath {
		t.Fatalf("expected trimmed resolver resolvers_file, got %q", cfg.Resolver.ResolversFile)
	}
}

func TestLoadRequiresExistingAmassResolversFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - amass
  tool_config:
    amass:
      resolvers_file: ` + filepath.Join(dir, "missing.txt") + `
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error when amass resolvers_file is missing")
	}
	if !strings.Contains(err.Error(), "config.discovery.tool_config.amass.resolvers_file is invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAcceptsExistingAmassResolversFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	resolversPath := filepath.Join(dir, "amass-resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("write resolvers file: %v", err)
	}

	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
database:
  path: recon.db
discovery:
  tools:
    - amass
  tool_config:
    amass:
      resolvers_file: " ` + resolversPath + ` "
resolver:
  binary: dnsx
  workers: 10
  timeout: 4s
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	toolCfg, ok := cfg.Discovery.ToolConfig["amass"]
	if !ok {
		t.Fatalf("expected amass tool config, got %#v", cfg.Discovery.ToolConfig)
	}
	if toolCfg.ResolversFile != resolversPath {
		t.Fatalf("expected trimmed amass resolvers_file, got %q", toolCfg.ResolversFile)
	}
}
