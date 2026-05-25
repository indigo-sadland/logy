package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database  DatabaseConfig  `yaml:"database"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Resolver  ResolverConfig  `yaml:"resolver"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type DiscoveryConfig struct {
	Tools      []string                       `yaml:"tools"`
	ToolConfig map[string]DiscoveryToolConfig `yaml:"tool_config"`
}

type DiscoveryToolConfig struct {
	Enabled       *bool  `yaml:"enabled"`
	ResolversFile string `yaml:"resolvers_file"`
	ConfigFile    string `yaml:"config_file"`
	APIKey        string `yaml:"api_key"`
	BaseURL       string `yaml:"base_url"`
}

type ResolverConfig struct {
	Binary        string `yaml:"binary"`
	Workers       int    `yaml:"workers"`
	Timeout       string `yaml:"timeout"`
	ResolversFile string `yaml:"resolvers_file"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.applyDefaults()
	cfg.resolveRelativePaths(path)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Database.Path == "" {
		c.Database.Path = "recon.db"
	}
	if len(c.Discovery.Tools) == 0 {
		c.Discovery.Tools = []string{"subfinder", "amass"}
	}
	if len(c.Discovery.ToolConfig) > 0 {
		normalized := make(map[string]DiscoveryToolConfig, len(c.Discovery.ToolConfig))
		for name, toolCfg := range c.Discovery.ToolConfig {
			key := strings.ToLower(strings.TrimSpace(name))
			if key == "" {
				continue
			}
			toolCfg.ResolversFile = strings.TrimSpace(toolCfg.ResolversFile)
			toolCfg.ConfigFile = strings.TrimSpace(toolCfg.ConfigFile)
			toolCfg.APIKey = strings.TrimSpace(toolCfg.APIKey)
			toolCfg.BaseURL = strings.TrimSpace(toolCfg.BaseURL)
			normalized[key] = toolCfg
		}
		c.Discovery.ToolConfig = normalized
	}
	if c.Resolver.Workers <= 0 {
		c.Resolver.Workers = 100
	}
	if c.Resolver.Binary == "" {
		c.Resolver.Binary = "dnsx"
	}
	c.Resolver.ResolversFile = strings.TrimSpace(c.Resolver.ResolversFile)
	if c.Resolver.Timeout == "" {
		c.Resolver.Timeout = "4s"
	}
}

// resolveRelativePaths anchors portable config values to the config file
// directory instead of the caller's current working directory. This keeps demo
// fixtures and shared configs stable across shells and operating systems.
func (c *Config) resolveRelativePaths(configPath string) {
	baseDir := filepath.Dir(strings.TrimSpace(configPath))
	if baseDir == "" || baseDir == "." {
		return
	}
	c.Database.Path = resolveConfigRelativePath(baseDir, c.Database.Path)
}

func (c Config) Validate() error {
	if c.Database.Path == "" {
		return fmt.Errorf("config.database.path is required")
	}
	if len(c.Discovery.Tools) == 0 {
		return fmt.Errorf("config.discovery.tools must not be empty")
	}
	if len(c.Discovery.EnabledTools()) == 0 {
		return fmt.Errorf("config.discovery.tools must include at least one enabled tool")
	}
	for _, tool := range c.Discovery.EnabledTools() {
		if strings.EqualFold(strings.TrimSpace(tool), "amass") {
			toolCfg, ok := c.discoveryToolConfig("amass")
			if !ok || strings.TrimSpace(toolCfg.ResolversFile) == "" {
				return fmt.Errorf("config.discovery.tool_config.amass.resolvers_file is required when amass is enabled")
			}
			if err := validateExistingFile(toolCfg.ResolversFile); err != nil {
				return fmt.Errorf("config.discovery.tool_config.amass.resolvers_file is invalid: %w", err)
			}
		}
		if strings.EqualFold(strings.TrimSpace(tool), "bufferover") {
			if _, ok := c.discoveryToolConfig("bufferover"); !ok {
				return fmt.Errorf("config.discovery.tool_config.bufferover is required when bufferover is enabled")
			}
		}
	}
	if c.Resolver.Workers <= 0 {
		return fmt.Errorf("config.resolver.workers must be > 0")
	}
	if c.Resolver.Binary == "" {
		return fmt.Errorf("config.resolver.binary is required")
	}
	if c.Resolver.ResolversFile != "" {
		if err := validateExistingFile(c.Resolver.ResolversFile); err != nil {
			return fmt.Errorf("config.resolver.resolvers_file is invalid: %w", err)
		}
	}
	if _, err := time.ParseDuration(c.Resolver.Timeout); err != nil {
		return fmt.Errorf("config.resolver.timeout is invalid: %w", err)
	}
	return nil
}

func validateExistingFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}

func (c Config) ResolverTimeout() (time.Duration, error) {
	return time.ParseDuration(c.Resolver.Timeout)
}

func (c Config) discoveryToolConfig(name string) (DiscoveryToolConfig, bool) {
	for key, cfg := range c.Discovery.ToolConfig {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return cfg, true
		}
	}
	return DiscoveryToolConfig{}, false
}

func (c DiscoveryConfig) EnabledTools() []string {
	out := make([]string, 0, len(c.Tools))
	for _, tool := range c.Tools {
		name := strings.TrimSpace(tool)
		if name == "" {
			continue
		}
		toolCfg, ok := c.toolConfig(name)
		if ok && toolCfg.Enabled != nil && !*toolCfg.Enabled {
			continue
		}
		out = append(out, name)
	}
	return out
}

func (c DiscoveryConfig) toolConfig(name string) (DiscoveryToolConfig, bool) {
	for key, cfg := range c.ToolConfig {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return cfg, true
		}
	}
	return DiscoveryToolConfig{}, false
}

func resolveConfigRelativePath(baseDir string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(baseDir, value)
}
