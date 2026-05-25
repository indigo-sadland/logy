package discovery

import (
	"github.com/indigo-sadland/logy/internal/modules/discovery/models"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"slices"
	"strings"
	"sync"
)

var (
	providerMu        sync.RWMutex
	providerFactories = map[string]func(models.Config) provider.Provider{
		"subfinder": func(cfg models.Config) provider.Provider {
			return provider.NewCommandProvider("subfinder", func(domain string) []string {
				args := []string{"-d", domain, "-silent", "-all"}
				if toolCfg, ok := cfg.ToolConfig["subfinder"]; ok && toolCfg.ConfigFile != "" {
					args = append(args, "-config", toolCfg.ConfigFile)
				}
				return args
			})
		},
		"amass": func(cfg models.Config) provider.Provider {
			return provider.NewCommandProvider("amass", func(domain string) []string {
				args := []string{"enum", "-passive", "-d", domain, "-silent"}
				if toolCfg, ok := cfg.ToolConfig["amass"]; ok && toolCfg.ResolversFile != "" {
					args = append(args, "-trf", toolCfg.ResolversFile)
				}
				if toolCfg, ok := cfg.ToolConfig["amass"]; ok && toolCfg.ConfigFile != "" {
					args = append(args, "-config", toolCfg.ConfigFile)
				}
				return args
			})
		},
		"findomain": func(cfg models.Config) provider.Provider {
			return provider.NewCommandProvider("findomain", func(domain string) []string {
				return []string{"-t", domain, "-q"}
			})
		},
		"bufferover": func(cfg models.Config) provider.Provider {
			toolCfg := cfg.ToolConfig["bufferover"]
			return NewBufferOverHTTPProvider("bufferover", HTTPProviderConfig{
				Logf: cfg.Logf,
				BufferOverConfig: BufferOverConfig{
					BaseURL: toolCfg.BaseURL,
					APIKey:  toolCfg.APIKey,
				},
			})
		},
		"ripestat": func(cfg models.Config) provider.Provider {
			toolCfg := cfg.ToolConfig["ripestat"]
			return NewRipeStatHTTPProvider("ripestat", HTTPProviderConfig{
				Logf: cfg.Logf,
				RipeStatConfig: RipeStatConfig{
					BaseURL: toolCfg.BaseURL,
				},
			})
		},
	}
)

// RegisterProviderFactory adds or replaces a provider factory by normalized name.
func RegisterProviderFactory(name string, factory func(models.Config) provider.Provider) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || factory == nil {
		return
	}
	providerMu.Lock()
	providerFactories[name] = factory
	providerMu.Unlock()
}

// ProvidersFromNames builds provider instances for the requested names in stable name order.
func ProvidersFromNames(names []string, cfg models.Config) []provider.Provider {
	out := make([]provider.Provider, 0, len(names))

	providerMu.RLock()
	factories := make(map[string]func(models.Config) provider.Provider, len(providerFactories))
	for name, factory := range providerFactories {
		factories[name] = factory
	}
	providerMu.RUnlock()

	for _, raw := range names {
		name := strings.TrimSpace(strings.ToLower(raw))
		if factory, ok := factories[name]; ok {
			out = append(out, factory(cfg))
		}
	}

	slices.SortFunc(out, func(a, b provider.Provider) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return out
}
