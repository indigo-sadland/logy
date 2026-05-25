package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

type scopeState struct {
	ActiveDomain string `yaml:"active_domain"`
}

var scopeCmd = &cobra.Command{
	Use:   "scope",
	Short: "Manage the active domain scope",
}

var scopeSetCmd = &cobra.Command{
	Use:   "set <domain>",
	Short: "Persist the active domain scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := normalizeDomainValue(args[0])
		if domain == "" {
			return fmt.Errorf("domain must not be empty")
		}
		if err := saveScopeState(defaultStatePath(), scopeState{ActiveDomain: domain}); err != nil {
			return err
		}
		_, err := fmt.Fprintln(os.Stdout, domain)
		return err
	},
}

var scopeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the active domain scope",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := loadScopeState(defaultStatePath())
		if err != nil {
			return err
		}
		if strings.TrimSpace(state.ActiveDomain) == "" {
			return fmt.Errorf("no active scope set")
		}
		_, err = fmt.Fprintln(os.Stdout, state.ActiveDomain)
		return err
	},
}

var scopeClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear the active domain scope",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clearScopeState(defaultStatePath())
	},
}

func init() {
	rootCmd.AddCommand(scopeCmd)
	scopeCmd.AddCommand(scopeSetCmd)
	scopeCmd.AddCommand(scopeShowCmd)
	scopeCmd.AddCommand(scopeClearCmd)
}

func resolveDomainLabel(domain string) (string, error) {
	domain = normalizeDomainValue(domain)
	if domain != "" {
		return domain, nil
	}

	state, err := loadScopeState(defaultStatePath())
	if err != nil {
		return "", err
	}
	return normalizeDomainValue(state.ActiveDomain), nil
}

func requireDomainLabel(domain string) (string, error) {
	resolved, err := resolveDomainLabel(domain)
	if err != nil {
		return "", err
	}
	if resolved == "" {
		return "", fmt.Errorf("no active domain; pass --domain or run `logy scope set <domain>`")
	}
	return resolved, nil
}

func loadScopeState(path string) (scopeState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return scopeState{}, nil
		}
		return scopeState{}, err
	}
	var state scopeState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return scopeState{}, fmt.Errorf("parse scope state %s: %w", path, err)
	}
	state.ActiveDomain = normalizeDomainValue(state.ActiveDomain)
	return state, nil
}

func saveScopeState(path string, state scopeState) error {
	state.ActiveDomain = normalizeDomainValue(state.ActiveDomain)
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func clearScopeState(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
