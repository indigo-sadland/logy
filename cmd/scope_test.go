package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestResolveDomainLabelPrefersExplicitValue(t *testing.T) {
	setTestHome(t)
	if err := saveScopeState(defaultStatePath(), scopeState{ActiveDomain: "scope.example.com"}); err != nil {
		t.Fatalf("saveScopeState: %v", err)
	}

	got, err := resolveDomainLabel("explicit.example.com")
	if err != nil {
		t.Fatalf("resolveDomainLabel: %v", err)
	}
	if got != "explicit.example.com" {
		t.Fatalf("domain=%q; want explicit.example.com", got)
	}
}

func TestResolveDomainLabelFallsBackToSavedScope(t *testing.T) {
	setTestHome(t)
	if err := saveScopeState(defaultStatePath(), scopeState{ActiveDomain: "scope.example.com"}); err != nil {
		t.Fatalf("saveScopeState: %v", err)
	}

	got, err := resolveDomainLabel("")
	if err != nil {
		t.Fatalf("resolveDomainLabel: %v", err)
	}
	if got != "scope.example.com" {
		t.Fatalf("domain=%q; want scope.example.com", got)
	}
}

func TestRequireDomainLabelErrorsWithoutExplicitOrScope(t *testing.T) {
	setTestHome(t)
	_, err := requireDomainLabel("")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestScopeStateRoundTripAndClear(t *testing.T) {
	home := setTestHome(t)
	statePath := filepath.Join(home, ".config", "logy", "state.yaml")
	if err := saveScopeState(statePath, scopeState{ActiveDomain: "scope.example.com"}); err != nil {
		t.Fatalf("saveScopeState: %v", err)
	}

	state, err := loadScopeState(statePath)
	if err != nil {
		t.Fatalf("loadScopeState: %v", err)
	}
	if state.ActiveDomain != "scope.example.com" {
		t.Fatalf("activeDomain=%q; want scope.example.com", state.ActiveDomain)
	}

	if err := clearScopeState(statePath); err != nil {
		t.Fatalf("clearScopeState: %v", err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat err=%v; want not exist", err)
	}
}

func TestResolvePortscanFromDBInputUsesExplicitDomainPositional(t *testing.T) {
	setTestHome(t)

	domain, args, err := resolvePortscanFromDBInput([]string{"example.com", "-Pn", "-sV"})
	if err != nil {
		t.Fatalf("resolvePortscanFromDBInput: %v", err)
	}
	if domain != "example.com" {
		t.Fatalf("domain=%q; want example.com", domain)
	}
	if !slices.Equal(args, []string{"-Pn", "-sV"}) {
		t.Fatalf("args=%v; want [-Pn -sV]", args)
	}
}

func TestResolvePortscanFromDBInputUsesScopeWhenFirstArgIsNmapFlag(t *testing.T) {
	setTestHome(t)
	if err := saveScopeState(defaultStatePath(), scopeState{ActiveDomain: "scope.example.com"}); err != nil {
		t.Fatalf("saveScopeState: %v", err)
	}

	domain, args, err := resolvePortscanFromDBInput([]string{"-Pn", "-sV"})
	if err != nil {
		t.Fatalf("resolvePortscanFromDBInput: %v", err)
	}
	if domain != "scope.example.com" {
		t.Fatalf("domain=%q; want scope.example.com", domain)
	}
	if !slices.Equal(args, []string{"-Pn", "-sV"}) {
		t.Fatalf("args=%v; want [-Pn -sV]", args)
	}
}

func setTestHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}
