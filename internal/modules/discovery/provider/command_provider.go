package provider

import (
	"context"
	"errors"
	"github.com/indigo-sadland/logy/internal/executor"
	"os/exec"
	"strings"
)

type CommandProvider struct {
	name                string
	argsFor             func(domain string) []string
	progressDoneFactory func(string) func()
}

// NewCommandProvider builds a CLI-backed discovery provider without progress hooks.
func NewCommandProvider(name string, argsFor func(domain string) []string) *CommandProvider {
	return &CommandProvider{name: name, argsFor: argsFor}
}

// NewCommandProviderWithProgress builds a CLI-backed discovery provider with an optional progress finalizer.
func NewCommandProviderWithProgress(name string, argsFor func(domain string) []string, progressDoneFactory func(string) func()) *CommandProvider {
	return &CommandProvider{name: name, argsFor: argsFor, progressDoneFactory: progressDoneFactory}
}

// Name returns the executable name used to identify the provider.
func (p *CommandProvider) Name() string {
	return p.name
}

// ArgsFor returns the command-line arguments for a given discovery target.
func (p *CommandProvider) ArgsFor(domain string) []string {
	if p.argsFor == nil {
		return nil
	}
	return p.argsFor(domain)
}

// HasProgress reports whether the provider has a progress cleanup callback.
func (p *CommandProvider) HasProgress() bool {
	return p.progressDoneFactory != nil
}

// Discover executes the configured CLI tool and keeps only normalized candidates for the target domain.
func (p *CommandProvider) Discover(ctx context.Context, domain string) ([]string, error) {
	domain = strings.Trim(strings.ToLower(domain), ".")
	if _, err := exec.LookPath(p.name); err != nil {
		return nil, errors.New(p.name + " is not installed or not in PATH")
	}

	out := make(chan string, 1024)
	errCh := make(chan error, 1)

	go func() {
		errCh <- executor.Run(ctx, out, p.name, p.argsFor(domain)...)
		close(out)
	}()

	var progressDone func()
	if p.progressDoneFactory != nil {
		progressDone = p.progressDoneFactory(domain)
	}
	if progressDone != nil {
		defer progressDone()
	}

	results := make([]string, 0, 512)
	for line := range out {
		host := NormalizeCandidate(line)
		if host == "" || !strings.HasSuffix(host, "."+domain) && host != domain {
			continue
		}
		results = append(results, host)
	}

	if err := <-errCh; err != nil {
		return nil, err
	}
	return results, nil
}

// NormalizeCandidate lowercases and trims wildcard or trailing-dot noise from a discovered hostname.
func NormalizeCandidate(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "*.")
	return strings.Trim(v, ".")
}
