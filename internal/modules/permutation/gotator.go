package permutation

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"github.com/indigo-sadland/logy/internal/utils/dedup"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type Config struct {
	Binary           string
	PermutationsFile string
	Depth            int
	Numbers          int
	MinDup           bool
	MD               bool
}

// Generate runs gotator against known subdomains and returns normalized, deduplicated candidates for the target domain.
func Generate(ctx context.Context, subdomains []string, matchDomain string, cfg Config, logf func(string, ...any)) ([]string, error) {
	if len(subdomains) == 0 {
		return nil, nil
	}
	matchDomain = provider.NormalizeCandidate(matchDomain)
	if cfg.Binary == "" {
		cfg.Binary = "gotator"
	}
	if cfg.Depth <= 0 {
		cfg.Depth = 1
	}
	if cfg.Numbers <= 0 {
		cfg.Numbers = 10
	}
	cfg.PermutationsFile = strings.TrimSpace(cfg.PermutationsFile)
	if cfg.PermutationsFile == "" {
		return nil, fmt.Errorf("permutations file is required")
	}
	if _, err := os.Stat(cfg.PermutationsFile); err != nil {
		return nil, fmt.Errorf("permutations file is invalid: %w", err)
	}
	if _, err := exec.LookPath(cfg.Binary); err != nil {
		return nil, fmt.Errorf("%s is not installed or not in PATH", cfg.Binary)
	}

	inputFile, err := os.CreateTemp("", "logy-gotator-input-*.txt")
	if err != nil {
		return nil, err
	}
	inputPath := inputFile.Name()
	defer os.Remove(inputPath)

	for _, subdomain := range subdomains {
		host := provider.NormalizeCandidate(subdomain)
		if host == "" {
			continue
		}
		if _, err := fmt.Fprintln(inputFile, host); err != nil {
			_ = inputFile.Close()
			return nil, err
		}
	}
	if err := inputFile.Close(); err != nil {
		return nil, err
	}

	args := []string{
		"-sub", inputPath,
		"-perm", cfg.PermutationsFile,
		"-depth", fmt.Sprintf("%d", cfg.Depth),
		"-numbers", fmt.Sprintf("%d", cfg.Numbers),
	}
	if cfg.MinDup {
		args = append(args, "-mindup")
	}
	if cfg.MD {
		args = append(args, "-md")
	}

	if logf != nil {
		logf("[*] permutation/%s: started, seeds=%d depth=%d numbers=%d\n", cfg.Binary, len(subdomains), cfg.Depth, cfg.Numbers)
	}

	cmd := exec.CommandContext(ctx, cfg.Binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	seen := dedup.New()
	out := make([]string, 0, len(subdomains))
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		host := provider.NormalizeCandidate(scanner.Text())
		if host == "" {
			continue
		}
		if matchDomain != "" && !strings.HasSuffix(host, "."+matchDomain) && host != matchDomain {
			continue
		}
		if seen.Add(host) {
			out = append(out, host)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if logf != nil {
			logf("[!] permutation/%s: failed: %s\n", cfg.Binary, msg)
		}
		return nil, fmt.Errorf("gotator failed: %s", msg)
	}

	sort.Strings(out)
	if logf != nil {
		logf("[+] permutation/%s: completed, generated=%d\n", cfg.Binary, len(out))
	}
	return out, nil
}
