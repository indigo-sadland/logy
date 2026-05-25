package resolver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type Config struct {
	Binary        string
	Workers       int
	Timeout       time.Duration
	ResolversFile string
}

type Result struct {
	Subdomain string
	IPs       []string
	Alive     bool
	Error     string
}

type dnsxRecord struct {
	Host string   `json:"host"`
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
}

// ResolveAll resolves hosts with dnsx and returns a result for every requested subdomain.
func ResolveAll(ctx context.Context, hosts []string, cfg Config, logf func(string, ...any)) ([]Result, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if cfg.Binary == "" {
		cfg.Binary = "dnsx"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 4 * time.Second
	}
	if _, err := exec.LookPath(cfg.Binary); err != nil {
		return nil, fmt.Errorf("%s is not installed or not in PATH", cfg.Binary)
	}
	if logf != nil {
		logf("[*] resolver/%s: started, hosts=%d, threads=%d\n", cfg.Binary, len(hosts), cfg.Workers)
	}

	inputFile, err := os.CreateTemp("", "logy-dnsx-input-*.txt")
	if err != nil {
		return nil, err
	}
	inputPath := inputFile.Name()
	defer os.Remove(inputPath)

	for _, host := range hosts {
		if _, err := fmt.Fprintln(inputFile, host); err != nil {
			_ = inputFile.Close()
			return nil, err
		}
	}
	if err := inputFile.Close(); err != nil {
		return nil, err
	}

	args := []string{
		"-silent",
		"-json",
		"-resp",
		"-l", inputPath,
		"-threads", fmt.Sprintf("%d", cfg.Workers),
		"-timeout", fmt.Sprintf("%d", timeoutSeconds(cfg.Timeout)),
	}
	if cfg.ResolversFile != "" {
		args = append(args, "-r", cfg.ResolversFile)
	}
	if logf != nil {
		if cfg.ResolversFile != "" {
			logf("[*] resolver/%s: using resolvers file %s\n", cfg.Binary, cfg.ResolversFile)
		} else {
			logf("[*] resolver/%s: using default resolvers\n", cfg.Binary)
		}
	}

	cmd := exec.CommandContext(ctx, cfg.Binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	tracker := newDNSXProgressTracker(cfg.Binary, len(hosts))
	tracker.start()
	defer tracker.finish()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var stdout bytes.Buffer
	scanner := bufio.NewScanner(stdoutPipe)
	for scanner.Scan() {
		line := scanner.Text()
		stdout.WriteString(line)
		stdout.WriteByte('\n')
		if strings.TrimSpace(line) != "" {
			tracker.incrementResolved()
		}
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if logf != nil {
			logf("[!] resolver/%s: failed: %s\n", cfg.Binary, msg)
		}
		return nil, fmt.Errorf("dnsx failed: %s", msg)
	}

	resolvedByHost, err := parseDNSXOutput(stdout.Bytes())
	if err != nil {
		return nil, err
	}

	results := make([]Result, 0, len(hosts))
	for _, host := range hosts {
		ips := resolvedByHost[host]
		result := Result{
			Subdomain: host,
			IPs:       ips,
			Alive:     len(ips) > 0,
		}
		if !result.Alive {
			result.Error = "no records returned by dnsx"
		}
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Subdomain < results[j].Subdomain
	})
	if logf != nil {
		resolvedCount := 0
		for _, result := range results {
			if result.Alive {
				resolvedCount++
			}
		}
		logf("[+] resolver/%s: completed, resolved=%d unresolved=%d\n", cfg.Binary, resolvedCount, len(results)-resolvedCount)
	}
	return results, nil
}

// parseDNSXOutput decodes line-delimited dnsx JSON output into host-to-IP mappings.
func parseDNSXOutput(raw []byte) (map[string][]string, error) {
	results := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record dnsxRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("parse dnsx json: %w", err)
		}
		host := normalizeHost(record.Host)
		if host == "" {
			continue
		}

		ips := append([]string{}, record.A...)
		ips = append(ips, record.AAAA...)
		ips = normalizeIPs(ips)
		if len(ips) > 0 {
			results[host] = ips
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(results) == 0 && len(bytes.TrimSpace(raw)) > 0 {
		return nil, errors.New("dnsx returned output but no parseable DNS records")
	}
	return results, nil
}

// normalizeHost canonicalizes dnsx host values for stable map keys and comparisons.
func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	return strings.Trim(host, ".")
}

// normalizeIPs trims, sorts, and deduplicates IP values from dnsx output.
func normalizeIPs(ips []string) []string {
	if len(ips) == 0 {
		return nil
	}
	for i := range ips {
		ips[i] = strings.TrimSpace(ips[i])
	}
	sort.Strings(ips)
	out := make([]string, 0, len(ips))
	var prev string
	for _, ip := range ips {
		if ip == "" || ip == prev {
			continue
		}
		out = append(out, ip)
		prev = ip
	}
	return out
}

// timeoutSeconds converts a duration to the minimum whole-second value accepted by dnsx.
func timeoutSeconds(d time.Duration) int {
	seconds := int(math.Ceil(d.Seconds()))
	if seconds < 1 {
		return 1
	}
	return seconds
}
