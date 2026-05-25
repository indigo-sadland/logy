package resolver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
)

type VHostConfig struct {
	Binary string
}

// ResolveVHosts runs VhostFinder against unresolved hosts and known IPs and returns newly resolved matches.
func ResolveVHosts(ctx context.Context, hosts []string, ips []string, cfg VHostConfig, logf func(string, ...any)) ([]Result, error) {
	hosts = uniqueSortedStrings(hosts)
	ips = uniqueSortedStrings(ips)

	if len(hosts) == 0 || len(ips) == 0 {
		return nil, nil
	}
	if cfg.Binary == "" {
		cfg.Binary = "VhostFinder"
	}
	if _, err := exec.LookPath(cfg.Binary); err != nil {
		return nil, fmt.Errorf("%s is not installed or not in PATH", cfg.Binary)
	}
	if logf != nil {
		logf("[*] resolver/%s: started, hosts=%d ips=%d\n", cfg.Binary, len(hosts), len(ips))
	}

	hostFile, err := writeTempLines("logy-vhost-hosts-*.txt", hosts)
	if err != nil {
		return nil, err
	}
	defer os.Remove(hostFile)

	ipFile, err := writeTempLines("logy-vhost-ips-*.txt", ips)
	if err != nil {
		return nil, err
	}
	defer os.Remove(ipFile)

	cmd := exec.CommandContext(ctx, cfg.Binary, "-ips", ipFile, "-wordlist", hostFile)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if logf != nil {
			logf("[!] resolver/%s: failed: %s\n", cfg.Binary, msg)
		}
		return nil, fmt.Errorf("%s failed: %s", cfg.Binary, msg)
	}

	results := parseVHostFinderOutput(stdout.Bytes(), hosts, ips)
	if logf != nil {
		logf("[+] resolver/%s: completed, resolved=%d unresolved=%d\n", cfg.Binary, len(results), len(hosts)-len(results))
	}
	return results, nil
}

// parseVHostFinderOutput extracts resolved host-to-IP matches from VhostFinder stdout.
func parseVHostFinderOutput(raw []byte, hosts []string, ips []string) []Result {
	hostSet := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		hostSet[normalizeHost(host)] = struct{}{}
	}
	ipSet := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			ipSet[parsed.String()] = struct{}{}
		}
	}

	byHost := make(map[string]map[string]struct{}, len(hosts))
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		matchedHosts, matchedIPs := extractVHostMatches(line, hostSet, ipSet)
		for _, host := range matchedHosts {
			if _, ok := byHost[host]; !ok {
				byHost[host] = make(map[string]struct{}, len(matchedIPs))
			}
			for _, ip := range matchedIPs {
				byHost[host][ip] = struct{}{}
			}
		}
	}

	results := make([]Result, 0, len(byHost))
	for host, hostIPs := range byHost {
		ipsOut := make([]string, 0, len(hostIPs))
		for ip := range hostIPs {
			ipsOut = append(ipsOut, ip)
		}
		slices.Sort(ipsOut)
		results = append(results, Result{
			Subdomain: host,
			IPs:       ipsOut,
			Alive:     true,
		})
	}
	slices.SortFunc(results, func(a, b Result) int {
		return strings.Compare(a.Subdomain, b.Subdomain)
	})
	return results
}

// extractVHostMatches finds known host and IP tokens inside a single VhostFinder output line.
func extractVHostMatches(line string, hostSet map[string]struct{}, ipSet map[string]struct{}) ([]string, []string) {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', ',', ';', '|', '[', ']', '(', ')', '{', '}', '"', '\'', '=', ':':
			return true
		default:
			return false
		}
	})

	hostMatches := make(map[string]struct{})
	ipMatches := make(map[string]struct{})
	for _, field := range fields {
		host := normalizeHost(field)
		if _, ok := hostSet[host]; ok {
			hostMatches[host] = struct{}{}
		}

		candidate := strings.Trim(field, "[]")
		if parsed := net.ParseIP(candidate); parsed != nil {
			ip := parsed.String()
			if _, ok := ipSet[ip]; ok {
				ipMatches[ip] = struct{}{}
			}
		}
	}

	hosts := make([]string, 0, len(hostMatches))
	for host := range hostMatches {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)

	ips := make([]string, 0, len(ipMatches))
	for ip := range ipMatches {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	return hosts, ips
}

// writeTempLines writes one value per line to a temp file and returns its path.
func writeTempLines(pattern string, lines []string) (string, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			_ = os.Remove(file.Name())
			return "", err
		}
	}
	return file.Name(), nil
}

// uniqueSortedStrings trims, deduplicates, and sorts string slices for deterministic tool input.
func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
