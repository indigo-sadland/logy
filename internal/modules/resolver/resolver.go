package resolver

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Config struct {
	// Binary is deprecated and ignored. DNS resolution is handled in-process
	// through codeberg.org/miekg/dns.
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

type lookupResult struct {
	host string
	ips  []string
	err  error
}

const resolverName = "miekg-dns"

var defaultResolverAddresses = []string{"1.1.1.1:53", "8.8.8.8:53"}

// ResolveAll resolves hosts with miekg/dns and returns a result for every requested subdomain.
func ResolveAll(ctx context.Context, hosts []string, cfg Config, logf func(string, ...any)) ([]Result, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 4 * time.Second
	}

	resolvers, err := loadResolverAddresses(cfg.ResolversFile)
	if err != nil {
		return nil, err
	}
	if logf != nil {
		logf("[*] resolver/%s: started, hosts=%d, workers=%d\n", resolverName, len(hosts), cfg.Workers)
	}

	if logf != nil {
		if cfg.ResolversFile != "" {
			logf("[*] resolver/%s: using resolvers file %s\n", resolverName, cfg.ResolversFile)
		} else {
			logf("[*] resolver/%s: using system resolvers\n", resolverName)
		}
	}

	tracker := newProgressTracker(resolverName, len(hosts))
	tracker.start()
	defer tracker.finish()

	jobs := make(chan string)
	resultCh := make(chan lookupResult, len(hosts))
	client := dns.NewClient()
	var wg sync.WaitGroup

	// miekg/dns clients are safe for concurrent use, so workers share one
	// client while preserving the configured concurrency limit.
	workerCount := min(cfg.Workers, len(hosts))
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				ips, err := resolveHost(ctx, client, host, resolvers, cfg.Timeout)
				resultCh <- lookupResult{host: host, ips: ips, err: err}
				tracker.incrementResolved()
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			select {
			case <-ctx.Done():
				return
			case jobs <- host:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	resolvedByHost := make(map[string]lookupResult, len(hosts))
	for result := range resultCh {
		resolvedByHost[normalizeHost(result.host)] = result
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	results := make([]Result, 0, len(hosts))
	for _, host := range hosts {
		normalizedHost := normalizeHost(host)
		lookup := resolvedByHost[normalizedHost]
		result := Result{
			Subdomain: host,
			IPs:       lookup.ips,
			Alive:     len(lookup.ips) > 0,
		}
		if !result.Alive {
			result.Error = "no A or AAAA records returned"
			if lookup.err != nil {
				result.Error = lookup.err.Error()
			}
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
		logf("[+] resolver/%s: completed, resolved=%d unresolved=%d\n", resolverName, resolvedCount, len(results)-resolvedCount)
	}
	return results, nil
}

func resolveHost(ctx context.Context, client *dns.Client, host string, resolvers []string, timeout time.Duration) ([]string, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	host = dnsutil.Fqdn(host)

	var ips []string
	var lastErr error

	// Query A and AAAA independently so an error in one family does not hide
	// valid records from the other.
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		records, err := resolveRecordType(ctx, client, host, qtype, resolvers, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		ips = append(ips, records...)
	}
	ips = normalizeIPs(ips)
	if len(ips) > 0 {
		return ips, nil
	}
	return nil, lastErr
}

func resolveRecordType(ctx context.Context, client *dns.Client, host string, qtype uint16, resolvers []string, timeout time.Duration) ([]string, error) {
	var lastErr error

	// Try resolvers in order. NXDOMAIN is authoritative for this query type;
	// transport errors and transient rcodes fall through to the next resolver.
	for _, resolver := range resolvers {
		queryCtx, cancel := context.WithTimeout(ctx, timeout)
		msg := dns.NewMsg(host, qtype)
		if msg == nil {
			cancel()
			return nil, fmt.Errorf("unsupported query type %d", qtype)
		}
		msg.UDPSize = dns.DefaultMsgSize

		resp, _, err := client.Exchange(queryCtx, msg, "udp", resolver)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", resolver, err)
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return nil, nil
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: dns rcode %s", resolver, dnsutil.RcodeToString(resp.Rcode))
			continue
		}
		return ipsFromAnswers(resp.Answer), nil
	}
	return nil, lastErr
}

func ipsFromAnswers(answers []dns.RR) []string {
	ips := make([]string, 0, len(answers))
	for _, answer := range answers {
		switch rr := answer.(type) {
		case *dns.A:
			if rr.Addr.IsValid() {
				ips = append(ips, rr.Addr.String())
			}
		case *dns.AAAA:
			if rr.Addr.IsValid() {
				ips = append(ips, rr.Addr.String())
			}
		}
	}
	return ips
}

func loadResolverAddresses(path string) ([]string, error) {
	if strings.TrimSpace(path) != "" {
		return loadResolverAddressesFromFile(path)
	}

	// Prefer the host resolver configuration for local network fidelity, then
	// fall back to public resolvers when the environment does not expose one.
	resolvers, err := loadSystemResolverAddresses()
	if err != nil {
		return defaultResolverAddresses, nil
	}
	if len(resolvers) == 0 {
		return defaultResolverAddresses, nil
	}
	return resolvers, nil
}

func loadResolverAddressesFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	resolvers := parseResolverAddresses(string(data))
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("resolver file %s contains no usable resolvers", path)
	}
	return resolvers, nil
}

func loadSystemResolverAddresses() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	var resolvers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(stripResolverComment(line))
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if resolver := normalizeResolverAddress(fields[1]); resolver != "" {
			resolvers = append(resolvers, resolver)
		}
	}
	return dedupStrings(resolvers), nil
}

func parseResolverAddresses(raw string) []string {
	resolvers := make([]string, 0)
	for _, line := range strings.Split(raw, "\n") {
		// Resolver files use one address per line, with optional comments and
		// whitespace; hostnames and DoH URLs are intentionally ignored.
		value := strings.TrimSpace(stripResolverComment(line))
		if value == "" {
			continue
		}
		if fields := strings.Fields(value); len(fields) > 0 {
			value = fields[0]
		}
		if resolver := normalizeResolverAddress(value); resolver != "" {
			resolvers = append(resolvers, resolver)
		}
	}
	return dedupStrings(resolvers)
}

func stripResolverComment(line string) string {
	if idx := strings.IndexAny(line, "#;"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func normalizeResolverAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		return ""
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || strings.TrimSpace(port) == "" {
			return ""
		}
		return net.JoinHostPort(ip.String(), port)
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	return net.JoinHostPort(ip.String(), "53")
}

func dedupStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// normalizeHost canonicalizes host values for stable map keys and comparisons.
func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	return strings.Trim(host, ".")
}

// normalizeIPs trims, validates, sorts, and deduplicates IP values from DNS answers.
func normalizeIPs(ips []string) []string {
	return normalizeIPLiterals(ips)
}

func normalizeIPLiterals(ips []string) []string {
	if len(ips) == 0 {
		return nil
	}
	for i := range ips {
		ips[i] = strings.TrimSpace(ips[i])
	}
	sort.Strings(ips)
	out := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		value := parsed.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
