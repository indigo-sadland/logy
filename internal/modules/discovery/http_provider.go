package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultBufferOverURL   = "https://tls.bufferover.run/dns"
	defaultRipeStatURL     = "https://stat.ripe.net"
	ripeStatMaxConcurrency = 8
	announcedPrefixesPath  = "/data/announced-prefixes/data.json"
	reverseDNSIPPath       = "/data/reverse-dns-ip/data.json"
)

type HTTPProviderConfig struct {
	Client           *http.Client
	Logf             func(string, ...any)
	BufferOverConfig BufferOverConfig
	RipeStatConfig   RipeStatConfig
}

type BufferOverConfig struct {
	BaseURL string
	APIKey  string
}

type RipeStatConfig struct {
	BaseURL string
}

type HTTPProvider struct {
	name       string
	client     *http.Client
	logf       func(string, ...any)
	bufferOver bufferOver
	ripeStat   ripeStat
}

type bufferOver struct {
	baseURL string
	apiKey  string
}

type ripeStat struct {
	baseURL string
}

type ripeStatResponse[T any] struct {
	Status string `json:"status"`
	Data   T      `json:"data"`
}

type ripeStatReverseDNSIPData struct {
	QueryTime string   `json:"query_time"`
	Resource  string   `json:"resource"`
	Result    []string `json:"result"`
	Error     string   `json:"error"`
}

// NewBufferOverHTTPProvider builds an HTTP provider configured for the BufferOver API.
func NewBufferOverHTTPProvider(name string, cfg HTTPProviderConfig) *HTTPProvider {
	baseURL := strings.TrimSpace(cfg.BufferOverConfig.BaseURL)
	if baseURL == "" {
		baseURL = defaultBufferOverURL
	}

	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}

	return &HTTPProvider{
		name:   name,
		client: client,
		logf:   cfg.Logf,
		bufferOver: bufferOver{
			baseURL: baseURL,
			apiKey:  strings.TrimSpace(cfg.BufferOverConfig.APIKey),
		},
	}
}

// NewRipeStatHTTPProvider builds an HTTP provider configured for the RIPEStat API.
func NewRipeStatHTTPProvider(name string, cfg HTTPProviderConfig) *HTTPProvider {
	baseURL := strings.TrimSpace(cfg.RipeStatConfig.BaseURL)
	if baseURL == "" {
		baseURL = defaultRipeStatURL
	}

	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}

	return &HTTPProvider{
		name:   name,
		client: client,
		logf:   cfg.Logf,
		ripeStat: ripeStat{
			baseURL: baseURL,
		},
	}
}

// Name returns the registered provider name.
func (p *HTTPProvider) Name() string {
	return p.name
}

// Discover dispatches to the provider-specific HTTP discovery implementation.
func (p *HTTPProvider) Discover(ctx context.Context, target string) ([]string, error) {
	switch p.name {
	case "bufferover":
		return bufferOverDiscover(ctx, target, p)
	case "ripestat":
		return ripeStatDiscover(ctx, target, p)
	default:
		return nil, fmt.Errorf("%s: unsupported http provider", p.name)
	}
}

// bufferOverDiscover queries BufferOver for subdomains under the requested domain.
func bufferOverDiscover(ctx context.Context, domain string, p *HTTPProvider) ([]string, error) {
	domain = provider.NormalizeCandidate(domain)
	if domain == "" {
		return nil, fmt.Errorf("%s: domain is required", p.name)
	}
	if p.bufferOver.apiKey == "" {
		return nil, fmt.Errorf("%s: api key is required", p.name)
	}

	reqURL, err := url.Parse(p.bufferOver.baseURL)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid base url: %w", p.name, err)
	}

	query := reqURL.Query()
	query.Set("q", "."+domain)
	reqURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", p.name, err)
	}
	req.Header.Set("x-api-key", p.bufferOver.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", p.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s: unexpected status %s: %s", p.name, resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Results []string `json:"Results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", p.name, err)
	}

	seen := make(map[string]struct{}, len(payload.Results))
	results := make([]string, 0, len(payload.Results))
	for _, item := range payload.Results {
		host := parseBufferOverResult(item)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		results = append(results, host)
	}

	return results, nil
}

// parseBufferOverResult extracts a hostname from a BufferOver result row.
func parseBufferOverResult(item string) string {
	value := strings.TrimSpace(item)
	if value == "" {
		return ""
	}
	idx := strings.LastIndexByte(value, ',')
	if idx < 0 {
		return ""
	}
	value = strings.TrimSpace(value[idx+1:])
	if strings.HasPrefix(strings.ToLower(value), "*.") {
		return ""
	}
	return provider.NormalizeCandidate(value)
}

// ripeStatDiscover expands ASN prefixes and resolves PTR records through RIPEStat.
func ripeStatDiscover(ctx context.Context, asn string, p *HTTPProvider) ([]string, error) {
	asn = normalizeASN(asn)
	if asn == "" {
		return nil, fmt.Errorf("%s: asn is required when using --asn", p.name)
	}

	prefixes, err := p.fetchRipeStatPrefixes(ctx, asn)
	if err != nil {
		return nil, err
	}
	if p.logf != nil {
		p.logf("[*] discovery/%s: announced_prefixes=%d\n", p.name, len(prefixes))
		if len(prefixes) > 0 {
			p.logf("[*] discovery/%s: prefixes=%s\n", p.name, strings.Join(prefixes, ", "))
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan string)
	errCh := make(chan error, 1)
	seen := make(map[string]struct{})
	var seenMu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < ripeStatMaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				host, err := p.fetchRipeStatPTR(ctx, ip)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					cancel()
					return
				}
				if host == "" {
					continue
				}
				seenMu.Lock()
				seen[host] = struct{}{}
				seenMu.Unlock()
			}
		}()
	}

	for _, prefix := range prefixes {
		if err := emitIPv4sFromPrefix(ctx, prefix, jobs); err != nil {
			close(jobs)
			wg.Wait()
			select {
			case requestErr := <-errCh:
				return nil, requestErr
			default:
			}
			return nil, err
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return nil, err
	default:
	}

	results := make([]string, 0, len(seen))
	for host := range seen {
		results = append(results, host)
	}
	sort.Strings(results)
	return results, nil
}

// fetchRipeStatPrefixes loads announced prefixes for an ASN from RIPEstat.
func (p *HTTPProvider) fetchRipeStatPrefixes(ctx context.Context, asn string) ([]string, error) {
	reqURL, err := buildAPIURL(p.ripeStat.baseURL, announcedPrefixesPath, map[string]string{
		"resource": asn,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: build announced-prefixes url: %w", p.name, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: build announced-prefixes request: %w", p.name, err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: announced-prefixes request failed: %w", p.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s: announced-prefixes unexpected status %s: %s", p.name, resp.Status, strings.TrimSpace(string(body)))
	}

	var ripeStatPrefixesResp struct {
		Status string `json:"status"`
		Data   struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ripeStatPrefixesResp); err != nil {
		return nil, fmt.Errorf("%s: decode announced-prefixes response: %w", p.name, err)
	}
	if ripeStatPrefixesResp.Status != "" && !strings.EqualFold(ripeStatPrefixesResp.Status, "ok") {
		return nil, fmt.Errorf("%s: announced-prefixes returned status %q", p.name, ripeStatPrefixesResp.Status)
	}

	prefixes := make([]string, 0, len(ripeStatPrefixesResp.Data.Prefixes))
	for _, item := range ripeStatPrefixesResp.Data.Prefixes {
		prefix := strings.TrimSpace(item.Prefix)
		if prefix == "" {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// fetchRipeStatPTR looks up a reverse-DNS hostname for a single IP through RIPEstat.
func (p *HTTPProvider) fetchRipeStatPTR(ctx context.Context, ip string) (string, error) {
	reqURL, err := buildAPIURL(p.ripeStat.baseURL, reverseDNSIPPath, map[string]string{
		"resource": ip,
	})
	if err != nil {
		return "", fmt.Errorf("%s: build reverse-dns-ip url for %s: %w", p.name, ip, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("%s: build reverse-dns-ip request for %s: %w", p.name, ip, err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: reverse-dns-ip request failed for %s: %w", p.name, ip, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("%s: reverse-dns-ip unexpected status %s for %s: %s", p.name, resp.Status, ip, strings.TrimSpace(string(body)))
	}

	var payload ripeStatResponse[ripeStatReverseDNSIPData]
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("%s: decode reverse-dns-ip response for %s: %w", p.name, ip, err)
	}
	if payload.Status != "" && !strings.EqualFold(payload.Status, "ok") {
		return "", fmt.Errorf("%s: reverse-dns-ip returned status %q for %s", p.name, payload.Status, ip)
	}
	if strings.TrimSpace(payload.Data.Error) != "" {
		return "", nil
	}
	for _, host := range payload.Data.Result {
		host = provider.NormalizeCandidate(host)
		if host != "" {
			return host, nil
		}
	}
	return "", nil
}

// buildAPIURL resolves an API path against a base URL and applies non-empty query parameters.
func buildAPIURL(baseURL string, path string, params map[string]string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}

	reqURL := base.ResolveReference(ref)
	query := reqURL.Query()
	for key, value := range params {
		if strings.TrimSpace(value) == "" {
			continue
		}
		query.Set(key, value)
	}
	reqURL.RawQuery = query.Encode()
	return reqURL.String(), nil
}

// normalizeASN validates and canonicalizes an ASN string to AS<digits> form.
func normalizeASN(value string) string {
	value = strings.TrimSpace(strings.ToUpper(value))
	value = strings.TrimPrefix(value, "AS")
	if value == "" {
		return ""
	}
	if _, err := strconv.ParseUint(value, 10, 32); err != nil {
		return ""
	}
	return "AS" + value
}

// emitIPv4sFromPrefix sends every IPv4 address in a CIDR block to the output channel.
func emitIPv4sFromPrefix(ctx context.Context, prefix string, out chan<- string) error {
	_, network, err := net.ParseCIDR(strings.TrimSpace(prefix))
	if err != nil {
		return fmt.Errorf("parse prefix %q: %w", prefix, err)
	}

	start := network.IP.To4()
	if start == nil {
		return nil
	}

	maskSize, bits := network.Mask.Size()
	if bits != 32 {
		return nil
	}

	startInt := ipv4ToUint32(start)
	hostCount := uint64(1) << uint64(bits-maskSize)
	if hostCount == 0 {
		return nil
	}
	if hostCount > uint64(math.MaxUint32) {
		return fmt.Errorf("prefix %q exceeds supported ipv4 range", prefix)
	}

	endInt := startInt + uint32(hostCount-1)
	for current := startInt; ; current++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- uint32ToIPv4(current).String():
		}
		if current == endInt {
			break
		}
	}
	return nil
}

// ipv4ToUint32 converts an IPv4 address to its integer form for range iteration.
func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIPv4 converts an integer back to an IPv4 address.
func uint32ToIPv4(value uint32) net.IP {
	return net.IPv4(
		byte(value>>24),
		byte(value>>16),
		byte(value>>8),
		byte(value),
	)
}
