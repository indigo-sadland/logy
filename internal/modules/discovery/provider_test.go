package discovery

import (
	"context"
	"fmt"
	provider2 "github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestProvidersFromNamesAddsAmassResolversFile(t *testing.T) {
	t.Parallel()

	providers := ProvidersFromNames([]string{"amass"}, Config{
		ToolConfig: map[string]ToolConfig{
			"amass": {ResolversFile: "/tmp/resolvers.txt"},
		},
	})
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}

	provider, ok := providers[0].(*provider2.CommandProvider)
	if !ok {
		t.Fatalf("expected CommandProvider, got %T", providers[0])
	}

	args := provider.ArgsFor("example.com")
	if !slices.Contains(args, "-trf") {
		t.Fatalf("expected -trf in args, got %v", args)
	}
	if !slices.Contains(args, "/tmp/resolvers.txt") {
		t.Fatalf("expected resolvers file in args, got %v", args)
	}
}

func TestProvidersFromNamesAddsBufferOverHTTPProvider(t *testing.T) {
	t.Parallel()

	providers := ProvidersFromNames([]string{"bufferover"}, Config{
		ToolConfig: map[string]ToolConfig{
			"bufferover": {
				APIKey:  "secret",
				BaseURL: "https://example.test/dns",
			},
		},
	})
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}

	provider, ok := providers[0].(*HTTPProvider)
	if !ok {
		t.Fatalf("expected HTTPProvider, got %T", providers[0])
	}
	if provider.bufferOver.apiKey != "secret" {
		t.Fatalf("expected api key to be propagated, got %q", provider.bufferOver.apiKey)
	}
	if provider.bufferOver.baseURL != "https://example.test/dns" {
		t.Fatalf("expected base url to be propagated, got %q", provider.bufferOver.baseURL)
	}
}

func TestPurednsProgressFactoryRequiresBruteforceInputs(t *testing.T) {
	t.Parallel()

	if got := purednsProgressDoneFactory(ToolConfig{}); got != nil {
		t.Fatal("expected nil progress factory without bruteforce inputs")
	}

	factory := purednsProgressDoneFactory(ToolConfig{
		WordlistFile:  "/tmp/words.txt",
		ResolversFile: "/tmp/resolvers.txt",
	})
	if factory == nil {
		t.Fatal("expected progress factory when bruteforce inputs are configured")
	}
	if done := factory("example.com"); done == nil {
		t.Fatal("expected progress finalizer for target domain")
	}
}

func TestCountNonEmptyLines(t *testing.T) {
	t.Parallel()

	file, err := os.CreateTemp(t.TempDir(), "wordlist-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString("api\n\nwww\n mail \n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}

	if got := countNonEmptyLines(file.Name()); got != 3 {
		t.Fatalf("countNonEmptyLines=%d; want 3", got)
	}
}

func TestProvidersFromNamesAddsRipeStatHTTPProvider(t *testing.T) {
	t.Parallel()

	providers := ProvidersFromNames([]string{"ripestat"}, Config{
		ToolConfig: map[string]ToolConfig{
			"ripestat": {
				BaseURL: "https://stat.example.test",
			},
		},
	})
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}

	provider, ok := providers[0].(*HTTPProvider)
	if !ok {
		t.Fatalf("expected HTTPProvider, got %T", providers[0])
	}
	if provider.ripeStat.baseURL != "https://stat.example.test" {
		t.Fatalf("expected base url to be propagated, got %q", provider.ripeStat.baseURL)
	}
}

func TestHTTPProviderDiscoverParsesBufferOverResults(t *testing.T) {
	t.Parallel()

	var gotAPIKey string
	var gotQuery string
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotAPIKey = r.Header.Get("x-api-key")
			gotQuery = r.URL.Query().Get("q")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(
					`{"Results":["23.66.19.18,5a7de128860598eec66afb7f8ca99786fc235bb1ef780c6ee390256984ebc34f,SALESFORCE.COM INC.,a25ca3e6c7c3c118a5cfcd7b2e208ef,image.et.uber.com","23.66.19.18,hash-2,SALESFORCE.COM INC.,hash-3,*.api.example.com","23.66.19.18,hash-4,SALESFORCE.COM INC.,hash-5,WWW.EXAMPLE.COM","bad-value","4.4.4.4,hash-6,OTHER INC.,hash-7,other.net"]}`,
				)),
				Request: r,
			}, nil
		}),
	}

	provider := NewBufferOverHTTPProvider("bufferover", HTTPProviderConfig{
		BufferOverConfig: BufferOverConfig{
			BaseURL: "https://example.test/dns",
			APIKey:  "secret",
		},
		Client: client,
	})

	results, err := provider.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if gotAPIKey != "secret" {
		t.Fatalf("expected x-api-key header, got %q", gotAPIKey)
	}
	if gotQuery != ".example.com" {
		t.Fatalf("expected query .example.com, got %q", gotQuery)
	}

	expected := []string{"image.et.uber.com", "www.example.com", "other.net"}
	if !slices.Equal(results, expected) {
		t.Fatalf("expected %v, got %v", expected, results)
	}
}

func TestHTTPProviderDiscoverResolvesRipeStatPTRs(t *testing.T) {
	t.Parallel()

	var announcedRequests int
	var logs []string
	var reverseRequests int
	var reverseResources []string
	var reverseMu sync.Mutex
	var active int32
	var maxActive int32

	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case announcedPrefixesPath:
				announcedRequests++
				if got := r.URL.Query().Get("resource"); got != "AS3333" {
					t.Fatalf("expected announced-prefixes resource AS3333, got %q", got)
				}
				if got := r.URL.Query().Get("sourceapp"); got != ripeStatSourceApp {
					t.Fatalf("expected sourceapp %q, got %q", ripeStatSourceApp, got)
				}
				return jsonResponse(`{
					"status":"ok",
					"data":{
						"prefixes":[
							{"prefix":"198.51.100.0/28"},
							{"prefix":"2001:db8::/126"}
						]
					}
				}`), nil
			case reverseDNSIPPath:
				atomic.AddInt32(&active, 1)
				current := atomic.LoadInt32(&active)
				for {
					prev := atomic.LoadInt32(&maxActive)
					if current <= prev || atomic.CompareAndSwapInt32(&maxActive, prev, current) {
						break
					}
				}
				defer atomic.AddInt32(&active, -1)

				resource := r.URL.Query().Get("resource")
				reverseMu.Lock()
				reverseRequests++
				reverseResources = append(reverseResources, resource)
				reverseMu.Unlock()
				time.Sleep(10 * time.Millisecond)

				switch resource {
				case "198.51.100.1", "198.51.100.2":
					return jsonResponse(`{"messages":[],"see_also":[],"version":"0.1","data_call_name":"reverse-dns-ip","data_call_status":"supported","cached":false,"query_id":"20260403092804-6bf9f17a-fd93-473a-8bf6-92e27aacfdb1","process_time":2,"server_id":"app190","build_version":"v0.9.5-2026.04.02","pipeline":"1214120","status":"ok","status_code":200,"time":"2026-04-03T09:28:04.545728","data":{"query_time":"2026-04-03T09:28:00","resource":"198.51.100.1","result":["ptr1.example.net."],"error":""}}`), nil
				case "198.51.100.3":
					return jsonResponse(`{"messages":[],"see_also":[],"version":"0.1","data_call_name":"reverse-dns-ip","data_call_status":"supported","cached":false,"query_id":"20260403092804-6bf9f17a-fd93-473a-8bf6-92e27aacfdb1","process_time":2,"server_id":"app190","build_version":"v0.9.5-2026.04.02","pipeline":"1214120","status":"ok","status_code":200,"time":"2026-04-03T09:28:04.545728","data":{"query_time":"2026-04-03T09:28:00","resource":"198.51.100.3","result":["PTR2.EXAMPLE.NET."],"error":""}}`), nil
				default:
					return jsonResponse(`{"messages":[],"see_also":[],"version":"0.1","data_call_name":"reverse-dns-ip","data_call_status":"supported","cached":false,"query_id":"20260403092804-6bf9f17a-fd93-473a-8bf6-92e27aacfdb1","process_time":2,"server_id":"app190","build_version":"v0.9.5-2026.04.02","pipeline":"1214120","status":"ok","status_code":200,"time":"2026-04-03T09:28:04.545728","data":{"query_time":"2026-04-03T09:28:00","resource":"` + resource + `","result":[],"error":"no PTR record found"}}`), nil
				}
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
				return nil, nil
			}
		}),
	}

	provider := NewRipeStatHTTPProvider("ripestat", HTTPProviderConfig{
		RipeStatConfig: RipeStatConfig{BaseURL: "https://stat.example.test"},
		Client:         client,
		Logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	})

	results, err := provider.Discover(context.Background(), "3333")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	expected := []string{"ptr1.example.net", "ptr2.example.net"}
	if !slices.Equal(results, expected) {
		t.Fatalf("expected %v, got %v", expected, results)
	}
	if announcedRequests != 1 {
		t.Fatalf("expected 1 announced-prefixes request, got %d", announcedRequests)
	}
	if reverseRequests != 16 {
		t.Fatalf("expected 16 reverse-dns-ip requests for /28, got %d", reverseRequests)
	}
	if maxActive > ripeStatMaxConcurrency {
		t.Fatalf("expected at most %d concurrent reverse requests, got %d", ripeStatMaxConcurrency, maxActive)
	}
	if !slices.Contains(reverseResources, "198.51.100.0") || !slices.Contains(reverseResources, "198.51.100.15") {
		t.Fatalf("expected full IPv4 prefix expansion, got %v", reverseResources)
	}
	expectedLogs := []string{
		"[*] discovery/ripestat: announced_prefixes=2\n",
		"[*] discovery/ripestat: prefixes=198.51.100.0/28, 2001:db8::/126\n",
	}
	if !slices.Equal(logs, expectedLogs) {
		t.Fatalf("logs=%v; want %v", logs, expectedLogs)
	}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
