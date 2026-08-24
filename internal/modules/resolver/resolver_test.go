package resolver

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func TestResolveAllQueriesAAndAAAAWithMiekgDNS(t *testing.T) {
	server := startResolverTestServer(t, func(req *dns.Msg) *dns.Msg {
		resp := dnsutil.SetReply(new(dns.Msg), req)
		name, qtype := dnsutil.Question(req)
		switch qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60},
				A:   rdata.A{Addr: netip.MustParseAddr("203.0.113.10")},
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: 60},
				AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::10")},
			})
		default:
			resp.Rcode = dns.RcodeNotImplemented
		}
		return resp
	})

	resolversPath := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte(server+"\n"), 0o644); err != nil {
		t.Fatalf("write resolvers: %v", err)
	}

	results, err := ResolveAll(context.Background(), []string{"WWW.Example.COM."}, Config{
		Binary:        "/missing/dnsx",
		Workers:       5,
		Timeout:       time.Second,
		ResolversFile: resolversPath,
	}, nil)
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%v; want one result", results)
	}
	if results[0].Subdomain != "WWW.Example.COM." {
		t.Fatalf("subdomain=%q; want original input", results[0].Subdomain)
	}
	if !results[0].Alive {
		t.Fatalf("result=%v; want alive", results[0])
	}
	if !slices.Equal(results[0].IPs, []string{"2001:db8::10", "203.0.113.10"}) {
		t.Fatalf("ips=%v; want answer A and AAAA records", results[0].IPs)
	}
}

func TestResolveAllReturnsUnresolvedResultForNXDomain(t *testing.T) {
	server := startResolverTestServer(t, func(req *dns.Msg) *dns.Msg {
		resp := dnsutil.SetReply(new(dns.Msg), req)
		resp.Rcode = dns.RcodeNameError
		return resp
	})

	resolversPath := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte(server+"\n"), 0o644); err != nil {
		t.Fatalf("write resolvers: %v", err)
	}

	results, err := ResolveAll(context.Background(), []string{"missing.example.com"}, Config{
		Workers:       1,
		Timeout:       time.Second,
		ResolversFile: resolversPath,
	}, nil)
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%v; want one result", results)
	}
	if results[0].Alive {
		t.Fatalf("result=%v; want unresolved", results[0])
	}
	if results[0].Error != "no A or AAAA records returned" {
		t.Fatalf("error=%q; want no-records message", results[0].Error)
	}
}

func TestParseResolverAddressesNormalizesAndDeduplicates(t *testing.T) {
	got := parseResolverAddresses(`
# comment
1.1.1.1
8.8.8.8:5353
1.1.1.1 ; duplicate
[2001:4860:4860::8888]:53
https://dns.example.test/query
bad-value
`)
	want := []string{
		"1.1.1.1:53",
		"8.8.8.8:5353",
		"[2001:4860:4860::8888]:53",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("resolvers=%v; want %v", got, want)
	}
}

func TestNormalizeIPsFiltersInvalidAndDeduplicates(t *testing.T) {
	got := normalizeIPs([]string{"203.0.113.10", "not-an-ip", "203.0.113.10", "2001:db8::10"})
	if !slices.Equal(got, []string{"2001:db8::10", "203.0.113.10"}) {
		t.Fatalf("ips=%v; want normalized unique IP literals", got)
	}
}

func startResolverTestServer(t *testing.T, handle func(*dns.Msg) *dns.Msg) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}

			req := new(dns.Msg)
			req.Data = append(req.Data[:0], buf[:n]...)
			if err := req.Unpack(); err != nil {
				continue
			}

			resp := handle(req)
			if err := resp.Pack(); err != nil {
				continue
			}
			_, _ = conn.WriteTo(resp.Data, addr)
		}
	}()

	return conn.LocalAddr().String()
}
