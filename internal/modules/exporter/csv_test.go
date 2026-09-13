package exporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/indigo-sadland/logy/internal/storage"
)

func TestBuildCSVExportRowsIncludesResolvedIPsWithoutPorts(t *testing.T) {
	rows := buildCSVExportRows([]storage.SubdomainRecord{
		{
			Domain:    "example.com",
			Subdomain: "api.example.com",
			Resolved:  true,
			IPs:       []string{"203.0.113.10", "203.0.113.11"},
		},
		{
			Domain:    "example.com",
			Subdomain: "old.example.com",
			Resolved:  false,
			IPs:       []string{"203.0.113.12"},
		},
	}, nil)

	if len(rows) != 2 {
		t.Fatalf("rows=%v; want one row per resolved IP", rows)
	}
	if rows[0].IPs != "203.0.113.10" || rows[1].IPs != "203.0.113.11" {
		t.Fatalf("IPs=%q, %q; want sorted IP rows", rows[0].IPs, rows[1].IPs)
	}
	if rows[0].Domain != "api.example.com" {
		t.Fatalf("domain=%q; want api.example.com", rows[0].Domain)
	}
	if rows[0].TCPPorts != "" || rows[1].TCPPorts != "" {
		t.Fatalf("TCPPorts=%q, %q; want empty ports columns", rows[0].TCPPorts, rows[1].TCPPorts)
	}
}

func TestBuildCSVExportRowsGroupsDomainsAndPortsByIP(t *testing.T) {
	rows := buildCSVExportRows([]storage.SubdomainRecord{
		{
			Domain:    "example.com",
			Subdomain: "app.example.com",
			Resolved:  true,
			IPs:       []string{"10.10.10.10"},
		},
		{
			Domain:    "example.com",
			Subdomain: "www.example.com",
			Resolved:  true,
			IPs:       []string{"10.10.10.10"},
		},
	}, []storage.PortScanRecord{
		{
			Domain:   "example.com",
			IP:       "10.10.10.10",
			Port:     443,
			Protocol: "tcp",
			State:    "open",
			Service:  "https",
			Version:  "nginx",
		},
		{
			Domain:   "example.com",
			IP:       "10.10.10.10",
			Port:     80,
			Protocol: "tcp",
			State:    "open",
			Service:  "http",
			Version:  "Microsoft IIS httpd 7.5",
		},
		{
			Domain:   "example.com",
			IP:       "10.10.10.10",
			Port:     53,
			Protocol: "udp",
			State:    "open",
			Service:  "domain",
		},
	})

	if len(rows) != 1 {
		t.Fatalf("rows=%v; want one row", rows)
	}
	expectedDomains := strings.Join([]string{
		"app.example.com",
		"www.example.com",
	}, "\n")
	if rows[0].Domain != expectedDomains {
		t.Fatalf("domain=%q; want all domains associated with the IP", rows[0].Domain)
	}
	expectedPorts := strings.Join([]string{
		"80/tcp    open  http               Microsoft IIS httpd 7.5",
		"443/tcp   open  https              nginx",
	}, "\n")
	if rows[0].TCPPorts != expectedPorts {
		t.Fatalf("TCPPorts=%q; want %q", rows[0].TCPPorts, expectedPorts)
	}
}

func TestExportCSVUsesSemicolonAndQuotesMultilineFields(t *testing.T) {
	var buf bytes.Buffer
	rows, err := ExportCSV(&buf, []storage.SubdomainRecord{
		{
			Domain:    "myapp.com",
			Subdomain: "app.myapp.com",
			Resolved:  true,
			IPs:       []string{"10.10.10.10"},
		},
		{
			Domain:    "myapp.com",
			Subdomain: "www.myapp.com",
			Resolved:  true,
			IPs:       []string{"10.10.10.10"},
		},
	}, []storage.PortScanRecord{
		{
			Domain:   "myapp.com",
			IP:       "10.10.10.10",
			Port:     21,
			Protocol: "tcp",
			State:    "open",
			Service:  "ftp",
			Version:  "FileZilla ftpd 0.9.41 beta",
		},
		{
			Domain:   "myapp.com",
			IP:       "10.10.10.10",
			Port:     80,
			Protocol: "tcp",
			State:    "open",
			Service:  "http",
			Version:  "Microsoft IIS httpd 7.5",
		},
	})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d; want 1", rows)
	}

	expected := strings.Join([]string{
		"IP;DOMAIN;TCP PORTS",
		"10.10.10.10;\"app.myapp.com",
		"www.myapp.com\";\"21/tcp    open  ftp                FileZilla ftpd 0.9.41 beta",
		"80/tcp    open  http               Microsoft IIS httpd 7.5\"",
		"",
	}, "\n")
	if buf.String() != expected {
		t.Fatalf("csv=%q; want %q", buf.String(), expected)
	}
}
