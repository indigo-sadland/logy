package web

import (
	"github.com/indigo-sadland/logy/internal/storage"
	"testing"
	"time"
)

func TestBuildFindingViewsInfersServiceFromLinkedSubdomain(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	findings := []storage.FindingRecord{
		{
			ID:               1,
			Domain:           "example.com",
			Title:            "Exposed admin panel",
			Severity:         "high",
			Status:           "open",
			LinkedSubdomains: []string{"admin.example.com"},
			CreatedAt:        now,
			UpdatedAt:        now,
		},
	}
	subdomains := []storage.SubdomainRecord{
		{
			Domain:    "example.com",
			Subdomain: "admin.example.com",
			Resolved:  true,
			IPs:       []string{"10.0.0.5"},
		},
	}
	scans := []storage.PortScanRecord{
		{
			Domain:   "example.com",
			IP:       "10.0.0.5",
			Port:     8443,
			Protocol: "tcp",
			State:    "open",
			Service:  "https",
		},
	}

	got := buildFindingViews(findings, subdomains, scans)
	if len(got) != 1 {
		t.Fatalf("len(got)=%d; want 1", len(got))
	}
	if got[0].AffectedService == nil {
		t.Fatal("expected affected service to be inferred")
	}
	service := got[0].AffectedService
	if service.Hostname != "admin.example.com" || service.HostIP != "10.0.0.5" || service.Port != 8443 || service.Service != "https" {
		t.Fatalf("service=%+v; want 10.0.0.5:8443 https", service)
	}
}

func TestBuildFindingViewsPrefersLinkedHostService(t *testing.T) {
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	findings := []storage.FindingRecord{
		{
			ID:          1,
			Domain:      "example.com",
			Title:       "Open management port",
			Severity:    "medium",
			Status:      "verified",
			LinkedHosts: []string{"10.0.0.9"},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	scans := []storage.PortScanRecord{
		{Domain: "example.com", IP: "10.0.0.9", Port: 22, Protocol: "tcp", State: "open", Service: "ssh"},
		{Domain: "example.com", IP: "10.0.0.9", Port: 443, Protocol: "tcp", State: "open", Service: "https"},
	}

	got := buildFindingViews(findings, nil, scans)
	if got[0].AffectedService == nil {
		t.Fatal("expected affected service to be inferred")
	}
	service := got[0].AffectedService
	if service.HostIP != "10.0.0.9" || service.Port != 22 || service.Service != "ssh" {
		t.Fatalf("service=%+v; want first sorted linked-host service 10.0.0.9:22 ssh", service)
	}
}
