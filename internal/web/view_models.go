package web

import (
	"github.com/indigo-sadland/logy/internal/storage"
	"slices"
	"strings"
)

const webTimeRFC3339 = "2006-01-02T15:04:05Z07:00"

type hostView struct {
	IP            string              `json:"ip"`
	Subdomains    []string            `json:"subdomains"`
	Ports         []hostPortView      `json:"ports"`
	Probes        []hostProbeView     `json:"probes"`
	Candidates    []candidateLinkView `json:"candidates"`
	OpenPortCount int                 `json:"open_port_count"`
	WebCount      int                 `json:"web_count"`
}

type hostAggregate struct {
	ip         string
	subdomains []string
	ports      []hostPortView
	probes     []hostProbeView
	candidates []candidateLinkView
}

type hostPortView struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	State     string `json:"state"`
	Service   string `json:"service,omitempty"`
	Version   string `json:"version,omitempty"`
	ScannedAt string `json:"scanned_at"`
}

type hostProbeView struct {
	Target       string   `json:"target"`
	URL          string   `json:"url"`
	FinalURL     string   `json:"final_url,omitempty"`
	Scheme       string   `json:"scheme"`
	Port         int      `json:"port"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	ProbedAt     string   `json:"probed_at"`
}

type candidateLinkView struct {
	Subdomain string   `json:"subdomain"`
	Sources   []string `json:"sources"`
}

type findingView struct {
	ID               int64               `json:"ID"`
	Domain           string              `json:"Domain"`
	Title            string              `json:"Title"`
	Severity         string              `json:"Severity"`
	Status           string              `json:"Status"`
	DescriptionHTML  string              `json:"DescriptionHTML"`
	LinkedSubdomains []string            `json:"LinkedSubdomains"`
	LinkedHosts      []string            `json:"LinkedHosts"`
	AffectedService  *findingServiceView `json:"AffectedService,omitempty"`
	CreatedAt        string              `json:"CreatedAt"`
	UpdatedAt        string              `json:"UpdatedAt"`
}

type findingServiceView struct {
	Hostname string `json:"hostname,omitempty"`
	HostIP   string `json:"host_ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
}

func buildHostViews(subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord, probes []storage.WebProbeRecord, candidates []storage.PermutationCandidateRecord) []hostView {
	hostByIP := make(map[string]*hostAggregate, len(scans))
	subdomainsByIP := make(map[string][]string, len(subdomains))
	ipsBySubdomain := make(map[string][]string, len(subdomains))

	for _, record := range subdomains {
		if !record.Resolved {
			continue
		}
		for _, ip := range record.IPs {
			if strings.TrimSpace(ip) == "" {
				continue
			}
			subdomainsByIP[ip] = append(subdomainsByIP[ip], record.Subdomain)
			ipsBySubdomain[record.Subdomain] = append(ipsBySubdomain[record.Subdomain], ip)
		}
	}

	for ip, hosts := range subdomainsByIP {
		slices.Sort(hosts)
		subdomainsByIP[ip] = uniqueStrings(hosts)
	}
	for host, ips := range ipsBySubdomain {
		slices.Sort(ips)
		ipsBySubdomain[host] = uniqueStrings(ips)
	}

	ensureHost := func(ip string) *hostAggregate {
		if existing, ok := hostByIP[ip]; ok {
			return existing
		}
		agg := &hostAggregate{
			ip:         ip,
			subdomains: slices.Clone(subdomainsByIP[ip]),
			ports:      make([]hostPortView, 0, 8),
			probes:     make([]hostProbeView, 0, 8),
			candidates: make([]candidateLinkView, 0, 8),
		}
		hostByIP[ip] = agg
		return agg
	}

	for _, scan := range scans {
		agg := ensureHost(scan.IP)
		agg.ports = append(agg.ports, hostPortView{
			Port:      scan.Port,
			Protocol:  scan.Protocol,
			State:     scan.State,
			Service:   scan.Service,
			Version:   scan.Version,
			ScannedAt: scan.ScannedAt.Format(webTimeRFC3339),
		})
	}

	for ip := range subdomainsByIP {
		ensureHost(ip)
	}

	for _, probe := range probes {
		for _, ip := range ipsBySubdomain[probe.Target] {
			agg := ensureHost(ip)
			agg.probes = append(agg.probes, hostProbeView{
				Target:       probe.Target,
				URL:          probe.URL,
				FinalURL:     probe.FinalURL,
				Scheme:       probe.Scheme,
				Port:         probe.Port,
				StatusCode:   probe.StatusCode,
				Title:        probe.Title,
				Technologies: slices.Clone(probe.Technologies),
				ProbedAt:     probe.ProbedAt.Format(webTimeRFC3339),
			})
		}
	}

	for _, candidate := range candidates {
		for _, agg := range hostByIP {
			if candidateRelatedToHost(candidate.Subdomain, agg.subdomains) {
				agg.candidates = append(agg.candidates, candidateLinkView{
					Subdomain: candidate.Subdomain,
					Sources:   slices.Clone(candidate.Sources),
				})
			}
		}
	}

	ips := make([]string, 0, len(hostByIP))
	for ip := range hostByIP {
		ips = append(ips, ip)
	}
	slices.Sort(ips)

	out := make([]hostView, 0, len(ips))
	for _, ip := range ips {
		agg := hostByIP[ip]
		sortHostViews(agg)
		out = append(out, hostView{
			IP:            agg.ip,
			Subdomains:    agg.subdomains,
			Ports:         agg.ports,
			Probes:        agg.probes,
			Candidates:    agg.candidates,
			OpenPortCount: len(agg.ports),
			WebCount:      len(agg.probes),
		})
	}
	return out
}

func buildFindingViews(findings []storage.FindingRecord, subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord) []findingView {
	ipsBySubdomain := make(map[string][]string, len(subdomains))
	for _, record := range subdomains {
		if !record.Resolved {
			continue
		}
		for _, ip := range record.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			ipsBySubdomain[record.Subdomain] = append(ipsBySubdomain[record.Subdomain], ip)
		}
	}
	for host, ips := range ipsBySubdomain {
		slices.Sort(ips)
		ipsBySubdomain[host] = uniqueStrings(ips)
	}

	portsByIP := make(map[string][]storage.PortScanRecord, len(scans))
	for _, scan := range scans {
		if strings.TrimSpace(scan.IP) == "" {
			continue
		}
		portsByIP[scan.IP] = append(portsByIP[scan.IP], scan)
	}
	for ip, ports := range portsByIP {
		slices.SortFunc(ports, func(a, b storage.PortScanRecord) int {
			if a.Port != b.Port {
				return a.Port - b.Port
			}
			if cmp := strings.Compare(a.Protocol, b.Protocol); cmp != 0 {
				return cmp
			}
			return strings.Compare(a.Service, b.Service)
		})
		portsByIP[ip] = ports
	}

	out := make([]findingView, 0, len(findings))
	for _, finding := range findings {
		out = append(out, findingView{
			ID:               finding.ID,
			Domain:           finding.Domain,
			Title:            finding.Title,
			Severity:         finding.Severity,
			Status:           finding.Status,
			DescriptionHTML:  finding.DescriptionHTML,
			LinkedSubdomains: slices.Clone(finding.LinkedSubdomains),
			LinkedHosts:      slices.Clone(finding.LinkedHosts),
			AffectedService:  findingServiceViewForRecord(finding, ipsBySubdomain, portsByIP),
			CreatedAt:        finding.CreatedAt.Format(webTimeRFC3339),
			UpdatedAt:        finding.UpdatedAt.Format(webTimeRFC3339),
		})
	}
	return out
}

func findingServiceViewForRecord(finding storage.FindingRecord, ipsBySubdomain map[string][]string, portsByIP map[string][]storage.PortScanRecord) *findingServiceView {
	if finding.AffectedService != nil {
		return &findingServiceView{
			Hostname: finding.AffectedService.Hostname,
			HostIP:   finding.AffectedService.HostIP,
			Port:     finding.AffectedService.Port,
			Protocol: finding.AffectedService.Protocol,
			Service:  finding.AffectedService.Service,
		}
	}
	return inferFindingService(finding, ipsBySubdomain, portsByIP)
}

func inferFindingService(finding storage.FindingRecord, ipsBySubdomain map[string][]string, portsByIP map[string][]storage.PortScanRecord) *findingServiceView {
	candidateIPs := make([]string, 0, len(finding.LinkedHosts)+len(finding.LinkedSubdomains))
	for _, ip := range finding.LinkedHosts {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			candidateIPs = append(candidateIPs, ip)
		}
	}
	for _, subdomain := range finding.LinkedSubdomains {
		candidateIPs = append(candidateIPs, ipsBySubdomain[subdomain]...)
	}
	candidateIPs = uniqueSortedStrings(candidateIPs)

	for _, ip := range candidateIPs {
		ports := portsByIP[ip]
		if len(ports) == 0 {
			continue
		}
		port := ports[0]
		return &findingServiceView{
			Hostname: linkedHostnameForIP(ip, finding.LinkedSubdomains, ipsBySubdomain),
			HostIP:   port.IP,
			Port:     port.Port,
			Protocol: port.Protocol,
			Service:  port.Service,
		}
	}
	return nil
}

func linkedHostnameForIP(ip string, linkedSubdomains []string, ipsBySubdomain map[string][]string) string {
	for _, subdomain := range linkedSubdomains {
		for _, linkedIP := range ipsBySubdomain[subdomain] {
			if linkedIP == ip {
				return subdomain
			}
		}
	}
	return ""
}

func sortHostViews(agg *hostAggregate) {
	slices.SortFunc(agg.ports, func(a, b hostPortView) int {
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})
	slices.SortFunc(agg.probes, func(a, b hostProbeView) int {
		if cmp := strings.Compare(a.Target, b.Target); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.URL, b.URL); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ProbedAt, b.ProbedAt)
	})
	slices.SortFunc(agg.candidates, func(a, b candidateLinkView) int {
		return strings.Compare(a.Subdomain, b.Subdomain)
	})
	agg.candidates = uniqueCandidateLinks(agg.candidates)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueSortedStrings(values []string) []string {
	values = uniqueStrings(values)
	slices.Sort(values)
	return values
}

func uniqueCandidateLinks(values []candidateLinkView) []candidateLinkView {
	seen := make(map[string]struct{}, len(values))
	out := make([]candidateLinkView, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value.Subdomain]; ok {
			continue
		}
		seen[value.Subdomain] = struct{}{}
		out = append(out, value)
	}
	return out
}

func candidateRelatedToHost(candidate string, hosts []string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if candidate == "" {
		return false
	}
	candidateLabels := strings.Split(candidate, ".")
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if strings.Contains(candidate, host) || strings.Contains(host, candidate) {
			return true
		}
		hostLabels := strings.Split(host, ".")
		if len(hostLabels) == 0 || len(candidateLabels) == 0 {
			continue
		}
		if hostLabels[0] == candidateLabels[0] {
			return true
		}
		if sharedHostToken(hostLabels[0], candidateLabels[0]) {
			return true
		}
	}
	return false
}

func sharedHostToken(a string, b string) bool {
	aParts := strings.FieldsFunc(a, func(r rune) bool { return r == '-' || r == '_' })
	bParts := strings.FieldsFunc(b, func(r rune) bool { return r == '-' || r == '_' })
	for _, left := range aParts {
		for _, right := range bParts {
			if left != "" && left == right {
				return true
			}
		}
	}
	return false
}
