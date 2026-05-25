package storage

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SaveWebProbes appends probe history rows for the given domain.
func (s *Store) SaveWebProbes(domain string, results []WebProbeRecord) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
INSERT INTO web_probes(domain, target, url, final_url, scheme, port, status_code, title, technologies, probed_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, result := range results {
		if _, err := stmt.Exec(
			domain,
			result.Target,
			result.URL,
			result.FinalURL,
			result.Scheme,
			result.Port,
			result.StatusCode,
			result.Title,
			strings.Join(result.Technologies, ","),
			result.ProbedAt.UTC().Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WebProbesByDomain returns saved web probe history for a domain, newest first.
func (s *Store) WebProbesByDomain(domain string) ([]WebProbeRecord, error) {
	rows, err := s.db.Query(`
SELECT domain, target, url, final_url, scheme, port, status_code, title, technologies, probed_at
FROM web_probes
WHERE domain=?
ORDER BY probed_at DESC, target ASC, url ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]WebProbeRecord, 0, 128)
	for rows.Next() {
		var record WebProbeRecord
		var technologies string
		var probedAt string
		if err := rows.Scan(
			&record.Domain,
			&record.Target,
			&record.URL,
			&record.FinalURL,
			&record.Scheme,
			&record.Port,
			&record.StatusCode,
			&record.Title,
			&technologies,
			&probedAt,
		); err != nil {
			return nil, err
		}

		parsedProbedAt, err := time.Parse(time.RFC3339, probedAt)
		if err != nil {
			return nil, err
		}
		record.Technologies = splitCSV(technologies)
		record.ProbedAt = parsedProbedAt
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, sql.ErrNoRows
	}
	return records, nil
}

// WebProbeTargetsByDomain returns hostname-based probe URLs inferred from resolved subdomains and HTTP/S-like port scan results.
func (s *Store) WebProbeTargetsByDomain(domain string) ([]WebProbeTarget, error) {
	subdomains, err := s.SubdomainsByDomain(domain)
	if err != nil {
		return nil, err
	}
	scans, err := s.PortScansByDomain(domain)
	if err != nil {
		return nil, err
	}

	portsByIP := make(map[string][]portScheme, len(scans))
	for _, scan := range scans {
		scheme, ok := inferWebScheme(scan)
		if !ok {
			continue
		}
		portsByIP[scan.IP] = append(portsByIP[scan.IP], portScheme{Scheme: scheme, Port: scan.Port})
	}

	seen := make(map[string]struct{}, 128)
	targets := make([]WebProbeTarget, 0, 128)
	for _, subdomain := range subdomains {
		if !subdomain.Resolved {
			continue
		}
		for _, ip := range subdomain.IPs {
			for _, candidate := range portsByIP[ip] {
				target := WebProbeTarget{
					Subdomain: subdomain.Subdomain,
					Scheme:    candidate.Scheme,
					Port:      candidate.Port,
					URL:       buildProbeURL(subdomain.Subdomain, candidate.Scheme, candidate.Port),
				}
				if _, ok := seen[target.URL]; ok {
					continue
				}
				seen[target.URL] = struct{}{}
				targets = append(targets, target)
			}
		}
	}

	if len(targets) == 0 {
		return nil, sql.ErrNoRows
	}

	slices.SortFunc(targets, func(a, b WebProbeTarget) int {
		if cmp := strings.Compare(a.Subdomain, b.Subdomain); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.Scheme, b.Scheme); cmp != 0 {
			return cmp
		}
		return a.Port - b.Port
	})
	return targets, nil
}

type portScheme struct {
	Scheme string
	Port   int
}

func inferWebScheme(scan PortScanRecord) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(scan.Protocol), "tcp") {
		return "", false
	}

	service := strings.ToLower(strings.TrimSpace(scan.Service))
	switch {
	case strings.Contains(service, "https"):
		return "https", true
	case strings.Contains(service, "ssl") && strings.Contains(service, "http"):
		return "https", true
	case strings.Contains(service, "http"):
		return "http", true
	}

	if _, ok := knownHTTPSPorts[scan.Port]; ok {
		return "https", true
	}
	if _, ok := knownHTTPPorts[scan.Port]; ok {
		return "http", true
	}
	return "", false
}

func buildProbeURL(host, scheme string, port int) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

var knownHTTPPorts = map[int]struct{}{
	80:   {},
	81:   {},
	280:  {},
	591:  {},
	593:  {},
	8000: {},
	8008: {},
	8080: {},
	8081: {},
	8088: {},
	8888: {},
	9000: {},
}

var knownHTTPSPorts = map[int]struct{}{
	443:   {},
	832:   {},
	981:   {},
	1311:  {},
	7002:  {},
	7443:  {},
	8333:  {},
	8443:  {},
	8834:  {},
	9443:  {},
	10443: {},
}
