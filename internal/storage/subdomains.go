package storage

import (
	"database/sql"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"github.com/indigo-sadland/logy/internal/modules/resolver"
	"net"
	"slices"
	"strings"
	"time"
)

// SaveDiscoveries upserts discovered subdomains while preserving first-seen timestamps.
func (s *Store) SaveDiscoveries(domain string, entries []discovery.Entry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	stmt, err := tx.Prepare(`
INSERT INTO subdomains(domain, subdomain, sources, first_seen_at, last_seen_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?)
ON CONFLICT(domain, subdomain) DO UPDATE SET
    sources=excluded.sources,
    last_seen_at=excluded.last_seen_at,
    updated_at=excluded.updated_at
`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, entry := range entries {
		if _, err := stmt.Exec(domain, entry.Subdomain, strings.Join(entry.Sources, ","), now, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SaveResolutions records dns resolution outcomes without overwriting previously successful state with failures.
func (s *Store) SaveResolutions(domain string, results []resolver.Result) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	successStmt, err := tx.Prepare(`
UPDATE subdomains
SET resolved=1,
    ips=?,
    resolve_error='',
    last_resolved_at=?,
    updated_at=?
WHERE domain=? AND subdomain=?
`)
	if err != nil {
		return err
	}
	defer successStmt.Close()

	failureStmt, err := tx.Prepare(`
UPDATE subdomains
SET resolve_error=CASE WHEN resolved=1 THEN resolve_error ELSE ? END,
    updated_at=?
WHERE domain=? AND subdomain=?
`)
	if err != nil {
		return err
	}
	defer failureStmt.Close()

	for _, result := range results {
		if result.Alive {
			if _, err := successStmt.Exec(strings.Join(result.IPs, ","), now, now, domain, result.Subdomain); err != nil {
				return err
			}
			continue
		}
		if _, err := failureStmt.Exec(result.Error, now, domain, result.Subdomain); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CountByResolution returns the number of resolved and unresolved subdomains for a domain.
func (s *Store) CountByResolution(domain string) (resolved int, unresolved int, err error) {
	row := s.db.QueryRow(
		`SELECT
SUM(CASE WHEN resolved=1 THEN 1 ELSE 0 END),
SUM(CASE WHEN resolved=0 THEN 1 ELSE 0 END)
FROM subdomains WHERE domain=?`,
		domain,
	)
	var gotResolved, gotUnresolved sql.NullInt64
	if err = row.Scan(&gotResolved, &gotUnresolved); err != nil {
		return 0, 0, err
	}
	if gotResolved.Valid {
		resolved = int(gotResolved.Int64)
	}
	if gotUnresolved.Valid {
		unresolved = int(gotUnresolved.Int64)
	}
	return resolved, unresolved, nil
}

// DomainExists reports whether any subdomains have been stored for the domain.
func (s *Store) DomainExists(domain string) (bool, error) {
	row := s.db.QueryRow(`SELECT 1 FROM subdomains WHERE domain=? LIMIT 1`, domain)
	var value int
	if err := row.Scan(&value); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// SubdomainsByDomain loads full subdomain records for a domain in subdomain order.
func (s *Store) SubdomainsByDomain(domain string) ([]SubdomainRecord, error) {
	rows, err := s.db.Query(`
SELECT domain, subdomain, sources, resolved, ips, resolve_error, first_seen_at, last_seen_at, last_resolved_at, updated_at
FROM subdomains
WHERE domain=?
ORDER BY subdomain ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]SubdomainRecord, 0, 128)
	for rows.Next() {
		var record SubdomainRecord
		var sources string
		var ips string
		var resolved int
		var firstSeenAt string
		var lastSeenAt string
		var lastResolvedAt sql.NullString
		var updatedAt string
		if err := rows.Scan(
			&record.Domain,
			&record.Subdomain,
			&sources,
			&resolved,
			&ips,
			&record.ResolveError,
			&firstSeenAt,
			&lastSeenAt,
			&lastResolvedAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		record.Sources = splitCSV(sources)
		record.IPs = splitCSV(ips)
		record.Resolved = resolved == 1

		parsedFirstSeenAt, err := time.Parse(time.RFC3339, firstSeenAt)
		if err != nil {
			return nil, err
		}
		record.FirstSeenAt = parsedFirstSeenAt

		parsedLastSeenAt, err := time.Parse(time.RFC3339, lastSeenAt)
		if err != nil {
			return nil, err
		}
		record.LastSeenAt = parsedLastSeenAt

		if lastResolvedAt.Valid && strings.TrimSpace(lastResolvedAt.String) != "" {
			parsedLastResolvedAt, err := time.Parse(time.RFC3339, lastResolvedAt.String)
			if err != nil {
				return nil, err
			}
			record.LastResolvedAt = sql.NullTime{Time: parsedLastResolvedAt, Valid: true}
		}

		parsedUpdatedAt, err := time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			return nil, err
		}
		record.UpdatedAt = parsedUpdatedAt
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

// UnresolvedSubdomainsByDomain returns unresolved hostnames for follow-up resolution workflows.
func (s *Store) UnresolvedSubdomainsByDomain(domain string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT subdomain
FROM subdomains
WHERE domain=? AND resolved=0
ORDER BY subdomain ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0, 128)
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			return nil, err
		}
		out = append(out, subdomain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, sql.ErrNoRows
	}
	return out, nil
}

// AllSubdomainsByDomain returns every known subdomain for the requested domain.
func (s *Store) AllSubdomainsByDomain(domain string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT subdomain
FROM subdomains
WHERE domain=?
ORDER BY subdomain ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0, 128)
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			return nil, err
		}
		out = append(out, subdomain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, sql.ErrNoRows
	}
	return out, nil
}

// ResolvedSubdomainTargetsByDomain returns resolved hostname targets and their unique IPv4 addresses.
func (s *Store) ResolvedSubdomainTargetsByDomain(domain string) ([]ResolvedSubdomainTarget, error) {
	rows, err := s.db.Query(`
SELECT domain, subdomain, ips
FROM subdomains
WHERE domain=? AND resolved=1
ORDER BY subdomain ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := make([]ResolvedSubdomainTarget, 0, 128)
	for rows.Next() {
		var target ResolvedSubdomainTarget
		var ips string
		if err := rows.Scan(&target.Domain, &target.Subdomain, &ips); err != nil {
			return nil, err
		}
		target.IPs = uniqueIPv4Strings(splitCSV(ips))
		if len(target.IPs) == 0 {
			continue
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, sql.ErrNoRows
	}
	return targets, nil
}

// SavedScanTargetsByDomain returns hostname-backed and IP-only scan targets for a domain label.
func (s *Store) SavedScanTargetsByDomain(domain string) ([]SavedScanTarget, error) {
	resolvedTargets, err := s.ResolvedSubdomainTargetsByDomain(domain)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	seenIPs := make(map[string]struct{}, 128)
	targets := make([]SavedScanTarget, 0, len(resolvedTargets))
	if err == nil {
		for _, target := range resolvedTargets {
			targets = append(targets, SavedScanTarget{
				Domain: domain,
				Label:  target.Subdomain,
				Kind:   savedScanTargetKind(target.Subdomain),
				IPs:    target.IPs,
			})
			for _, ip := range target.IPs {
				seenIPs[ip] = struct{}{}
			}
		}
	}

	scannedIPs, err := s.ScannedIPsByDomain(domain)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == nil {
		for _, ip := range scannedIPs {
			if _, ok := seenIPs[ip]; ok {
				continue
			}
			targets = append(targets, SavedScanTarget{
				Domain: domain,
				Label:  ip,
				Kind:   "ip",
				IPs:    []string{ip},
			})
		}
	}

	if len(targets) == 0 {
		return nil, sql.ErrNoRows
	}
	return targets, nil
}

func savedScanTargetKind(label string) string {
	if net.ParseIP(strings.TrimSpace(label)) != nil {
		return "ip"
	}
	return "hostname"
}

// ResolvedIPsByDomain returns the unique set of IPs seen on resolved subdomains for a domain.
func (s *Store) ResolvedIPsByDomain(domain string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT ips
FROM subdomains
WHERE domain=? AND resolved=1
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := make(map[string]struct{}, 128)
	out := make([]string, 0, 128)
	for rows.Next() {
		var ips string
		if err := rows.Scan(&ips); err != nil {
			return nil, err
		}
		for _, ip := range splitCSV(ips) {
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, sql.ErrNoRows
	}
	slices.Sort(out)
	return out, nil
}

// SaveVHostResolutions marks unresolved subdomains as resolved when vhost detection succeeds.
func (s *Store) SaveVHostResolutions(domain string, results []resolver.Result) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	stmt, err := tx.Prepare(`
UPDATE subdomains
SET resolved=1,
    ips=CASE WHEN ? <> '' THEN ? ELSE ips END,
    resolve_error='',
    last_seen_at=?,
    last_resolved_at=?,
    updated_at=?
WHERE domain=? AND subdomain=?
`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, result := range results {
		if !result.Alive {
			continue
		}
		ipsCSV := strings.Join(result.IPs, ",")
		if _, err := stmt.Exec(ipsCSV, ipsCSV, now, now, now, domain, result.Subdomain); err != nil {
			return err
		}
	}
	return tx.Commit()
}
