package storage

import (
	"database/sql"
	"github.com/indigo-sadland/logy/internal/modules/discovery"
	"strings"
	"time"
)

// SavePermutationCandidates upserts speculative permutation-derived hostnames without promoting them to confirmed subdomains.
func (s *Store) SavePermutationCandidates(domain string, entries []discovery.Entry) error {
	if len(entries) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	stmt, err := tx.Prepare(`
INSERT INTO permutation_candidates(domain, subdomain, sources, first_seen_at, last_seen_at, updated_at)
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

// PermutationCandidatesByDomain returns unresolved permutation candidates for the requested domain.
func (s *Store) PermutationCandidatesByDomain(domain string) ([]PermutationCandidateRecord, error) {
	rows, err := s.db.Query(`
SELECT domain, subdomain, sources, first_seen_at, last_seen_at, updated_at
FROM permutation_candidates
WHERE domain=?
ORDER BY subdomain ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]PermutationCandidateRecord, 0, 128)
	for rows.Next() {
		var record PermutationCandidateRecord
		var sources string
		var firstSeenAt string
		var lastSeenAt string
		var updatedAt string
		if err := rows.Scan(
			&record.Domain,
			&record.Subdomain,
			&sources,
			&firstSeenAt,
			&lastSeenAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		record.Sources = splitCSV(sources)

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

// DeletePermutationCandidates removes candidate rows after they have been confirmed through DNS or vhost resolution.
func (s *Store) DeletePermutationCandidates(domain string, hosts []string) error {
	hosts = uniqueSortedStrings(hosts)
	if len(hosts) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`DELETE FROM permutation_candidates WHERE domain=? AND subdomain=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, host := range hosts {
		if _, err := stmt.Exec(domain, host); err != nil {
			return err
		}
	}
	return tx.Commit()
}
