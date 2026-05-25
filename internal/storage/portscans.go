package storage

import (
	"database/sql"
	"time"
)

// SavePortScans upserts open-port scan results keyed by domain, IP, port, and protocol.
func (s *Store) SavePortScans(domain string, results []PortScanRecord) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
INSERT INTO port_scans(domain, ip, port, protocol, state, service, version, scanned_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(domain, ip, port, protocol) DO UPDATE SET
    state=excluded.state,
    service=excluded.service,
    version=excluded.version,
    scanned_at=excluded.scanned_at
`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, result := range results {
		if _, err := stmt.Exec(
			domain,
			result.IP,
			result.Port,
			result.Protocol,
			result.State,
			result.Service,
			result.Version,
			result.ScannedAt.UTC().Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PortScansByDomain returns stored open-port scan results for a domain ordered by IP and port.
func (s *Store) PortScansByDomain(domain string) ([]PortScanRecord, error) {
	rows, err := s.db.Query(`
SELECT domain, ip, port, protocol, state, service, version, scanned_at
FROM port_scans
WHERE domain=?
ORDER BY ip ASC, port ASC, protocol ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]PortScanRecord, 0, 128)
	for rows.Next() {
		var record PortScanRecord
		var scannedAt string
		if err := rows.Scan(
			&record.Domain,
			&record.IP,
			&record.Port,
			&record.Protocol,
			&record.State,
			&record.Service,
			&record.Version,
			&scannedAt,
		); err != nil {
			return nil, err
		}
		parsedScannedAt, err := time.Parse(time.RFC3339, scannedAt)
		if err != nil {
			return nil, err
		}
		record.ScannedAt = parsedScannedAt
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

// ScannedIPsByDomain returns unique IPv4 addresses seen in saved port scan results.
func (s *Store) ScannedIPsByDomain(domain string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT DISTINCT ip
FROM port_scans
WHERE domain=?
ORDER BY ip ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ips := make([]string, 0, 128)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ips = uniqueIPv4Strings(ips)
	if len(ips) == 0 {
		return nil, sql.ErrNoRows
	}
	return ips, nil
}
