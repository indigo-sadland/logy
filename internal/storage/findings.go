package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

var validFindingSeverities = map[string]struct{}{
	"critical": {},
	"high":     {},
	"medium":   {},
	"low":      {},
	"info":     {},
}

var validFindingStatuses = map[string]struct{}{
	"open":           {},
	"verified":       {},
	"fixed":          {},
	"false_positive": {},
}

type FindingInput struct {
	Domain           string
	Title            string
	Severity         string
	Status           string
	DescriptionHTML  string
	LinkedSubdomains []string
	LinkedHosts      []string
	AffectedService  *FindingServiceInput
}

type FindingServiceInput struct {
	Hostname string
	HostIP   string
	Port     int
	Protocol string
	Service  string
}

// CreateFinding inserts a finding and its links.
func (s *Store) CreateFinding(input FindingInput) (FindingRecord, error) {
	input = normalizeFindingInput(input)
	if err := validateFindingInput(input); err != nil {
		return FindingRecord{}, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return FindingRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	result, err := tx.Exec(`
INSERT INTO findings(domain, title, severity, status, description_html, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?)
`, input.Domain, input.Title, input.Severity, input.Status, input.DescriptionHTML, now, now)
	if err != nil {
		return FindingRecord{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return FindingRecord{}, err
	}

	if err := saveFindingLinksTx(tx, id, input.LinkedSubdomains, input.LinkedHosts); err != nil {
		return FindingRecord{}, err
	}
	if err := saveFindingServiceTx(tx, id, input.AffectedService); err != nil {
		return FindingRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return FindingRecord{}, err
	}
	return s.FindingByID(id)
}

// UpdateFinding updates a finding and replaces its links.
func (s *Store) UpdateFinding(id int64, input FindingInput) (FindingRecord, error) {
	input = normalizeFindingInput(input)
	if err := validateFindingInput(input); err != nil {
		return FindingRecord{}, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return FindingRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
	result, err := tx.Exec(`
UPDATE findings
SET domain=?, title=?, severity=?, status=?, description_html=?, updated_at=?
WHERE id=?
`, input.Domain, input.Title, input.Severity, input.Status, input.DescriptionHTML, now, id)
	if err != nil {
		return FindingRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return FindingRecord{}, err
	}
	if affected == 0 {
		return FindingRecord{}, sql.ErrNoRows
	}

	if _, err := tx.Exec(`DELETE FROM finding_subdomains WHERE finding_id=?`, id); err != nil {
		return FindingRecord{}, err
	}
	if _, err := tx.Exec(`DELETE FROM finding_hosts WHERE finding_id=?`, id); err != nil {
		return FindingRecord{}, err
	}
	if _, err := tx.Exec(`DELETE FROM finding_services WHERE finding_id=?`, id); err != nil {
		return FindingRecord{}, err
	}
	if err := saveFindingLinksTx(tx, id, input.LinkedSubdomains, input.LinkedHosts); err != nil {
		return FindingRecord{}, err
	}
	if err := saveFindingServiceTx(tx, id, input.AffectedService); err != nil {
		return FindingRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return FindingRecord{}, err
	}
	return s.FindingByID(id)
}

// DeleteFinding removes a finding and its links.
func (s *Store) DeleteFinding(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM finding_subdomains WHERE finding_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM finding_hosts WHERE finding_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM finding_services WHERE finding_id=?`, id); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM findings WHERE id=?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// FindingsByDomain returns findings with linked subdomains and hosts.
func (s *Store) FindingsByDomain(domain string) ([]FindingRecord, error) {
	rows, err := s.db.Query(`
SELECT id, domain, title, severity, status, description_html, created_at, updated_at
FROM findings
WHERE domain=?
ORDER BY updated_at DESC, id DESC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]FindingRecord, 0, 64)
	for rows.Next() {
		record, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, sql.ErrNoRows
	}
	if err := s.attachFindingLinks(records); err != nil {
		return nil, err
	}
	return records, nil
}

// FindingByID returns a single finding with links.
func (s *Store) FindingByID(id int64) (FindingRecord, error) {
	row := s.db.QueryRow(`
SELECT id, domain, title, severity, status, description_html, created_at, updated_at
FROM findings
WHERE id=?
`, id)
	record, err := scanFinding(row)
	if err != nil {
		return FindingRecord{}, err
	}
	records := []FindingRecord{record}
	if err := s.attachFindingLinks(records); err != nil {
		return FindingRecord{}, err
	}
	return records[0], nil
}

type findingScanner interface{ Scan(dest ...any) error }

func scanFinding(scanner findingScanner) (FindingRecord, error) {
	var record FindingRecord
	var createdAt string
	var updatedAt string
	if err := scanner.Scan(
		&record.ID,
		&record.Domain,
		&record.Title,
		&record.Severity,
		&record.Status,
		&record.DescriptionHTML,
		&createdAt,
		&updatedAt,
	); err != nil {
		return FindingRecord{}, err
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return FindingRecord{}, err
	}
	parsedUpdatedAt, err := time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return FindingRecord{}, err
	}
	record.CreatedAt = parsedCreatedAt
	record.UpdatedAt = parsedUpdatedAt
	return record, nil
}

func (s *Store) attachFindingLinks(records []FindingRecord) error {
	if len(records) == 0 {
		return nil
	}
	byID := make(map[int64]*FindingRecord, len(records))
	for i := range records {
		byID[records[i].ID] = &records[i]
	}

	subRows, err := s.db.Query(`SELECT finding_id, subdomain FROM finding_subdomains ORDER BY subdomain ASC`)
	if err != nil {
		return err
	}
	defer subRows.Close()
	for subRows.Next() {
		var id int64
		var subdomain string
		if err := subRows.Scan(&id, &subdomain); err != nil {
			return err
		}
		record := byID[id]
		if record == nil {
			continue
		}
		record.LinkedSubdomains = append(record.LinkedSubdomains, subdomain)
	}
	if err := subRows.Err(); err != nil {
		return err
	}

	hostRows, err := s.db.Query(`SELECT finding_id, host_ip FROM finding_hosts ORDER BY host_ip ASC`)
	if err != nil {
		return err
	}
	defer hostRows.Close()
	for hostRows.Next() {
		var id int64
		var host string
		if err := hostRows.Scan(&id, &host); err != nil {
			return err
		}
		record := byID[id]
		if record == nil {
			continue
		}
		record.LinkedHosts = append(record.LinkedHosts, host)
	}
	if err := hostRows.Err(); err != nil {
		return err
	}

	serviceRows, err := s.db.Query(`SELECT finding_id, hostname, host_ip, port, protocol, service FROM finding_services`)
	if err != nil {
		return err
	}
	defer serviceRows.Close()
	for serviceRows.Next() {
		var id int64
		var service FindingServiceRecord
		if err := serviceRows.Scan(
			&id,
			&service.Hostname,
			&service.HostIP,
			&service.Port,
			&service.Protocol,
			&service.Service,
		); err != nil {
			return err
		}
		record := byID[id]
		if record == nil {
			continue
		}
		record.AffectedService = &service
	}
	return serviceRows.Err()
}

func saveFindingLinksTx(tx *sql.Tx, id int64, subdomains []string, hosts []string) error {
	subStmt, err := tx.Prepare(`INSERT INTO finding_subdomains(finding_id, subdomain) VALUES(?, ?)`)
	if err != nil {
		return err
	}
	defer subStmt.Close()

	hostStmt, err := tx.Prepare(`INSERT INTO finding_hosts(finding_id, host_ip) VALUES(?, ?)`)
	if err != nil {
		return err
	}
	defer hostStmt.Close()

	for _, subdomain := range uniqueSortedStrings(subdomains) {
		if _, err := subStmt.Exec(id, subdomain); err != nil {
			return err
		}
	}
	for _, host := range uniqueSortedStrings(hosts) {
		if _, err := hostStmt.Exec(id, host); err != nil {
			return err
		}
	}
	return nil
}

func saveFindingServiceTx(tx *sql.Tx, id int64, service *FindingServiceInput) error {
	if service == nil {
		return nil
	}
	_, err := tx.Exec(`
INSERT INTO finding_services(finding_id, hostname, host_ip, port, protocol, service)
VALUES(?, ?, ?, ?, ?, ?)
`, id, service.Hostname, service.HostIP, service.Port, service.Protocol, service.Service)
	return err
}

func normalizeFindingInput(input FindingInput) FindingInput {
	input.Domain = strings.TrimSpace(input.Domain)
	input.Title = strings.TrimSpace(input.Title)
	input.Severity = strings.ToLower(strings.TrimSpace(input.Severity))
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.DescriptionHTML = strings.TrimSpace(input.DescriptionHTML)
	input.LinkedSubdomains = uniqueSortedStrings(input.LinkedSubdomains)
	input.LinkedHosts = uniqueSortedStrings(input.LinkedHosts)
	if input.AffectedService != nil {
		service := *input.AffectedService
		service.Hostname = strings.TrimSpace(service.Hostname)
		service.HostIP = strings.TrimSpace(service.HostIP)
		service.Protocol = strings.ToLower(strings.TrimSpace(service.Protocol))
		service.Service = strings.TrimSpace(service.Service)
		if service.Protocol == "" {
			service.Protocol = "tcp"
		}
		input.AffectedService = &service
	}
	return input
}

func validateFindingInput(input FindingInput) error {
	if input.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if input.Title == "" {
		return fmt.Errorf("title is required")
	}
	if _, ok := validFindingSeverities[input.Severity]; !ok {
		return fmt.Errorf("invalid severity %q", input.Severity)
	}
	if _, ok := validFindingStatuses[input.Status]; !ok {
		return fmt.Errorf("invalid status %q", input.Status)
	}
	if input.AffectedService != nil {
		if input.AffectedService.HostIP == "" {
			return fmt.Errorf("affected service host IP is required")
		}
		if input.AffectedService.Port <= 0 || input.AffectedService.Port > 65535 {
			return fmt.Errorf("affected service port must be between 1 and 65535")
		}
		if input.AffectedService.Protocol == "" {
			return fmt.Errorf("affected service protocol is required")
		}
	}
	return nil
}
