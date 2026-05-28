package storage

import (
	"database/sql"
	"time"
)

// SaveServiceHistoricalObservations appends historical service observations for
// later export and team-visible comparison against the current service view.
func (s *Store) SaveServiceHistoricalObservations(domain string, observations []ServiceHistoricalObservationRecord) error {
	if len(observations) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
INSERT INTO service_historical_observations(domain, host_ip, hostname, port, protocol, observed_state, observed_banner, observed_service, observed_at, source)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, observation := range observations {
		if _, err := stmt.Exec(
			domain,
			observation.HostIP,
			observation.Hostname,
			observation.Port,
			observation.Protocol,
			observation.ObservedState,
			observation.ObservedBanner,
			observation.ObservedService,
			observation.ObservedAt.UTC().Format(time.RFC3339),
			observation.Source,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ServiceHistoricalObservationsByDomain returns historical service observations
// in chronological order for export and comparison workflows.
func (s *Store) ServiceHistoricalObservationsByDomain(domain string) ([]ServiceHistoricalObservationRecord, error) {
	rows, err := s.db.Query(`
SELECT domain, host_ip, hostname, port, protocol, observed_state, observed_banner, observed_service, observed_at, source
FROM service_historical_observations
WHERE domain=?
ORDER BY observed_at ASC, id ASC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]ServiceHistoricalObservationRecord, 0, 64)
	for rows.Next() {
		var record ServiceHistoricalObservationRecord
		var observedAt string
		if err := rows.Scan(
			&record.Domain,
			&record.HostIP,
			&record.Hostname,
			&record.Port,
			&record.Protocol,
			&record.ObservedState,
			&record.ObservedBanner,
			&record.ObservedService,
			&observedAt,
			&record.Source,
		); err != nil {
			return nil, err
		}
		parsedObservedAt, err := time.Parse(time.RFC3339, observedAt)
		if err != nil {
			return nil, err
		}
		record.ObservedAt = parsedObservedAt
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
