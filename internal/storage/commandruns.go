package storage

import (
	"database/sql"
	"time"
)

// CreateCommandRun inserts a command execution record before the process starts.
func (s *Store) CreateCommandRun(record CommandRunRecord) (int64, error) {
	result, err := s.db.Exec(`
INSERT INTO command_runs(domain, target, tool, command, wordlist, status, started_at, notes, transcript_path, transcript_bytes, transcript_mode)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		record.Domain,
		record.Target,
		record.Tool,
		record.Command,
		record.Wordlist,
		record.Status,
		record.StartedAt.UTC().Format(time.RFC3339),
		record.Notes,
		record.TranscriptPath,
		nullInt64Value(record.TranscriptBytes),
		record.TranscriptMode,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// FinishCommandRun stores the final status, exit code, and finish time.
func (s *Store) FinishCommandRun(id int64, status string, exitCode int, finishedAt time.Time, transcriptPath string, transcriptBytes sql.NullInt64, transcriptMode string) error {
	_, err := s.db.Exec(`
UPDATE command_runs
SET status=?, exit_code=?, finished_at=?, transcript_path=?, transcript_bytes=?, transcript_mode=?
WHERE id=?
`,
		status,
		exitCode,
		finishedAt.UTC().Format(time.RFC3339),
		transcriptPath,
		nullInt64Value(transcriptBytes),
		transcriptMode,
		id,
	)
	return err
}

// CommandRunsByDomain returns command execution history for a domain, newest first.
func (s *Store) CommandRunsByDomain(domain string) ([]CommandRunRecord, error) {
	rows, err := s.db.Query(`
SELECT id, domain, target, tool, command, wordlist, status, started_at, finished_at, exit_code, notes, transcript_path, transcript_bytes, transcript_mode
FROM command_runs
WHERE domain=?
ORDER BY started_at DESC, id DESC
`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]CommandRunRecord, 0, 64)
	for rows.Next() {
		record, err := scanCommandRun(rows)
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
	return records, nil
}

type commandRunScanner interface {
	Scan(dest ...any) error
}

func scanCommandRun(scanner commandRunScanner) (CommandRunRecord, error) {
	var record CommandRunRecord
	var startedAt string
	var finishedAt sql.NullString
	var exitCode sql.NullInt64
	if err := scanner.Scan(
		&record.ID,
		&record.Domain,
		&record.Target,
		&record.Tool,
		&record.Command,
		&record.Wordlist,
		&record.Status,
		&startedAt,
		&finishedAt,
		&exitCode,
		&record.Notes,
		&record.TranscriptPath,
		&record.TranscriptBytes,
		&record.TranscriptMode,
	); err != nil {
		return CommandRunRecord{}, err
	}

	parsedStartedAt, err := time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return CommandRunRecord{}, err
	}
	record.StartedAt = parsedStartedAt

	if finishedAt.Valid && finishedAt.String != "" {
		parsedFinishedAt, err := time.Parse(time.RFC3339, finishedAt.String)
		if err != nil {
			return CommandRunRecord{}, err
		}
		record.FinishedAt = sql.NullTime{Time: parsedFinishedAt, Valid: true}
	}
	record.ExitCode = exitCode
	return record, nil
}

func nullInt64Value(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}
