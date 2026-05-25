package storage

import "strings"

// init creates the SQLite schema when it does not already exist.
func (s *Store) init() error {
	_, err := s.db.Exec(sqliteSchema)
	if err != nil {
		return err
	}
	return s.migrateCommandRunsSchema()
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    sources TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    ips TEXT NOT NULL DEFAULT '',
    resolve_error TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_resolved_at TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(domain, subdomain)
);

CREATE TABLE IF NOT EXISTS permutation_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    sources TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(domain, subdomain)
);

CREATE TABLE IF NOT EXISTS port_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    scanned_at TEXT NOT NULL,
    UNIQUE(domain, ip, port, protocol)
);

CREATE TABLE IF NOT EXISTS web_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    target TEXT NOT NULL,
    url TEXT NOT NULL,
    final_url TEXT NOT NULL DEFAULT '',
    scheme TEXT NOT NULL,
    port INTEGER NOT NULL,
    status_code INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    technologies TEXT NOT NULL DEFAULT '',
    probed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS command_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    target TEXT NOT NULL,
    tool TEXT NOT NULL,
    command TEXT NOT NULL,
    wordlist TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    exit_code INTEGER,
    notes TEXT NOT NULL DEFAULT '',
    transcript_path TEXT NOT NULL DEFAULT '',
    transcript_bytes INTEGER,
    transcript_mode TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    description_html TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_subdomains (
    finding_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    UNIQUE(finding_id, subdomain)
);

CREATE TABLE IF NOT EXISTS finding_hosts (
    finding_id INTEGER NOT NULL,
    host_ip TEXT NOT NULL,
    UNIQUE(finding_id, host_ip)
);

CREATE TABLE IF NOT EXISTS finding_services (
    finding_id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    host_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service TEXT NOT NULL DEFAULT ''
);
`

// migrateCommandRunsSchema adds transcript metadata columns for existing
// databases created before terminal recording support existed. New databases
// already get the full schema from sqliteSchema above, so these ALTER TABLE
// statements are only needed when an older DB is opened in place.
func (s *Store) migrateCommandRunsSchema() error {
	for _, statement := range []string{
		`ALTER TABLE command_runs ADD COLUMN transcript_path TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE command_runs ADD COLUMN transcript_bytes INTEGER`,
		`ALTER TABLE command_runs ADD COLUMN transcript_mode TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(statement); err != nil && !sqliteDuplicateColumnError(err) {
			return err
		}
	}
	return nil
}

func sqliteDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
}
