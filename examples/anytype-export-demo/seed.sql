PRAGMA foreign_keys = OFF;

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

INSERT INTO subdomains (domain, subdomain, sources, resolved, ips, resolve_error, first_seen_at, last_seen_at, last_resolved_at, updated_at) VALUES
('demo.example', 'app.demo.example', 'subfinder,import', 1, '10.20.30.40', '', '2026-05-24T16:45:00Z', '2026-05-24T18:22:00Z', '2026-05-24T18:22:00Z', '2026-05-24T18:22:00Z'),
('demo.example', 'api.demo.example', 'subfinder', 1, '10.20.30.40', '', '2026-05-24T16:50:00Z', '2026-05-24T18:22:00Z', '2026-05-24T18:22:00Z', '2026-05-24T18:22:00Z'),
('demo.example', 'admin.demo.example', 'findomain', 1, '10.20.30.41', '', '2026-05-24T16:55:00Z', '2026-05-24T18:25:00Z', '2026-05-24T18:25:00Z', '2026-05-24T18:25:00Z'),
('demo.example', 'staging.demo.example', 'gotator', 0, '', 'no A record', '2026-05-24T17:15:00Z', '2026-05-24T17:15:00Z', NULL, '2026-05-24T17:15:00Z');

INSERT INTO permutation_candidates (domain, subdomain, sources, first_seen_at, last_seen_at, updated_at) VALUES
('demo.example', 'beta-admin.demo.example', 'gotator', '2026-05-24T17:20:00Z', '2026-05-24T17:20:00Z', '2026-05-24T17:20:00Z');

INSERT INTO port_scans (domain, ip, port, protocol, state, service, version, scanned_at) VALUES
('demo.example', '10.20.30.40', 22, 'tcp', 'open', 'ssh', 'OpenSSH 9.8p1 Debian 1', '2026-05-24T17:14:18Z'),
('demo.example', '10.20.30.40', 80, 'tcp', 'open', 'http', 'nginx 1.27.0', '2026-05-24T17:14:18Z'),
('demo.example', '10.20.30.40', 443, 'tcp', 'open', 'https', 'nginx 1.27.0', '2026-05-24T17:14:18Z'),
('demo.example', '10.20.30.41', 8443, 'tcp', 'open', 'https', 'Caddy 2.9.1', '2026-05-24T17:20:31Z'),
('demo.example', '172.16.10.50', 3389, 'tcp', 'open', 'ms-wbt-server', 'Microsoft Terminal Services', '2026-05-24T17:25:41Z');

INSERT INTO web_probes (domain, target, url, final_url, scheme, port, status_code, title, technologies, probed_at) VALUES
('demo.example', 'app.demo.example', 'https://app.demo.example', 'https://app.demo.example/login', 'https', 443, 200, 'Demo Login', 'nginx,react', '2026-05-24T17:35:00Z'),
('demo.example', 'admin.demo.example', 'https://admin.demo.example:8443', 'https://admin.demo.example:8443/', 'https', 8443, 401, 'Admin Console', 'caddy,go', '2026-05-24T17:37:00Z');

INSERT INTO command_runs (domain, target, tool, command, wordlist, status, started_at, finished_at, exit_code, notes, transcript_path, transcript_bytes, transcript_mode) VALUES
('demo.example', '10.20.30.40', 'nmap', 'nmap -Pn -sV 10.20.30.40', '', 'completed', '2026-05-24T17:14:11Z', '2026-05-24T17:14:18Z', 0, 'Baseline service census with transcript capture enabled', 'transcripts/nmap-demo.typescript', 668, 'pty-script'),
('demo.example', 'https://app.demo.example/FUZZ', 'ffuf', 'ffuf -u https://app.demo.example/FUZZ -w raft-small-words.txt -mc all', 'raft-small-words.txt', 'completed', '2026-05-24T17:45:00Z', '2026-05-24T17:52:13Z', 0, 'Content discovery against app.demo.example', '', NULL, ''),
('demo.example', '10.20.30.41', 'curl', 'curl -ki https://admin.demo.example:8443/', '', 'failed', '2026-05-24T18:05:00Z', '2026-05-24T18:05:07Z', 35, 'TLS handshake check against admin interface', '', NULL, '');
