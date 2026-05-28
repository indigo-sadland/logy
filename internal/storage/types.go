package storage

import (
	"database/sql"
	"time"
)

type SubdomainRecord struct {
	Domain         string
	Subdomain      string
	Sources        []string
	Resolved       bool
	IPs            []string
	ResolveError   string
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	LastResolvedAt sql.NullTime
	UpdatedAt      time.Time
}

type ResolvedSubdomainTarget struct {
	Domain    string
	Subdomain string
	IPs       []string
}

type SavedScanTarget struct {
	Domain string
	Label  string
	Kind   string
	IPs    []string
}

type PermutationCandidateRecord struct {
	Domain      string
	Subdomain   string
	Sources     []string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	UpdatedAt   time.Time
}

type FindingRecord struct {
	ID               int64
	Domain           string
	Title            string
	Severity         string
	Status           string
	DescriptionHTML  string
	LinkedSubdomains []string
	LinkedHosts      []string
	AffectedService  *FindingServiceRecord
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type FindingServiceRecord struct {
	Hostname string
	HostIP   string
	Port     int
	Protocol string
	Service  string
}

type PortScanRecord struct {
	Domain    string
	IP        string
	Port      int
	Protocol  string
	State     string
	Service   string
	Version   string
	ScannedAt time.Time
}

type ServiceHistoricalObservationRecord struct {
	Domain          string
	HostIP          string
	Hostname        string
	Port            int
	Protocol        string
	ObservedState   string
	ObservedBanner  string
	ObservedService string
	ObservedAt      time.Time
	Source          string
}

type WebProbeRecord struct {
	Domain       string
	Target       string
	URL          string
	FinalURL     string
	Scheme       string
	Port         int
	StatusCode   int
	Title        string
	Technologies []string
	ProbedAt     time.Time
}

type WebProbeTarget struct {
	Subdomain string
	Scheme    string
	Port      int
	URL       string
}

type CommandRunRecord struct {
	ID              int64
	Domain          string
	Target          string
	Tool            string
	Command         string
	Wordlist        string
	Status          string
	StartedAt       time.Time
	FinishedAt      sql.NullTime
	ExitCode        sql.NullInt64
	Notes           string
	TranscriptPath  string
	TranscriptBytes sql.NullInt64
	TranscriptMode  string
}
