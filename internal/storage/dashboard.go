package storage

type DomainSummary struct {
	Domain      string `json:"domain"`
	Subdomains  int    `json:"subdomains"`
	Resolved    int    `json:"resolved"`
	Candidates  int    `json:"candidates"`
	Findings    int    `json:"findings"`
	Ports       int    `json:"ports"`
	WebProbes   int    `json:"web_probes"`
	CommandRuns int    `json:"command_runs"`
}

// Domains returns every domain label known to any persisted dataset.
func (s *Store) Domains() ([]string, error) {
	rows, err := s.db.Query(`
SELECT domain FROM subdomains
UNION
SELECT domain FROM permutation_candidates
UNION
SELECT domain FROM findings
UNION
SELECT domain FROM port_scans
UNION
SELECT domain FROM web_probes
UNION
SELECT domain FROM command_runs
ORDER BY domain ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	domains := make([]string, 0, 16)
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

// DomainSummaries returns compact counts used by the web dashboard.
func (s *Store) DomainSummaries() ([]DomainSummary, error) {
	domains, err := s.Domains()
	if err != nil {
		return nil, err
	}
	summaries := make([]DomainSummary, 0, len(domains))
	for _, domain := range domains {
		summary, err := s.DomainSummary(domain)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

// DomainSummary returns dashboard counts for a single domain.
func (s *Store) DomainSummary(domain string) (DomainSummary, error) {
	summary := DomainSummary{Domain: domain}
	queries := []struct {
		dst   *int
		query string
	}{
		{&summary.Subdomains, `SELECT COUNT(*) FROM subdomains WHERE domain=?`},
		{&summary.Resolved, `SELECT COUNT(*) FROM subdomains WHERE domain=? AND resolved=1`},
		{&summary.Candidates, `SELECT COUNT(*) FROM permutation_candidates WHERE domain=?`},
		{&summary.Findings, `SELECT COUNT(*) FROM findings WHERE domain=?`},
		{&summary.Ports, `SELECT COUNT(*) FROM port_scans WHERE domain=?`},
		{&summary.WebProbes, `SELECT COUNT(*) FROM web_probes WHERE domain=?`},
		{&summary.CommandRuns, `SELECT COUNT(*) FROM command_runs WHERE domain=?`},
	}
	for _, item := range queries {
		if err := s.db.QueryRow(item.query, domain).Scan(item.dst); err != nil {
			return DomainSummary{}, err
		}
	}
	return summary, nil
}
