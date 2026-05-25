package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/indigo-sadland/logy/internal/storage"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Server struct {
	store *storage.Store
	mux   *http.ServeMux
}

func NewServer(store *storage.Store) *Server {
	server := &Server{
		store: store,
		mux:   http.NewServeMux(),
	}
	server.routes()
	return server
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	httpServer := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}
	go func() {
		<-ctx.Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	err := httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/api/domains", s.handleDomains)
	s.mux.HandleFunc("/api/domain/", s.handleDomainAPI)
	s.mux.HandleFunc("/api/finding/", s.handleFindingAPI)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexTemplate.Execute(w, nil)
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	summaries, err := s.store.DomainSummaries()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, summaries)
}

func (s *Server) handleDomainAPI(w http.ResponseWriter, r *http.Request) {
	domain, resource, ok := parseDomainPath(strings.TrimPrefix(r.URL.Path, "/api/domain/"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch resource {
	case "summary":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := s.store.DomainSummary(domain)
		writeJSONOrError(w, data, err)
	case "hosts":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := s.domainHosts(domain)
		writeJSONOrNoRows(w, data, err)
	case "candidates":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := s.store.PermutationCandidatesByDomain(domain)
		writeJSONOrNoRows(w, data, err)
	case "findings":
		if r.Method == http.MethodGet {
			data, err := s.domainFindings(domain)
			writeJSONOrNoRows(w, data, err)
			return
		}
		if r.Method == http.MethodPost {
			s.handleCreateFinding(w, r, domain)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	case "subdomains":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := s.store.SubdomainsByDomain(domain)
		writeJSONOrNoRows(w, data, err)
	case "ports":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := s.store.PortScansByDomain(domain)
		writeJSONOrNoRows(w, data, err)
	case "web-probes":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := s.store.WebProbesByDomain(domain)
		writeJSONOrNoRows(w, data, err)
	case "runs":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := s.store.CommandRunsByDomain(domain)
		writeJSONOrNoRows(w, data, err)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleFindingAPI(w http.ResponseWriter, r *http.Request) {
	idText := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/finding/"), "/")
	if idText == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid finding id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.handleUpdateFinding(w, r, id)
	case http.MethodDelete:
		if err := s.store.DeleteFinding(id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type findingPayload struct {
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Status           string   `json:"status"`
	DescriptionHTML  string   `json:"description_html"`
	LinkedSubdomains []string `json:"linked_subdomains"`
	LinkedHosts      []string `json:"linked_hosts"`
	AffectedService  *struct {
		Hostname string `json:"hostname"`
		HostIP   string `json:"host_ip"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	} `json:"affected_service"`
}

func (s *Server) handleCreateFinding(w http.ResponseWriter, r *http.Request, domain string) {
	payload, err := decodeFindingPayload(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	record, err := s.store.CreateFinding(storage.FindingInput{
		Domain:           domain,
		Title:            payload.Title,
		Severity:         payload.Severity,
		Status:           payload.Status,
		DescriptionHTML:  payload.DescriptionHTML,
		LinkedSubdomains: payload.LinkedSubdomains,
		LinkedHosts:      payload.LinkedHosts,
		AffectedService:  findingServiceInput(payload),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONWithStatus(w, record, http.StatusCreated)
}

func (s *Server) handleUpdateFinding(w http.ResponseWriter, r *http.Request, id int64) {
	payload, err := decodeFindingPayload(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	existing, err := s.store.FindingByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		writeError(w, err)
		return
	}
	record, err := s.store.UpdateFinding(id, storage.FindingInput{
		Domain:           existing.Domain,
		Title:            payload.Title,
		Severity:         payload.Severity,
		Status:           payload.Status,
		DescriptionHTML:  payload.DescriptionHTML,
		LinkedSubdomains: payload.LinkedSubdomains,
		LinkedHosts:      payload.LinkedHosts,
		AffectedService:  findingServiceInput(payload),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, record)
}

func decodeFindingPayload(body io.Reader) (findingPayload, error) {
	var payload findingPayload
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		return findingPayload{}, err
	}
	return payload, nil
}

func findingServiceInput(payload findingPayload) *storage.FindingServiceInput {
	if payload.AffectedService == nil {
		return nil
	}
	return &storage.FindingServiceInput{
		Hostname: payload.AffectedService.Hostname,
		HostIP:   payload.AffectedService.HostIP,
		Port:     payload.AffectedService.Port,
		Protocol: payload.AffectedService.Protocol,
		Service:  payload.AffectedService.Service,
	}
}

func (s *Server) domainHosts(domain string) ([]hostView, error) {
	subdomains, err := s.store.SubdomainsByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		subdomains = nil
	}

	scans, err := s.store.PortScansByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		scans = nil
	}

	probes, err := s.store.WebProbesByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		probes = nil
	}

	candidates, err := s.store.PermutationCandidatesByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		candidates = nil
	}

	data := buildHostViews(subdomains, scans, probes, candidates)
	if len(data) == 0 {
		return nil, sql.ErrNoRows
	}
	return data, nil
}

func (s *Server) domainFindings(domain string) ([]findingView, error) {
	findings, err := s.store.FindingsByDomain(domain)
	if err != nil {
		return nil, err
	}

	subdomains, err := s.store.SubdomainsByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		subdomains = nil
	}

	scans, err := s.store.PortScansByDomain(domain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		scans = nil
	}

	return buildFindingViews(findings, subdomains, scans), nil
}

func parseDomainPath(value string) (domain string, resource string, ok bool) {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func writeJSONOrNoRows[T any](w http.ResponseWriter, data T, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, []any{})
		return
	}
	writeJSONOrError(w, data, err)
}

func writeJSONOrError[T any](w http.ResponseWriter, data T, err error) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, data)
}

func writeJSON(w http.ResponseWriter, data any) {
	writeJSONWithStatus(w, data, http.StatusOK)
}

func writeJSONWithStatus(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

var indexTemplate = template.Must(template.New("index").Parse(reconscopeIndexHTML))
