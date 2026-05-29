# Project Structure

- `main.go` - CLI entrypoint; delegates to the Cobra command tree in `cmd`
- `config.yaml.example` - example runtime configuration for database, discovery tools, and resolver settings
- `assets/` - project images and static assets

## Commands

- `cmd/` - Cobra command tree and user-facing workflows
  - `root.go` - root command and top-level `domain` command group
  - `enum.go` - `domain enum` discovery/resolution flow and `domain show` JSON output
  - `candidates.go` - `domain candidates show` workflow for unresolved permutation candidate inspection
  - `brute.go` - `domain brute` dedicated `puredns` bruteforce flow
  - `domain_import.go` - `domain import` workflow for hostname/IP imports with automatic DNS resolution for plain hosts
  - `resolve.go` - `domain resolve vhost` and `domain resolve permute` enrichment commands
  - `portscan.go` - top-level `portscan` commands for raw `nmap`, DB-backed scans, exact saved-target selection, interactive saved-target picking, persistence, and result display
  - `portscan_picker.go` - terminal picker helpers for interactive DB-backed single-target scans across hostname-backed and IP-only assets
  - `probe.go` - top-level `probe` commands for raw `httpx`, saved raw probes, DB-backed automatic probing, and stored result display
  - `run.go` - `holdmy exec` and `holdmy show` command tracking workflows for external tools
  - `serve.go` - `serve` command for the read-only local web UI
  - `export.go` - `export anytype` push workflow for saved Assets, Services, service historical observations, web app observations, and Scans, plus scan-only export mode
  - `secrets.go` - `secrets` command group for age-encrypted local credentials

## Internal Packages

- `internal/config/` - YAML config loading, defaults, and validation
  - `config.go` - config model, normalization, resolver timeout parsing, and tool validation
- `internal/secrets/` - age passphrase-mode encryption for local machine/user secrets
  - `secrets.go` - encrypted secrets load/save helpers for Anytype and BufferOver credentials
- `internal/pipeline/` - workflow orchestration
  - `engine.go` - coordinates provider discovery, persistence, DNS resolution, and summary reporting
- `internal/web/` - read-only HTTP UI and JSON endpoints for saved recon data
  - `server.go` - web server, API handlers, and HTML template wiring
  - `index_html.go` - ReconScope-style single-page dashboard HTML, CSS, and client-side rendering logic
  - `view_models.go` - host-centric web view aggregation helpers for ports, probes, and candidate links
- `internal/storage/` - SQLite persistence layer
  - `store.go` - store construction and database handle lifecycle
  - `schema.go` - SQLite schema initialization, including confirmed subdomain state, service historical observations, and permutation candidate storage
  - `types.go` - storage record types shared by command and module code
  - `subdomains.go` - confirmed subdomain discovery and resolution persistence/query helpers, including saved scan target aggregation
  - `candidates.go` - unresolved permutation candidate persistence, listing, and promotion cleanup helpers
  - `portscans.go` - open-port scan persistence/query helpers, including IP-only saved target support for the picker
  - `service_observations.go` - append-only service historical observation persistence/query helpers for export and comparison workflows
  - `webprobes.go` - web probe history and automatic probe target construction
  - `commandruns.go` - external command execution history persistence/query helpers
  - `dashboard.go` - domain summary and dashboard query helpers
  - `helpers.go` - small storage parsing helpers
- `internal/executor/` - subprocess helpers
  - `exec.go` - streams command stdout line-by-line and reports stderr on failure
- `internal/utils/` - shared utilities
  - `dedup/dedup.go` - simple unique-string collection helper
  - `output/line_printer.go` - terminal-aware output formatting helpers
  - `puredns/progress_tracker.go` - progress tracking for `puredns` bruteforce runs

## Recon Modules

- `internal/modules/discovery/` - subdomain discovery provider registry and aggregation
  - `providers.go` - provider factory registry and config-to-provider wiring
  - `discover.go` - concurrent multi-provider execution, normalization, deduplication, and source tracking
  - `http_provider.go` - HTTP-backed providers such as BufferOver and RIPEStat
  - `types.go` - discovery config and provider-facing types
  - `provider/` - provider interfaces and CLI-backed provider adapter
  - `models/` - discovery config model aliases used by provider factories
- `internal/modules/exporter/`
  - `anytype.go` - Anytype API client and push workflow for Assets, Services, service historical observations, web app observations, and Scans
- `internal/modules/resolver/` - DNS and vhost resolution adapters
  - `resolver.go` - `dnsx` wrapper, live progress handling, and JSONL response parsing
  - `progress.go` - terminal progress tracker for long-running `dnsx` resolution
  - `vhostfinder.go` - `VhostFinder` wrapper and output parsing
- `internal/modules/permutation/`
  - `gotator.go` - `gotator` wrapper for generating candidate subdomain permutations that are later confirmed through DNS or vhost resolution
- `internal/modules/portscan/`
  - `nmap.go` - `nmap` wrapper, XML capture, XML parsing, and open-port normalization
- `internal/modules/tracking/`
  - `service.go` - command execution tracking, transcript capture, and stored command run rendering for `holdmy`
- `internal/modules/webprobe/`
  - `httpx.go` - `httpx` wrapper, raw passthrough mode, JSONL parsing, and result normalization

## Tests

- `*_test.go` files live next to the packages they exercise.
- Most module tests focus on parsers, normalization, validation, storage behavior, and command helper logic rather than invoking external recon binaries directly.
