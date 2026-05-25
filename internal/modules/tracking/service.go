package tracking

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/indigo-sadland/logy/internal/config"
	"github.com/indigo-sadland/logy/internal/storage"
)

const (
	timeRFC3339       = "2006-01-02T15:04:05Z07:00"
	transcriptModePTY = "pty-script"
)

// Service owns the command-tracking workflow. Cobra stays in cmd/, while this
// package handles metadata inference, persistence, transcript capture, and the
// JSON-friendly result shapes returned to callers.
type Service struct {
	TranscriptDir string
}

// ExecOptions describes one tracked command execution request after the caller
// has already resolved any CLI-specific defaults such as the active domain.
type ExecOptions struct {
	Domain       string
	Target       string
	Tool         string
	Wordlist     string
	Notes        string
	ConfigPath   string
	RecordOutput bool
}

// ShowOptions describes how stored command runs should be filtered.
type ShowOptions struct {
	Domain     string
	Target     string
	Tool       string
	ConfigPath string
}

// ExecResult is the stable JSON-facing shape returned to cmd/ for
// `holdmy exec`.
type ExecResult struct {
	ID              int64  `json:"id"`
	Domain          string `json:"domain"`
	Target          string `json:"target"`
	Tool            string `json:"tool"`
	Command         string `json:"command"`
	Wordlist        string `json:"wordlist,omitempty"`
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	Database        string `json:"database"`
	TranscriptPath  string `json:"transcript_path,omitempty"`
	TranscriptBytes *int64 `json:"transcript_bytes,omitempty"`
	TranscriptMode  string `json:"transcript_mode,omitempty"`
}

// ShowResult is the stable JSON-facing shape returned to cmd/ for
// `holdmy show`.
type ShowResult struct {
	Domain   string          `json:"domain"`
	Database string          `json:"database"`
	Count    int             `json:"count"`
	Runs     []ShowRunResult `json:"runs"`
}

// ShowRunResult is one serialized command-run record.
type ShowRunResult struct {
	ID              int64  `json:"id"`
	Target          string `json:"target"`
	Tool            string `json:"tool"`
	Command         string `json:"command"`
	Wordlist        string `json:"wordlist,omitempty"`
	Status          string `json:"status"`
	ExitCode        *int64 `json:"exit_code,omitempty"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at,omitempty"`
	Notes           string `json:"notes,omitempty"`
	TranscriptPath  string `json:"transcript_path,omitempty"`
	TranscriptBytes *int64 `json:"transcript_bytes,omitempty"`
	TranscriptMode  string `json:"transcript_mode,omitempty"`
}

func (s Service) Execute(ctx context.Context, opts ExecOptions, args []string) (ExecResult, error) {
	opts = normalizeExecOptions(opts)
	if opts.Domain == "" {
		return ExecResult{}, fmt.Errorf("domain is required")
	}
	if len(args) == 0 {
		return ExecResult{}, fmt.Errorf("command after -- is required\n")
	}
	opts = inferExecMetadata(opts, args)

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return ExecResult{}, err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return ExecResult{}, err
	}
	defer store.Close()

	if opts.Tool == "" {
		opts.Tool = filepath.Base(args[0])
	}

	startedAt := time.Now().UTC()
	commandLine := shellQuoteArgs(args)
	runID, err := store.CreateCommandRun(storage.CommandRunRecord{
		Domain:    opts.Domain,
		Target:    opts.Target,
		Tool:      opts.Tool,
		Command:   commandLine,
		Wordlist:  opts.Wordlist,
		Status:    "running",
		StartedAt: startedAt,
		Notes:     opts.Notes,
	})
	if err != nil {
		return ExecResult{}, err
	}

	exitCode := 0
	status := "completed"
	transcript := commandTranscript{}
	if opts.RecordOutput {
		transcript = s.buildCommandTranscript(runID, startedAt)
	}

	runErr := executeTrackedCommand(ctx, args, transcript)
	if runErr != nil {
		status = "failed"
		exitCode = commandExitCode(runErr)
	}
	transcript.captureMetadata()

	finishedAt := time.Now().UTC()
	if err := store.FinishCommandRun(runID, status, exitCode, finishedAt, transcript.Path, transcript.Bytes, transcript.Mode); err != nil {
		return ExecResult{}, err
	}

	result := ExecResult{
		ID:              runID,
		Domain:          opts.Domain,
		Target:          opts.Target,
		Tool:            opts.Tool,
		Command:         commandLine,
		Wordlist:        opts.Wordlist,
		Status:          status,
		ExitCode:        exitCode,
		StartedAt:       startedAt.Format(timeRFC3339),
		FinishedAt:      finishedAt.Format(timeRFC3339),
		Database:        cfg.Database.Path,
		TranscriptPath:  transcript.Path,
		TranscriptBytes: nullInt64Pointer(transcript.Bytes),
		TranscriptMode:  transcript.Mode,
	}
	if runErr != nil {
		return result, runErr
	}
	return result, nil
}

func (s Service) Show(opts ShowOptions) (ShowResult, error) {
	opts = normalizeShowOptions(opts)
	if opts.Domain == "" {
		return ShowResult{}, fmt.Errorf("domain is required")
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return ShowResult{}, err
	}

	store, err := storage.Open(cfg.Database.Path)
	if err != nil {
		return ShowResult{}, err
	}
	defer store.Close()

	records, err := store.CommandRunsByDomain(opts.Domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ShowResult{}, fmt.Errorf("no tracked command runs for domain %s\n", opts.Domain)
		}
		return ShowResult{}, err
	}
	records = filterCommandRuns(records, opts.Tool, opts.Target)

	result := ShowResult{
		Domain:   opts.Domain,
		Database: cfg.Database.Path,
		Count:    len(records),
		Runs:     make([]ShowRunResult, 0, len(records)),
	}
	for _, record := range records {
		finishedAt := ""
		if record.FinishedAt.Valid {
			finishedAt = record.FinishedAt.Time.Format(timeRFC3339)
		}
		result.Runs = append(result.Runs, ShowRunResult{
			ID:              record.ID,
			Target:          record.Target,
			Tool:            record.Tool,
			Command:         record.Command,
			Wordlist:        record.Wordlist,
			Status:          record.Status,
			ExitCode:        nullInt64Pointer(record.ExitCode),
			StartedAt:       record.StartedAt.Format(timeRFC3339),
			FinishedAt:      finishedAt,
			Notes:           record.Notes,
			TranscriptPath:  record.TranscriptPath,
			TranscriptBytes: nullInt64Pointer(record.TranscriptBytes),
			TranscriptMode:  record.TranscriptMode,
		})
	}
	return result, nil
}

func MarshalIndented(v any) ([]byte, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func normalizeExecOptions(opts ExecOptions) ExecOptions {
	opts.Domain = strings.TrimSpace(opts.Domain)
	opts.Target = strings.TrimSpace(opts.Target)
	opts.Tool = strings.TrimSpace(opts.Tool)
	opts.Wordlist = strings.TrimSpace(opts.Wordlist)
	opts.Notes = strings.TrimSpace(opts.Notes)
	opts.ConfigPath = strings.TrimSpace(opts.ConfigPath)
	return opts
}

func normalizeShowOptions(opts ShowOptions) ShowOptions {
	opts.Domain = strings.TrimSpace(opts.Domain)
	opts.Target = strings.TrimSpace(opts.Target)
	opts.Tool = strings.TrimSpace(opts.Tool)
	opts.ConfigPath = strings.TrimSpace(opts.ConfigPath)
	return opts
}

func inferExecMetadata(opts ExecOptions, args []string) ExecOptions {
	if opts.Tool == "" && len(args) > 0 {
		opts.Tool = filepath.Base(args[0])
	}
	if opts.Target == "" {
		opts.Target = inferCommandTarget(args)
	}
	if opts.Wordlist == "" {
		opts.Wordlist = inferCommandWordlist(args)
	}
	return opts
}

func executeTrackedCommand(ctx context.Context, args []string, transcript commandTranscript) error {
	if transcript.Enabled() {
		return executeTrackedCommandWithTranscript(ctx, args, transcript)
	}
	external := exec.CommandContext(ctx, args[0], args[1:]...)
	external.Stdin = os.Stdin
	external.Stdout = os.Stdout
	external.Stderr = os.Stderr
	return external.Run()
}

func filterCommandRuns(records []storage.CommandRunRecord, tool string, target string) []storage.CommandRunRecord {
	tool = strings.TrimSpace(tool)
	target = strings.TrimSpace(target)
	if tool == "" && target == "" {
		return records
	}
	out := make([]storage.CommandRunRecord, 0, len(records))
	for _, record := range records {
		if tool != "" && record.Tool != tool {
			continue
		}
		if target != "" && record.Target != target {
			continue
		}
		out = append(out, record)
	}
	return out
}

func nullInt64Pointer(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	out := value.Int64
	return &out
}

func inferCommandTarget(args []string) string {
	if len(args) == 0 {
		return ""
	}
	tool := filepath.Base(strings.TrimSpace(args[0]))
	if target := inferCommandTargetByTool(tool, args[1:]); target != "" {
		return target
	}

	for i, arg := range args {
		switch arg {
		case "-u", "--url", "-target", "--target":
			if i+1 < len(args) {
				return normalizeCommandTarget(args[i+1])
			}
		}
		for _, prefix := range []string{"-u=", "--url=", "-target=", "--target="} {
			if strings.HasPrefix(arg, prefix) {
				return normalizeCommandTarget(strings.TrimPrefix(arg, prefix))
			}
		}
	}
	for _, arg := range args {
		if strings.Contains(arg, "://") {
			return normalizeCommandTarget(arg)
		}
	}
	for _, arg := range args[1:] {
		if target := inferGenericPositionalTarget(arg); target != "" {
			return target
		}
	}
	return ""
}

// inferCommandTargetByTool keeps common shell workflows readable by handling
// positional argument conventions used by tools such as ssh, scp, and curl.
func inferCommandTargetByTool(tool string, args []string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "ssh":
		return inferSSHTarget(args)
	case "scp", "rsync", "sftp":
		return inferRemoteCopyTarget(args)
	case "nc", "netcat", "nmap", "ping", "curl", "wget":
		for _, arg := range args {
			if target := inferGenericPositionalTarget(arg); target != "" {
				return target
			}
		}
	}
	return ""
}

func inferSSHTarget(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if target := normalizeSSHStyleTarget(arg); target != "" {
			return target
		}
	}
	return ""
}

func inferRemoteCopyTarget(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if target := normalizeRemotePathTarget(arg); target != "" {
			return target
		}
	}
	return ""
}

func inferGenericPositionalTarget(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" || strings.HasPrefix(arg, "-") {
		return ""
	}
	if target := normalizeSSHStyleTarget(arg); target != "" {
		return target
	}
	if target := normalizeRemotePathTarget(arg); target != "" {
		return target
	}
	return normalizeCommandTarget(arg)
}

func normalizeCommandTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		return value
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	if isLikelyHostname(value) {
		return value
	}
	return ""
}

func normalizeSSHStyleTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "-") {
		return ""
	}
	at := strings.LastIndex(value, "@")
	if at >= 0 && at+1 < len(value) {
		value = value[at+1:]
	}
	if value == "" {
		return ""
	}
	if i := strings.Index(value, ":"); i >= 0 {
		value = value[:i]
	}
	return normalizeCommandTarget(value)
}

func normalizeRemotePathTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "-") {
		return ""
	}
	colon := strings.Index(value, ":")
	if colon <= 0 {
		return ""
	}
	hostPart := value[:colon]
	if strings.Contains(hostPart, "/") {
		return ""
	}
	return normalizeSSHStyleTarget(hostPart)
}

func isLikelyHostname(value string) bool {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func inferCommandWordlist(args []string) string {
	for i, arg := range args {
		switch arg {
		case "-w", "--wordlist":
			if i+1 < len(args) {
				return normalizeWordlistValue(args[i+1])
			}
		}
		for _, prefix := range []string{"-w=", "--wordlist="} {
			if strings.HasPrefix(arg, prefix) {
				return normalizeWordlistValue(strings.TrimPrefix(arg, prefix))
			}
		}
	}
	return ""
}

func normalizeWordlistValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if cut := strings.Index(value, ":"); cut >= 0 {
		value = value[:cut]
	}
	return strings.TrimSpace(value)
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func shellQuoteArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			quoted = append(quoted, "''")
			continue
		}
		if !strings.ContainsAny(arg, " \t\n'\"\\$`!()[]{}<>|&;*?~") {
			quoted = append(quoted, arg)
			continue
		}
		quoted = append(quoted, "'"+strings.ReplaceAll(arg, "'", `'\''`)+"'")
	}
	return strings.Join(quoted, " ")
}

type commandTranscript struct {
	Path  string
	Mode  string
	Bytes sql.NullInt64
}

func (t commandTranscript) Enabled() bool {
	return t.Path != ""
}

// buildCommandTranscript derives a deterministic transcript filename from the
// run id and start time so the database row and the filesystem artifact are
// easy to correlate later during export and manual review.
func (s Service) buildCommandTranscript(runID int64, startedAt time.Time) commandTranscript {
	name := fmt.Sprintf("%s-run-%d.typescript", startedAt.UTC().Format("20060102T150405Z"), runID)
	return commandTranscript{
		Path: filepath.Join(s.TranscriptDir, name),
		Mode: transcriptModePTY,
	}
}

// captureMetadata records the final transcript size after the wrapped command
// exits. The transcript itself lives on disk because terminal recordings can be
// large and are a poor fit for a SQLite row payload.
func (t *commandTranscript) captureMetadata() {
	if t == nil || t.Path == "" {
		return
	}
	info, err := os.Stat(t.Path)
	if err != nil || info.IsDir() {
		return
	}
	t.Bytes = sql.NullInt64{Int64: info.Size(), Valid: true}
}

// executeTrackedCommandWithTranscript delegates terminal recording to the
// system's script(1) utility. That utility already provides the PTY-backed
// behavior we want: the child command sees a real terminal, the operator sees
// live output, and the same session is mirrored into a transcript file.
func executeTrackedCommandWithTranscript(ctx context.Context, args []string, transcript commandTranscript) error {
	if err := os.MkdirAll(filepath.Dir(transcript.Path), 0o755); err != nil {
		return fmt.Errorf("create transcript directory: %w", err)
	}

	commandLine := shellQuoteArgs(args)
	// -q keeps script itself quiet, -e returns the child exit code, and -f
	// flushes transcript writes so the file is usable even during long sessions.
	external := exec.CommandContext(ctx, "script", "-q", "-e", "-f", "-c", commandLine, transcript.Path)
	external.Stdin = os.Stdin
	external.Stdout = os.Stdout
	external.Stderr = os.Stderr
	if err := external.Run(); err != nil {
		return fmt.Errorf("record command output with script(1): %w", err)
	}
	return nil
}
