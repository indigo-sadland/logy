package webprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Binary            string
	Resolvers         []string
	Progress          func(Progress)
	HeartbeatInterval time.Duration
}

type Result struct {
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

type Progress struct {
	Completed  int
	Total      int
	Status2xx  int
	Status3xx  int
	Status4xx  int
	Status5xx  int
	LastTarget string
	Elapsed    time.Duration
	Heartbeat  bool
}

// RunRaw preserves httpx's terminal-oriented output for manual probing workflows.
func RunRaw(ctx context.Context, cfg Config, inputFile string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return runRaw(ctx, cfg, inputFile, stdin, stdout, stderr, "")
}

// RunRawAndCapture keeps the normal stdout stream while also asking httpx to write output.
func RunRawAndCapture(ctx context.Context, cfg Config, inputFile string, stdin io.Reader, stdout io.Writer, stderr io.Writer) ([]Result, error) {
	baseDir, err := os.MkdirTemp("", "logy-httpx-output-*")
	if err != nil {
		return nil, fmt.Errorf("create httpx temp dir: %w\n", err)
	}
	defer os.RemoveAll(baseDir)

	basePath := filepath.Join(baseDir, "results")
	if err := runRaw(ctx, cfg, inputFile, stdin, stdout, stderr, basePath); err != nil {
		return nil, err
	}

	jsonPath, err := locateJSONOutput(basePath)
	if err != nil {
		return nil, err
	}
	return loadResultsFromFile(jsonPath)
}

// ProbeTargets is used for DB-backed runs where we want normalized JSONL instead of passthrough text.
func ProbeTargets(ctx context.Context, cfg Config, targets []string) ([]Result, error) {
	targets = normalizeTargets(targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one probe target is required")
	}

	args := buildProbeArgs(cfg)
	cmd := exec.CommandContext(ctx, normalizeBinary(cfg.Binary), args...)
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n") + "\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("httpx failed: %s", msg)
	}

	results, err := parseJSONL(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	return results, nil
}

// ProbeTargetsWithProgress streams httpx JSONL output so automatic DB-backed
// probing can report incremental status while the scan is still running.
func ProbeTargetsWithProgress(ctx context.Context, cfg Config, targets []string) ([]Result, error) {
	targets = normalizeTargets(targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one probe target is required")
	}

	args := buildProbeArgs(cfg)
	cmd := exec.CommandContext(ctx, normalizeBinary(cfg.Binary), args...)
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n") + "\n")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("httpx stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start httpx: %w", err)
	}

	// Keep a live view of completed probe results while httpx is still running.
	tracker := newProgressTracker(len(targets), cfg.Progress, cfg.HeartbeatInterval)
	tracker.start(ctx)
	defer tracker.stop()

	results, parseErr := scanResults(stdout, tracker)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return nil, parseErr
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("httpx failed: %s", msg)
	}

	slices.SortFunc(results, func(a, b Result) int {
		if cmp := strings.Compare(a.Target, b.Target); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.URL, b.URL); cmp != 0 {
			return cmp
		}
		return a.Port - b.Port
	})
	return results, nil
}

func loadResultsFromFile(path string) ([]Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read httpx json output: %w\n", err)
	}
	return parseJSONL(raw)
}

// parseJSONL accepts httpx's line-oriented JSON output and normalizes ordering for stable downstream behavior.
func parseJSONL(raw []byte) ([]Result, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	results := make([]Result, 0, 64)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		record, err := parseResultLine(line)
		if err != nil {
			return nil, err
		}
		results = append(results, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan httpx output: %w", err)
	}

	slices.SortFunc(results, func(a, b Result) int {
		if cmp := strings.Compare(a.Target, b.Target); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(a.URL, b.URL); cmp != 0 {
			return cmp
		}
		return a.Port - b.Port
	})
	return results, nil
}

// scanResults consumes httpx JSONL incrementally so callers can update progress per result line.
func scanResults(stdout io.Reader, tracker *progressTracker) ([]Result, error) {
	scanner := bufio.NewScanner(stdout)
	results := make([]Result, 0, 64)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		record, err := parseResultLine(line)
		if err != nil {
			return nil, err
		}
		results = append(results, record)
		if tracker != nil {
			tracker.record(record)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan httpx output: %w", err)
	}
	return results, nil
}

// parseResultLine tolerates field-name and type differences across httpx versions.
func parseResultLine(line []byte) (Result, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(line, &payload); err != nil {
		return Result{}, fmt.Errorf("parse httpx json line: %w\n", err)
	}

	result := Result{
		Target:       extractString(payload, "input", "host", "target"),
		URL:          extractString(payload, "url"),
		FinalURL:     extractString(payload, "final_url"),
		Scheme:       extractString(payload, "scheme"),
		StatusCode:   extractInt(payload, "status_code"),
		Title:        extractString(payload, "title"),
		Technologies: extractStringSlice(payload, "tech", "technologies"),
		ProbedAt:     time.Now().UTC(),
	}
	result.Port = extractInt(payload, "port")

	if result.FinalURL == "" {
		result.FinalURL = result.URL
	}
	if result.Target == "" {
		result.Target = result.URL
	}

	if parsedURL, err := url.Parse(result.URL); err == nil {
		if result.Scheme == "" {
			result.Scheme = parsedURL.Scheme
		}
		if result.Port == 0 {
			if port, err := strconv.Atoi(parsedURL.Port()); err == nil {
				result.Port = port
			}
		}
	}
	if result.Port == 0 {
		switch result.Scheme {
		case "https":
			result.Port = 443
		case "http":
			result.Port = 80
		}
	}
	return result, nil
}

// extractString tries a small set of candidate keys because httpx field names are not perfectly stable.
func extractString(payload map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func extractInt(payload map[string]json.RawMessage, keys ...string) int {
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok {
			continue
		}
		var integer int
		if err := json.Unmarshal(raw, &integer); err == nil {
			return integer
		}
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
				return parsed
			}
		}
	}
	return 0
}

// extractStringSlice accepts both proper JSON arrays and comma-separated strings from older/newer outputs.
func extractStringSlice(payload map[string]json.RawMessage, keys ...string) []string {
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok {
			continue
		}

		var values []string
		if err := json.Unmarshal(raw, &values); err == nil {
			return normalizeStringSlice(values)
		}

		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			return normalizeStringSlice(strings.Split(single, ","))
		}
	}
	return nil
}

func normalizeStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

// progressTracker keeps one shared snapshot for counters and heartbeat updates.
type progressTracker struct {
	mu         sync.Mutex
	startedAt  time.Time
	total      int
	reportFn   func(Progress)
	interval   time.Duration
	completed  int
	status2xx  int
	status3xx  int
	status4xx  int
	status5xx  int
	lastTarget string
	stopOnce   sync.Once
	stopCh     chan struct{}
}

func newProgressTracker(total int, reportFn func(Progress), interval time.Duration) *progressTracker {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &progressTracker{
		startedAt: time.Now(),
		total:     total,
		reportFn:  reportFn,
		interval:  interval,
		stopCh:    make(chan struct{}),
	}
}

// The heartbeat keeps long silent stretches from looking like a hung probe run.
func (t *progressTracker) start(ctx context.Context) {
	if t.reportFn == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(t.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.stopCh:
				return
			case <-ticker.C:
				t.report(true)
			}
		}
	}()
}

func (t *progressTracker) stop() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
	})
}

// Each parsed JSON line represents one completed probe result from httpx.
func (t *progressTracker) record(result Result) {
	if t == nil || t.reportFn == nil {
		return
	}

	t.mu.Lock()
	t.completed++
	t.lastTarget = strings.TrimSpace(result.FinalURL)
	if t.lastTarget == "" {
		t.lastTarget = strings.TrimSpace(result.URL)
	}
	if t.lastTarget == "" {
		t.lastTarget = strings.TrimSpace(result.Target)
	}
	switch {
	case result.StatusCode >= 200 && result.StatusCode <= 299:
		t.status2xx++
	case result.StatusCode >= 300 && result.StatusCode <= 399:
		t.status3xx++
	case result.StatusCode >= 400 && result.StatusCode <= 499:
		t.status4xx++
	case result.StatusCode >= 500 && result.StatusCode <= 599:
		t.status5xx++
	}
	t.mu.Unlock()

	t.report(false)
}

// report publishes the latest counters without tying formatting to the scanner loop.
func (t *progressTracker) report(heartbeat bool) {
	if t == nil || t.reportFn == nil {
		return
	}

	t.mu.Lock()
	progress := Progress{
		Completed:  t.completed,
		Total:      t.total,
		Status2xx:  t.status2xx,
		Status3xx:  t.status3xx,
		Status4xx:  t.status4xx,
		Status5xx:  t.status5xx,
		LastTarget: t.lastTarget,
		Elapsed:    time.Since(t.startedAt).Round(time.Second),
		Heartbeat:  heartbeat,
	}
	t.mu.Unlock()

	t.reportFn(progress)
}

// normalizeTargets deduplicates upfront so raw and automatic runs do not probe the same endpoint twice.
func normalizeTargets(targets []string) []string {
	out := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	slices.Sort(out)
	return out
}

// buildProbeArgs keeps raw and automatic probe runs aligned on the same httpx flags.
func buildProbeArgs(cfg Config) []string {
	args := []string{"-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects"}
	if resolvers := normalizeResolvers(cfg.Resolvers); len(resolvers) > 0 {
		args = append(args, "-r", strings.Join(resolvers, ","))
	}
	return append(args, "-json")
}

func runRaw(ctx context.Context, cfg Config, inputFile string, stdin io.Reader, stdout io.Writer, stderr io.Writer, outputBasePath string) error {
	args := []string{"-silent", "-status-code", "-title", "-tech-detect"}
	if resolvers := normalizeResolvers(cfg.Resolvers); len(resolvers) > 0 {
		args = append(args, "-r", strings.Join(resolvers, ","))
	}
	if outputBasePath != "" {
		args = append(args, "-output-all", outputBasePath)
	}
	if strings.TrimSpace(inputFile) != "" {
		args = append(args, "-list", inputFile)
	}

	cmd := exec.CommandContext(ctx, normalizeBinary(cfg.Binary), args...)
	if strings.TrimSpace(inputFile) == "" && stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("httpx failed: %w", err)
	}
	return nil
}

func normalizeResolvers(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// httpx has emitted either .json or .jsonl depending on version/build, so check both.
func locateJSONOutput(basePath string) (string, error) {
	candidates := []string{
		basePath + ".json",
		basePath + ".jsonl",
	}
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("httpx did not produce a json output file for %s\n", basePath)
}

func normalizeBinary(binary string) string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return "httpx"
	}
	return binary
}
