package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/indigo-sadland/logy/internal/storage"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type portscanPickCandidate struct {
	Label string
	Kind  string
	IPs   []string
}

func buildPortscanPickCandidates(targets []storage.SavedScanTarget) []portscanPickCandidate {
	candidates := make([]portscanPickCandidate, 0, len(targets))
	for _, target := range targets {
		if strings.TrimSpace(target.Label) == "" || len(target.IPs) == 0 {
			continue
		}
		candidates = append(candidates, portscanPickCandidate{
			Label: target.Label,
			Kind:  target.Kind,
			IPs:   target.IPs,
		})
	}
	return candidates
}

func filterPortscanPickCandidates(candidates []portscanPickCandidate, query string) []portscanPickCandidate {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return candidates
	}
	filtered := make([]portscanPickCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.Contains(strings.ToLower(candidate.Label), query) {
			filtered = append(filtered, candidate)
			continue
		}
		if strings.Contains(strings.ToLower(strings.Join(candidate.IPs, ",")), query) {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func isInteractiveTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func runPortscanPicker(in *os.File, out io.Writer, domain string, candidates []portscanPickCandidate) (portscanPickCandidate, error) {
	if len(candidates) == 0 {
		return portscanPickCandidate{}, errors.New("no candidates available")
	}

	fd := int(in.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return portscanPickCandidate{}, fmt.Errorf("enable raw terminal mode: %w", err)
	}
	defer func() {
		_ = term.Restore(fd, oldState)
	}()

	reader := bufio.NewReader(in)
	query := ""
	cursor := 0

	for {
		filtered := filterPortscanPickCandidates(candidates, query)
		if cursor >= len(filtered) {
			cursor = max(0, len(filtered)-1)
		}
		renderPortscanPicker(out, domain, query, cursor, filtered)

		key, err := reader.ReadByte()
		if err != nil {
			return portscanPickCandidate{}, err
		}

		switch key {
		case 3:
			clearPortscanPicker(out)
			return portscanPickCandidate{}, errors.New("portscan pick canceled")
		case 'k':
			if cursor > 0 {
				cursor--
			}
		case 'j':
			if cursor+1 < len(filtered) {
				cursor++
			}
		case 13, 10:
			if len(filtered) == 0 {
				continue
			}
			clearPortscanPicker(out)
			return filtered[cursor], nil
		case 127, 8:
			if len(query) > 0 {
				query = query[:len(query)-1]
				cursor = 0
			}
		case 27:
			next, err := reader.ReadByte()
			if err != nil {
				clearPortscanPicker(out)
				return portscanPickCandidate{}, errors.New("portscan pick canceled")
			}
			if next != '[' {
				clearPortscanPicker(out)
				return portscanPickCandidate{}, errors.New("portscan pick canceled")
			}
			arrow, err := reader.ReadByte()
			if err != nil {
				return portscanPickCandidate{}, err
			}
			switch arrow {
			case 'A':
				if cursor > 0 {
					cursor--
				}
			case 'B':
				if cursor+1 < len(filtered) {
					cursor++
				}
			}
		default:
			if key >= 32 && key <= 126 {
				query += string(key)
				cursor = 0
			}
		}
	}
}

func renderPortscanPicker(out io.Writer, domain string, query string, cursor int, candidates []portscanPickCandidate) {
	clearPortscanPicker(out)
	_, _ = fmt.Fprintf(out, "Select target from %s\r\n", domain)
	_, _ = fmt.Fprintf(out, "Filter: %s\r\n\r\n", query)
	if len(candidates) == 0 {
		_, _ = io.WriteString(out, "  No matching targets.\r\n")
	} else {
		limit := min(len(candidates), 10)
		for i := 0; i < limit; i++ {
			prefix := "  "
			if i == cursor {
				prefix = "> "
			}
			kindSuffix := ""
			if candidates[i].Kind == "ip" {
				kindSuffix = " [ip-only]"
			}
			_, _ = fmt.Fprintf(out, "%s%s%s [%s]\r\n", prefix, candidates[i].Label, kindSuffix, strings.Join(candidates[i].IPs, ", "))
		}
		if len(candidates) > limit {
			_, _ = fmt.Fprintf(out, "\r\n  ... %d more match(es)\r\n", len(candidates)-limit)
		}
	}
	_, _ = io.WriteString(out, "\r\nType to filter, Up/Down or j/k to move, Enter to scan, Ctrl+C to cancel.\r\n")
}

func clearPortscanPicker(out io.Writer) {
	_, _ = io.WriteString(out, "\033[H\033[2J")
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
