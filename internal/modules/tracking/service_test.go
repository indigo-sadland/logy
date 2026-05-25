package tracking

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInferExecMetadataFromFFUFArgs(t *testing.T) {
	t.Parallel()

	opts := inferExecMetadata(ExecOptions{
		Domain: "example.com",
	}, []string{
		"ffuf",
		"-u", "https://app.example.com/FUZZ",
		"-w", "words.txt",
	})

	if opts.Tool != "ffuf" {
		t.Fatalf("tool=%q; want ffuf", opts.Tool)
	}
	if opts.Target != "https://app.example.com/FUZZ" {
		t.Fatalf("target=%q; want https://app.example.com/FUZZ", opts.Target)
	}
	if opts.Wordlist != "words.txt" {
		t.Fatalf("wordlist=%q; want words.txt", opts.Wordlist)
	}
}

func TestInferExecMetadataKeepsExplicitValues(t *testing.T) {
	t.Parallel()

	opts := inferExecMetadata(ExecOptions{
		Domain:   "example.com",
		Target:   "manual-target",
		Tool:     "custom-tool",
		Wordlist: "manual-words.txt",
	}, []string{
		"ffuf",
		"-u=https://app.example.com/FUZZ",
		"-w=words.txt:FUZZ",
	})

	if opts.Tool != "custom-tool" {
		t.Fatalf("tool=%q; want custom-tool", opts.Tool)
	}
	if opts.Target != "manual-target" {
		t.Fatalf("target=%q; want manual-target", opts.Target)
	}
	if opts.Wordlist != "manual-words.txt" {
		t.Fatalf("wordlist=%q; want manual-words.txt", opts.Wordlist)
	}
}

func TestInferExecMetadataLeavesTargetEmptyWhenUnknown(t *testing.T) {
	t.Parallel()

	opts := inferExecMetadata(ExecOptions{
		Domain: "example.com",
	}, []string{"echo", "hello"})

	if opts.Target != "" {
		t.Fatalf("target=%q; want empty", opts.Target)
	}
}

func TestInferExecMetadataFromSSHArgs(t *testing.T) {
	t.Parallel()

	opts := inferExecMetadata(ExecOptions{
		Domain: "example.com",
	}, []string{"ssh", "root@103.80.86.124"})

	if opts.Tool != "ssh" {
		t.Fatalf("tool=%q; want ssh", opts.Tool)
	}
	if opts.Target != "103.80.86.124" {
		t.Fatalf("target=%q; want 103.80.86.124", opts.Target)
	}
}

func TestInferExecMetadataFromRemoteCopyArgs(t *testing.T) {
	t.Parallel()

	opts := inferExecMetadata(ExecOptions{
		Domain: "example.com",
	}, []string{"scp", "notes.txt", "admin@app.internal.local:/tmp/"})

	if opts.Target != "app.internal.local" {
		t.Fatalf("target=%q; want app.internal.local", opts.Target)
	}
}

func TestInferExecMetadataFromGenericIPArgs(t *testing.T) {
	t.Parallel()

	opts := inferExecMetadata(ExecOptions{
		Domain: "example.com",
	}, []string{"nmap", "-Pn", "10.20.30.40"})

	if opts.Target != "10.20.30.40" {
		t.Fatalf("target=%q; want 10.20.30.40", opts.Target)
	}
}

func TestBuildCommandTranscriptUsesRunIDAndUTCStartTime(t *testing.T) {
	home := setTestHome(t)
	startedAt := time.Date(2026, 5, 24, 14, 3, 2, 0, time.FixedZone("MSK", 3*60*60))

	service := Service{TranscriptDir: filepath.Join(home, ".config", "logy", "transcripts")}
	transcript := service.buildCommandTranscript(42, startedAt)
	wantDir := filepath.Join(home, ".config", "logy", "transcripts")
	if filepath.Dir(transcript.Path) != wantDir {
		t.Fatalf("dir=%q; want %q", filepath.Dir(transcript.Path), wantDir)
	}
	if !strings.HasSuffix(transcript.Path, "20260524T110302Z-run-42.typescript") {
		t.Fatalf("path=%q; unexpected filename", transcript.Path)
	}
	if transcript.Mode != transcriptModePTY {
		t.Fatalf("mode=%q; want %q", transcript.Mode, transcriptModePTY)
	}
}

func setTestHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}
