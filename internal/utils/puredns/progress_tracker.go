package puredns

import (
	"bufio"
	"fmt"
	"github.com/indigo-sadland/logy/internal/modules/discovery/models"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type purednsProgressTracker struct {
	wordlist  string
	wordCount int
	startedAt time.Time
	stopCh    chan struct{}
	stopped   atomic.Bool
}

func ProgressDoneFactory(toolCfg models.ToolConfig) func(string) func() {
	if strings.TrimSpace(toolCfg.WordlistFile) == "" || strings.TrimSpace(toolCfg.ResolversFile) == "" {
		return nil
	}

	return func(string) func() {
		tracker := newPurednsProgressTracker(toolCfg.WordlistFile)
		tracker.start()
		return tracker.finish
	}
}

func newPurednsProgressTracker(wordlist string) *purednsProgressTracker {
	return &purednsProgressTracker{
		wordlist:  wordlist,
		wordCount: CountNonEmptyLines(wordlist),
		startedAt: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

func (t *purednsProgressTracker) start() {
	if !shouldRenderProgress() {
		return
	}

	t.render()
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.render()
			case <-t.stopCh:
				return
			}
		}
	}()
}

func (t *purednsProgressTracker) render() {
	if !shouldRenderProgress() {
		return
	}

	frames := []string{"|", "/", "-", "\\"}
	elapsed := time.Since(t.startedAt).Round(time.Second)
	frame := frames[int(time.Since(t.startedAt)/(200*time.Millisecond))%len(frames)]
	msg := fmt.Sprintf("\r[*] puredns/bruteforce %s elapsed=%s", frame, elapsed)
	if t.wordCount > 0 {
		msg += fmt.Sprintf(" wordlist=%d", t.wordCount)
	}
	_, _ = fmt.Fprint(os.Stdout, msg)
}

func (t *purednsProgressTracker) finish() {
	if !shouldRenderProgress() {
		return
	}
	if t.stopped.CompareAndSwap(false, true) {
		close(t.stopCh)
	}
	_, _ = fmt.Fprint(os.Stdout, "\r\033[K")
}

func shouldRenderProgress() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func CountNonEmptyLines(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0
	}
	return count
}
