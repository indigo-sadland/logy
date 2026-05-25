package resolver

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

type dnsxProgressTracker struct {
	binary    string
	hostCount int
	startedAt time.Time
	stopCh    chan struct{}
	stopped   atomic.Bool
	resolved  atomic.Int64
}

func newDNSXProgressTracker(binary string, hostCount int) *dnsxProgressTracker {
	return &dnsxProgressTracker{
		binary:    filepath.Base(binary),
		hostCount: hostCount,
		startedAt: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

func (t *dnsxProgressTracker) start() {
	if !shouldRenderResolverProgress() {
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

func (t *dnsxProgressTracker) incrementResolved() {
	t.resolved.Add(1)
}

func (t *dnsxProgressTracker) render() {
	if !shouldRenderResolverProgress() {
		return
	}
	_, _ = fmt.Fprint(os.Stdout, t.renderLine())
}

func (t *dnsxProgressTracker) renderLine() string {
	frames := []string{"|", "/", "-", "\\"}
	elapsed := time.Since(t.startedAt).Round(time.Second)
	frame := frames[int(time.Since(t.startedAt)/(200*time.Millisecond))%len(frames)]
	return fmt.Sprintf("\r[*] resolver/%s %s elapsed=%s hosts=%d resolved_lines=%d",
		t.binary,
		frame,
		elapsed,
		t.hostCount,
		t.resolved.Load(),
	) // 'resolved_lines' is how many result lines dnsx has emitted so far, not full  host completion across resolved and unresolved names
}

func (t *dnsxProgressTracker) finish() {
	if !shouldRenderResolverProgress() {
		return
	}
	if t.stopped.CompareAndSwap(false, true) {
		close(t.stopCh)
	}
	_, _ = fmt.Fprint(os.Stdout, "\r\033[K")
}

func shouldRenderResolverProgress() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
