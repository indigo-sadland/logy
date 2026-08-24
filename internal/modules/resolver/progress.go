package resolver

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

type progressTracker struct {
	name      string
	hostCount int
	startedAt time.Time
	stopCh    chan struct{}
	stopped   atomic.Bool
	resolved  atomic.Int64
}

func newProgressTracker(name string, hostCount int) *progressTracker {
	return &progressTracker{
		name:      filepath.Base(name),
		hostCount: hostCount,
		startedAt: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

func (t *progressTracker) start() {
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

func (t *progressTracker) incrementResolved() {
	t.resolved.Add(1)
}

func (t *progressTracker) render() {
	if !shouldRenderResolverProgress() {
		return
	}
	_, _ = fmt.Fprint(os.Stdout, t.renderLine())
}

func (t *progressTracker) renderLine() string {
	frames := []string{"|", "/", "-", "\\"}
	elapsed := time.Since(t.startedAt).Round(time.Second)
	frame := frames[int(time.Since(t.startedAt)/(200*time.Millisecond))%len(frames)]
	return fmt.Sprintf("\r[*] resolver/%s %s elapsed=%s hosts=%d completed=%d",
		t.name,
		frame,
		elapsed,
		t.hostCount,
		t.resolved.Load(),
	)
}

func (t *progressTracker) finish() {
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
