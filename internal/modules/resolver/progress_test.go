package resolver

import (
	"strings"
	"testing"
	"time"
)

func TestProgressTrackerRenderLineIncludesKeyFields(t *testing.T) {
	t.Parallel()

	tracker := newProgressTracker("miekg-dns", 42)
	tracker.startedAt = time.Now().Add(-3 * time.Second)
	tracker.resolved.Store(7)

	line := tracker.renderLine()
	if !strings.Contains(line, "resolver/miekg-dns") {
		t.Fatalf("line=%q; want resolver/miekg-dns", line)
	}
	if !strings.Contains(line, "hosts=42") {
		t.Fatalf("line=%q; want hosts=42", line)
	}
	if !strings.Contains(line, "completed=7") {
		t.Fatalf("line=%q; want completed=7", line)
	}
}

func TestProgressTrackerIncrementResolved(t *testing.T) {
	t.Parallel()

	tracker := newProgressTracker("miekg-dns", 2)
	tracker.incrementResolved()
	tracker.incrementResolved()

	if got := tracker.resolved.Load(); got != 2 {
		t.Fatalf("resolved=%d; want 2", got)
	}
}
