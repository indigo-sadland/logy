package resolver

import (
	"strings"
	"testing"
	"time"
)

func TestDNSXProgressTrackerRenderLineIncludesKeyFields(t *testing.T) {
	t.Parallel()

	tracker := newDNSXProgressTracker("/tmp/custom-dnsx", 42)
	tracker.startedAt = time.Now().Add(-3 * time.Second)
	tracker.resolved.Store(7)

	line := tracker.renderLine()
	if !strings.Contains(line, "resolver/custom-dnsx") {
		t.Fatalf("line=%q; want resolver/custom-dnsx", line)
	}
	if !strings.Contains(line, "hosts=42") {
		t.Fatalf("line=%q; want hosts=42", line)
	}
	if !strings.Contains(line, "resolved_lines=7") {
		t.Fatalf("line=%q; want resolved_lines=7", line)
	}
}

func TestDNSXProgressTrackerIncrementResolved(t *testing.T) {
	t.Parallel()

	tracker := newDNSXProgressTracker("dnsx", 2)
	tracker.incrementResolved()
	tracker.incrementResolved()

	if got := tracker.resolved.Load(); got != 2 {
		t.Fatalf("resolved=%d; want 2", got)
	}
}
