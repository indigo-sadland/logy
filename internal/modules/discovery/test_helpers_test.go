package discovery

import (
	"github.com/indigo-sadland/logy/internal/utils/puredns"
)

func purednsProgressDoneFactory(cfg ToolConfig) func(string) func() {
	factory := puredns.ProgressDoneFactory(cfg)
	if factory == nil {
		return nil
	}
	return func(domain string) func() {
		done := factory(domain)
		if done == nil {
			return nil
		}
		return done
	}
}

func countNonEmptyLines(path string) int {
	return puredns.CountNonEmptyLines(path)
}
