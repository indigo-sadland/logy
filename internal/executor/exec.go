package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Run executes a CLI tool and streams its stdout line-by-line into out.
// stderr is buffered and included in the returned error on failure.
func Run(ctx context.Context, results chan<- string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			select {
			case results <- line:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		command := strings.TrimSpace(name + " " + strings.Join(args, " "))
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return fmt.Errorf("%s: %w", command, err)
		}
		return fmt.Errorf("%s: %w: %s", command, err, msg)
	}
	return nil
}
