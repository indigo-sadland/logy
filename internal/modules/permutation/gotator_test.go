package permutation

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGenerateNormalizesDedupesAndFiltersDomain(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	permsPath := filepath.Join(dir, "perms.txt")
	if err := os.WriteFile(permsPath, []byte("dev\napi\n"), 0o755); err != nil {
		t.Fatalf("write permutations file: %v", err)
	}

	binaryPath := filepath.Join(dir, "fake-gotator.sh")
	script := `#!/bin/sh
cat <<'EOF'
Dev.api.example.com
*.test.example.com
test.example.com.
outside.net
EOF
`
	if err := os.WriteFile(binaryPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake gotator: %v", err)
	}

	got, err := Generate(context.Background(), []string{"api.example.com", "www.example.com"}, "example.com", Config{
		Binary:           binaryPath,
		PermutationsFile: permsPath,
		Depth:            1,
		Numbers:          10,
		MinDup:           true,
		MD:               true,
	}, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	want := []string{"dev.api.example.com", "test.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("got=%v; want %v", got, want)
	}
}

func TestGenerateRequiresPermutationsFile(t *testing.T) {
	t.Parallel()

	_, err := Generate(context.Background(), []string{"api.example.com"}, "example.com", Config{}, nil)
	if err == nil {
		t.Fatal("expected error when permutations file is missing")
	}
}
