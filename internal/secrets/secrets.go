// Package secrets stores local credentials in an age-encrypted JSON file.
//
// The package intentionally uses age passphrase mode instead of a desktop
// keyring so logy can work in SSH/headless sessions.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// Secrets is the top-level plaintext payload stored inside the encrypted file.
type Secrets struct {
	Anytype    *AnytypeSecrets    `json:"anytype,omitempty"`
	BufferOver *BufferOverSecrets `json:"bufferover,omitempty"`
}

// AnytypeSecrets contains the credentials needed for Anytype export.
type AnytypeSecrets struct {
	SpaceID string `json:"space_id"`
	Token   string `json:"token"`
}

// BufferOverSecrets contains the API key used by the BufferOver discovery provider.
type BufferOverSecrets struct {
	APIKey string `json:"api_key"`
}

// Load decrypts and decodes secrets from path. Missing or empty files return an
// empty Secrets value so callers can treat encrypted credentials as optional.
func Load(path string, passphrase string) (Secrets, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Secrets{}, nil
		}
		return Secrets{}, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Secrets{}, nil
	}
	plaintext, err := decrypt(raw, passphrase)
	if err != nil {
		return Secrets{}, err
	}
	var values Secrets
	if err := json.Unmarshal(plaintext, &values); err != nil {
		return Secrets{}, fmt.Errorf("decode secrets: %w", err)
	}
	return values, nil
}

// Save encrypts values and atomically writes them to path with owner-only file permissions.
func Save(path string, passphrase string, values Secrets) error {
	plaintext, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return err
	}
	ciphertext, err := encrypt(plaintext, passphrase)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secrets-*.age")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// Exists reports whether path points to an existing secrets file.
func Exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("secrets passphrase is required")
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	writer, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("secrets passphrase is required")
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
