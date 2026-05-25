package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/indigo-sadland/logy/internal/secrets"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const secretsPassphraseEnv = "LOGY_SECRETS_PASSPHRASE"

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage encrypted local secrets",
}

var secretsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Store encrypted secrets",
}

var secretsSetAnytypeCmd = &cobra.Command{
	Use:   "anytype",
	Short: "Store Anytype space id and API token",
	RunE: func(cmd *cobra.Command, args []string) error {
		passphrase, err := secretsPassphraseForWrite(defaultSecretsPath())
		if err != nil {
			return err
		}
		values, err := secrets.Load(defaultSecretsPath(), passphrase)
		if err != nil {
			return err
		}
		spaceID, err := promptLine("Anytype space id: ")
		if err != nil {
			return err
		}
		token, err := promptSecret("Anytype token: ")
		if err != nil {
			return err
		}
		spaceID = strings.TrimSpace(spaceID)
		token = strings.TrimSpace(token)
		if spaceID == "" {
			return fmt.Errorf("Anytype space id is required")
		}
		if token == "" {
			return fmt.Errorf("Anytype token is required")
		}
		values.Anytype = &secrets.AnytypeSecrets{SpaceID: spaceID, Token: token}
		if err := secrets.Save(defaultSecretsPath(), passphrase, values); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "stored Anytype secrets in %s\n", defaultSecretsPath())
		return nil
	},
}

var secretsSetBufferOverCmd = &cobra.Command{
	Use:   "bufferover",
	Short: "Store BufferOver API key",
	RunE: func(cmd *cobra.Command, args []string) error {
		passphrase, err := secretsPassphraseForWrite(defaultSecretsPath())
		if err != nil {
			return err
		}
		values, err := secrets.Load(defaultSecretsPath(), passphrase)
		if err != nil {
			return err
		}
		apiKey, err := promptSecret("BufferOver API key: ")
		if err != nil {
			return err
		}
		apiKey = strings.TrimSpace(apiKey)
		if apiKey == "" {
			return fmt.Errorf("BufferOver API key is required")
		}
		values.BufferOver = &secrets.BufferOverSecrets{APIKey: apiKey}
		if err := secrets.Save(defaultSecretsPath(), passphrase, values); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "stored BufferOver secrets in %s\n", defaultSecretsPath())
		return nil
	},
}

var secretsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which encrypted secrets are configured",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := defaultSecretsPath()
		if !secrets.Exists(path) {
			return json.NewEncoder(os.Stdout).Encode(struct {
				Path       string `json:"path"`
				Exists     bool   `json:"exists"`
				Anytype    bool   `json:"anytype"`
				BufferOver bool   `json:"bufferover"`
			}{Path: path})
		}
		passphrase, err := secretsPassphraseForRead()
		if err != nil {
			return err
		}
		values, err := secrets.Load(path, passphrase)
		if err != nil {
			return err
		}
		status := struct {
			Path       string `json:"path"`
			Exists     bool   `json:"exists"`
			Anytype    bool   `json:"anytype"`
			BufferOver bool   `json:"bufferover"`
		}{
			Path:       path,
			Exists:     true,
			Anytype:    values.Anytype != nil && values.Anytype.SpaceID != "" && values.Anytype.Token != "",
			BufferOver: values.BufferOver != nil && values.BufferOver.APIKey != "",
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	},
}

var secretsClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove encrypted local secrets",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := defaultSecretsPath()
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		fmt.Fprintf(os.Stdout, "removed %s\n", path)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(secretsCmd)
	secretsCmd.AddCommand(secretsSetCmd)
	secretsCmd.AddCommand(secretsStatusCmd)
	secretsCmd.AddCommand(secretsClearCmd)
	secretsSetCmd.AddCommand(secretsSetAnytypeCmd)
	secretsSetCmd.AddCommand(secretsSetBufferOverCmd)
}

// defaultSecretsPath returns the per-user encrypted secrets path.
func defaultSecretsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "secrets.json.age"
	}
	return filepath.Join(home, ".config", "logy", "secrets.json.age")
}

// secretsPassphraseForRead returns the passphrase from the environment or asks
// interactively when a command needs to decrypt existing secrets.
func secretsPassphraseForRead() (string, error) {
	if passphrase := strings.TrimSpace(os.Getenv(secretsPassphraseEnv)); passphrase != "" {
		return passphrase, nil
	}
	return promptSecret("Secrets passphrase: ")
}

// loadEncryptedSecretsIfNeeded decrypts the local secrets file only when it
// exists. Callers use it for lazy secret lookup after flags/env/config fallbacks.
func loadEncryptedSecretsIfNeeded() (secrets.Secrets, error) {
	path := defaultSecretsPath()
	if !secrets.Exists(path) {
		return secrets.Secrets{}, nil
	}
	passphrase, err := secretsPassphraseForRead()
	if err != nil {
		return secrets.Secrets{}, err
	}
	return secrets.Load(path, passphrase)
}

// secretsPassphraseForWrite asks for a new passphrase when creating the secrets
// file and asks once when updating an existing file.
func secretsPassphraseForWrite(path string) (string, error) {
	if passphrase := strings.TrimSpace(os.Getenv(secretsPassphraseEnv)); passphrase != "" {
		return passphrase, nil
	}
	if secrets.Exists(path) {
		return promptSecret("Secrets passphrase: ")
	}
	passphrase, err := promptSecret("New secrets passphrase: ")
	if err != nil {
		return "", err
	}
	confirm, err := promptSecret("Confirm secrets passphrase: ")
	if err != nil {
		return "", err
	}
	if passphrase != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}
	return passphrase, nil
}

// promptLine reads a visible single-line value from stdin.
func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

// promptSecret reads a hidden value from a terminal-backed stdin.
func promptSecret(label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("cannot prompt for secret because stdin is not a terminal")
	}
	fmt.Fprint(os.Stderr, label)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}
