package secrets

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadEncryptedSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json.age")
	want := Secrets{
		Anytype: &AnytypeSecrets{
			SpaceID: "space-id",
			Token:   "token-value",
		},
		BufferOver: &BufferOverSecrets{
			APIKey: "bufferover-key",
		},
	}

	if err := Save(path, "passphrase", want); err != nil {
		t.Fatalf("save secrets: %v", err)
	}
	got, err := Load(path, "passphrase")
	if err != nil {
		t.Fatalf("load secrets: %v", err)
	}
	if got.Anytype == nil || got.Anytype.SpaceID != "space-id" || got.Anytype.Token != "token-value" {
		t.Fatalf("anytype=%+v", got.Anytype)
	}
	if got.BufferOver == nil || got.BufferOver.APIKey != "bufferover-key" {
		t.Fatalf("bufferover=%+v", got.BufferOver)
	}
}

func TestLoadRejectsWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json.age")
	if err := Save(path, "right-passphrase", Secrets{
		Anytype: &AnytypeSecrets{SpaceID: "space-id", Token: "token-value"},
	}); err != nil {
		t.Fatalf("save secrets: %v", err)
	}
	if _, err := Load(path, "wrong-passphrase"); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}
