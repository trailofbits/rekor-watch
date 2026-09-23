//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadWebhookSecretDeriver_requiresKeyFile fails closed when no key file is
// configured: the watcher must not start without a master key.
func TestLoadWebhookSecretDeriver_requiresKeyFile(t *testing.T) {
	if _, err := loadWebhookSecretDeriver(""); err == nil {
		t.Error("loadWebhookSecretDeriver(\"\") should fail closed when no key file is configured")
	}
}

// TestLoadWebhookSecretDeriver_loadsConfiguredKey loads a valid key file.
func TestLoadWebhookSecretDeriver_loadsConfiguredKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	d, err := loadWebhookSecretDeriver(path)
	if err != nil {
		t.Fatalf("loadWebhookSecretDeriver() error: %v", err)
	}
	if d == nil {
		t.Fatal("loadWebhookSecretDeriver() returned nil deriver")
	}
}
