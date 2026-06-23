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
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"

	"github.com/sigstore/rekor-monitor/cmd/rekor_watch/notifications"
	"github.com/sigstore/rekor-monitor/pkg/store/sqlite"
)

func TestWebhookEventID_formatsAsBatchMinMax(t *testing.T) {
	if got := webhookEventID(5, 10, 20); got != "sub_5-batch_10-20" {
		t.Errorf("webhookEventID(5,10,20) = %q, want %q", got, "sub_5-batch_10-20")
	}
}

func TestWebhookEventID_stableForSameBatch(t *testing.T) {
	if webhookEventID(1, 3, 9) != webhookEventID(1, 3, 9) {
		t.Error("webhookEventID must be stable for the same batch range")
	}
}

func TestWebhookEventID_changesWhenMaxGrows(t *testing.T) {
	if webhookEventID(1, 3, 9) == webhookEventID(1, 3, 10) {
		t.Error("webhookEventID must change when the batch's max match ID grows")
	}
}

func notifyTestDeriver(t *testing.T) *notifications.WebhookSecretDeriver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master.key")
	key := base64.StdEncoding.EncodeToString([]byte("dispatch-master-key-0123456789ab")) // 32 bytes
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	d, err := notifications.LoadWebhookSecretDeriver(path)
	if err != nil {
		t.Fatalf("failed to load deriver: %v", err)
	}
	return d
}

// firstSubscription returns the single subscription seeded by insertSubAndMatch.
func firstSubscription(t *testing.T, s *sqlite.Store) (id, userID int64, version int) {
	t.Helper()
	subs, err := s.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("ListSubscriptions() error: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	return subs[0].ID, subs[0].UserID, subs[0].WebhookSecretVersion
}

type capturedDelivery struct {
	id   string
	ts   string
	sig  string
	body []byte
}

func captureSink(t *testing.T, into *capturedDelivery) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		into.id = r.Header.Get("webhook-id")
		into.ts = r.Header.Get("webhook-timestamp")
		into.sig = r.Header.Get("webhook-signature")
		into.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
}

// TestSendNotifications_SignsWithDerivedSecret is the end-to-end property: a
// dispatched webhook carries a valid Standard Webhooks signature that a
// subscriber can verify using the secret derived from the same master key.
func TestSendNotifications_SignsWithDerivedSecret(t *testing.T) {
	var got capturedDelivery
	srv := captureSink(t, &got)
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)
	subID, _, version := firstSubscription(t, s)
	deriver := notifyTestDeriver(t)

	if err := sendNotifications(context.Background(), s, time.Now(), "test-ua", http.DefaultClient, nil, nil, deriver); err != nil {
		t.Fatalf("sendNotifications() error: %v", err)
	}

	if got.id == "" || got.sig == "" {
		t.Fatalf("expected signing headers, got id=%q sig=%q", got.id, got.sig)
	}

	ts, err := strconv.ParseInt(got.ts, 10, 64)
	if err != nil {
		t.Fatalf("webhook-timestamp = %q, want unix seconds: %v", got.ts, err)
	}

	secret, err := deriver.Secret(subID, version)
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	wantSig := recomputeSig(t, secret, got.id, ts, got.body)
	if got.sig != wantSig {
		t.Errorf("delivered signature = %q, want %q (verifiable with the revealed secret)", got.sig, wantSig)
	}
}

// recomputeSig reproduces the Standard Webhooks v1 signature a subscriber would
// compute, using the same library, so tests can assert dispatch signed the
// exact wire bytes under the expected secret.
func recomputeSig(t *testing.T, secret, id string, ts int64, body []byte) string {
	t.Helper()
	wh, err := standardwebhooks.NewWebhook(secret)
	if err != nil {
		t.Fatalf("NewWebhook() error: %v", err)
	}
	sig, err := wh.Sign(id, time.Unix(ts, 0), body)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	return sig
}

// TestSendNotifications_UsesCurrentSecretVersion ensures dispatch signs with the
// secret for the subscription's CURRENT version, so a regenerate takes effect
// on the next delivery.
func TestSendNotifications_UsesCurrentSecretVersion(t *testing.T) {
	var got capturedDelivery
	srv := captureSink(t, &got)
	defer srv.Close()

	s := setupTestStore(t)
	insertSubAndMatch(t, s, srv.URL)
	subID, userID, _ := firstSubscription(t, s)

	newVersion, err := s.RegenerateWebhookSecret(context.Background(), subID, userID)
	if err != nil {
		t.Fatalf("RegenerateWebhookSecret() error: %v", err)
	}

	deriver := notifyTestDeriver(t)
	if err := sendNotifications(context.Background(), s, time.Now(), "test-ua", http.DefaultClient, nil, nil, deriver); err != nil {
		t.Fatalf("sendNotifications() error: %v", err)
	}

	ts, err := strconv.ParseInt(got.ts, 10, 64)
	if err != nil {
		t.Fatalf("webhook-timestamp = %q, want unix seconds: %v", got.ts, err)
	}

	// Signature must verify under the NEW version's secret, not version 1's.
	newSecret, _ := deriver.Secret(subID, newVersion)
	wantSig := recomputeSig(t, newSecret, got.id, ts, got.body)
	if got.sig != wantSig {
		t.Errorf("delivered signature does not match current (v%d) secret", newVersion)
	}

	oldSecret, _ := deriver.Secret(subID, 1)
	oldSig := recomputeSig(t, oldSecret, got.id, ts, got.body)
	if got.sig == oldSig {
		t.Error("delivered signature still matches the retired version-1 secret")
	}
}
