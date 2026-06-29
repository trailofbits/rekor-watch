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

package notifications

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

func signingTestPayload() NotificationPayload {
	return NotificationPayload{
		Type:      NotificationEventTypeMatchCreated,
		Timestamp: "2026-05-21T12:00:00Z",
		Data: NotificationData{
			MonitoredValue: json.RawMessage(`{"type":"subject","subject":"target"}`),
			Entries:        []NotificationMatch{{Origin: "o", LogIndex: 7, UUID: "u"}},
		},
	}
}

// TestSend_withSecret_setsThreeHeaders verifies that, given an event ID and a
// secret, Send sets the three Standard Webhooks headers and the signature
// verifies over the exact bytes received by the server using the timestamp it
// advertised.
func TestSend_withSecret_setsThreeHeaders(t *testing.T) {
	const (
		eventID = "sub_5-batch_10-20"
		secret  = "whsec_dGVzdC1zZWNyZXQtMTIzNDU2Nzg5MDEy" // 24 bytes base64
	)

	var (
		gotID   string
		gotTS   string
		gotSig  string
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get("webhook-id")
		gotTS = r.Header.Get("webhook-timestamp")
		gotSig = r.Header.Get("webhook-signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender("", http.DefaultClient)
	if err := sender.Send(context.Background(), srv.URL, signingTestPayload(), eventID, secret); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if gotID != eventID {
		t.Errorf("webhook-id = %q, want %q", gotID, eventID)
	}
	if _, err := strconv.ParseInt(gotTS, 10, 64); err != nil {
		t.Errorf("webhook-timestamp = %q, want a unix seconds integer", gotTS)
	}

	ts, _ := strconv.ParseInt(gotTS, 10, 64)
	wh, err := standardwebhooks.NewWebhook(secret)
	if err != nil {
		t.Fatalf("NewWebhook() error: %v", err)
	}
	wantSig, err := wh.Sign(eventID, time.Unix(ts, 0), gotBody)
	if err != nil {
		t.Fatalf("recompute Sign() error: %v", err)
	}
	if gotSig != wantSig {
		t.Errorf("webhook-signature = %q, want %q (must verify over exact wire bytes)", gotSig, wantSig)
	}
}

// TestSend_emptySecret_omitsHeaders keeps unsigned delivery byte-identical to
// the pre-signing behavior: no signing headers when no secret is given.
func TestSend_emptySecret_omitsHeaders(t *testing.T) {
	var headersPresent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"webhook-id", "webhook-timestamp", "webhook-signature"} {
			if r.Header.Get(h) != "" {
				headersPresent = true
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender("", http.DefaultClient)
	if err := sender.Send(context.Background(), srv.URL, signingTestPayload(), "", ""); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	if headersPresent {
		t.Error("unsigned Send must not set any webhook-* signing headers")
	}
}
