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

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
	"github.com/sigstore/rekor-monitor/pkg/store/sqlite"
)

// createSecretResponse decodes the reveal-once secret from a create/regenerate
// response body. The subscription fields (if any) are ignored.
type createSecretResponse struct {
	Secret string `json:"secret"`
}

func webhookBody(name, fingerprint, url string) string {
	return fmt.Sprintf(
		`{"name":%q,"monitoredValue":{"type":"fingerprint","fingerprint":%q},"notificationType":"webhook","webhookURL":%q}`,
		name, fingerprint, url,
	)
}

// createWebhookSub posts a webhook subscription and returns the response.
func createWebhookSub(t *testing.T, mux *http.ServeMux, session, name, fingerprint, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(webhookBody(name, fingerprint, url)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// mustSaveEmailSub saves an email subscription directly in the store and
// returns its ID.
func mustSaveEmailSub(t *testing.T, s *sqlite.Store, userID int64, name string) int64 {
	t.Helper()
	sub := &store.Subscription{
		UserID:           userID,
		Name:             name,
		MonitoredValue:   identity.FingerprintValue{Fingerprint: "EMAILSUB"},
		NotificationType: store.NotificationTypeEmail,
	}
	if err := s.SaveSubscription(context.Background(), sub); err != nil {
		t.Fatalf("failed to save email subscription: %v", err)
	}
	return sub.ID
}

func TestCreateWebhookSubscription_returnsDerivedSecretOnce(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "wh-create@example.com", "wh-create-session")
	mux := testMux(t, srv)

	w := createWebhookSub(t, mux, "wh-create-session", "sub1", "ABCD", "https://hooks.example.com/x")
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ID     int64  `json:"ID"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !strings.HasPrefix(resp.Secret, "whsec_") {
		t.Errorf("create response secret = %q, want a 'whsec_' prefix", resp.Secret)
	}

	// The revealed secret must be the version-1 derivation — the same one
	// dispatch will sign with. (A stale in-memory version would silently
	// reveal a secret that never matches delivered signatures.)
	want, err := testSecretDeriver(t).Secret(resp.ID, 1, "https://hooks.example.com/x")
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	if resp.Secret != want {
		t.Errorf("revealed secret = %q, want the version-1 secret %q", resp.Secret, want)
	}
}

func TestCreateEmailSubscription_omitsSecret(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "email-create@example.com", "email-create-session")
	mux := testMux(t, srv)

	body := `{"name":"emailsub","monitoredValue":{"type":"fingerprint","fingerprint":"EEEE"},"notificationType":"email"}`
	req := httptest.NewRequest(http.MethodPost, routeAPISubscriptions, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "email-create-session"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp createSecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Secret != "" {
		t.Errorf("email subscription create returned a secret %q, want none", resp.Secret)
	}
}

// TestCreateWebhookSubscription_distinctUsersSameURLDistinctSecrets is the core
// safety property: two users pointing at the SAME webhook URL must receive
// different signing secrets so one cannot forge deliveries for the other.
func TestCreateWebhookSubscription_distinctUsersSameURLDistinctSecrets(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "alice@example.com", "alice-session")
	createTestUserSession(t, s, "bob@example.com", "bob-session")
	mux := testMux(t, srv)

	const sharedURL = "https://hooks.example.com/shared"
	aliceResp := createWebhookSub(t, mux, "alice-session", "alice-sub", "AAAA", sharedURL)
	bobResp := createWebhookSub(t, mux, "bob-session", "bob-sub", "BBBB", sharedURL)

	var a, b createSecretResponse
	if err := json.Unmarshal(aliceResp.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode alice: %v", err)
	}
	if err := json.Unmarshal(bobResp.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode bob: %v", err)
	}
	if a.Secret == "" || b.Secret == "" {
		t.Fatalf("expected both secrets set, got alice=%q bob=%q", a.Secret, b.Secret)
	}
	if a.Secret == b.Secret {
		t.Errorf("two users sharing %q got the same secret %q; must differ", sharedURL, a.Secret)
	}
}

// updateWebhookSub PUTs a webhook subscription and returns the response.
func updateWebhookSub(t *testing.T, mux *http.ServeMux, session string, id int64, name, fingerprint, url string) *httptest.ResponseRecorder {
	t.Helper()
	target := fmt.Sprintf("/api/subscriptions/%d", id)
	req := httptest.NewRequest(http.MethodPut, target, strings.NewReader(webhookBody(name, fingerprint, url)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestUpdateSubscription_urlChangeRevealsRotatedSecret(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "wh-update@example.com", "wh-update-session")
	mux := testMux(t, srv)

	createResp := createWebhookSub(t, mux, "wh-update-session", "upsub", "ABCD", "https://hooks.example.com/old")
	var created struct {
		ID     int64  `json:"ID"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(createResp.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	w := updateWebhookSub(t, mux, "wh-update-session", created.ID, "upsub", "ABCD", "https://hooks.example.com/new")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var updated createSecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if updated.Secret == "" {
		t.Fatal("URL change did not reveal a rotated secret")
	}
	if updated.Secret == created.Secret {
		t.Errorf("URL change returned the same secret as create %q; must differ", updated.Secret)
	}

	// The rotated secret must be the version-2 derivation for the NEW URL — the
	// one dispatch will sign with after the change.
	want, err := testSecretDeriver(t).Secret(created.ID, 2, "https://hooks.example.com/new")
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	if updated.Secret != want {
		t.Errorf("rotated secret = %q, want the version-2 new-URL secret %q", updated.Secret, want)
	}
}

func TestUpdateSubscription_noURLChangeOmitsSecret(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "wh-noop@example.com", "wh-noop-session")
	mux := testMux(t, srv)

	createResp := createWebhookSub(t, mux, "wh-noop-session", "noopsub", "ABCD", "https://hooks.example.com/keep")
	var created struct {
		ID int64 `json:"ID"`
	}
	if err := json.Unmarshal(createResp.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Rename only, same URL: nothing rotates, so no secret is revealed.
	w := updateWebhookSub(t, mux, "wh-noop-session", created.ID, "noopsub-renamed", "ABCD", "https://hooks.example.com/keep")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var updated createSecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if updated.Secret != "" {
		t.Errorf("non-URL update returned a secret %q, want none", updated.Secret)
	}
}

func regenerate(t *testing.T, mux *http.ServeMux, session string, id int64) *httptest.ResponseRecorder {
	t.Helper()
	url := fmt.Sprintf("/api/subscriptions/%d/regenerate-secret", id)
	req := httptest.NewRequest(http.MethodPost, url, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestRegenerateSecret_returnsNewSecret(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "regen@example.com", "regen-session")
	mux := testMux(t, srv)

	createResp := createWebhookSub(t, mux, "regen-session", "regensub", "CCCC", "https://hooks.example.com/r")
	var created struct {
		ID     int64  `json:"ID"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(createResp.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	w := regenerate(t, mux, "regen-session", created.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var regen createSecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &regen); err != nil {
		t.Fatalf("decode regen: %v", err)
	}
	if !strings.HasPrefix(regen.Secret, "whsec_") {
		t.Errorf("regenerate secret = %q, want 'whsec_' prefix", regen.Secret)
	}
	if regen.Secret == created.Secret {
		t.Errorf("regenerate returned the same secret as create %q; must differ (hard cutover)", regen.Secret)
	}

	// Regenerate must bump to exactly version 2 — the secret dispatch will sign
	// with next. A wrong-version bump would still "differ" from create and slip
	// past the check above.
	want, err := testSecretDeriver(t).Secret(created.ID, 2, "https://hooks.example.com/r")
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	if regen.Secret != want {
		t.Errorf("regenerated secret = %q, want the version-2 secret %q", regen.Secret, want)
	}
}

func TestRegenerateSecret_rejectsEmailSubscription(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	user := createTestUserSession(t, s, "regen-email@example.com", "regen-email-session")
	mux := testMux(t, srv)

	// Create an email subscription directly in the store.
	emailSub := mustSaveEmailSub(t, s, user.ID, "emailsub")

	w := regenerate(t, mux, "regen-email-session", emailSub)
	if w.Code != http.StatusBadRequest {
		t.Errorf("regenerate on email sub = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestRegenerateSecret_rejectsNonOwner(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "regen-owner@example.com", "regen-owner-session")
	createTestUserSession(t, s, "regen-attacker@example.com", "regen-attacker-session")
	mux := testMux(t, srv)

	createResp := createWebhookSub(t, mux, "regen-owner-session", "ownsub", "DDDD", "https://hooks.example.com/own")
	var created struct {
		ID int64 `json:"ID"`
	}
	if err := json.Unmarshal(createResp.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	w := regenerate(t, mux, "regen-attacker-session", created.ID)
	if w.Code != http.StatusNotFound {
		t.Errorf("regenerate by non-owner = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestRegenerateSecret_missingSubscription(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "regen-missing@example.com", "regen-missing-session")
	mux := testMux(t, srv)

	w := regenerate(t, mux, "regen-missing-session", 999999)
	if w.Code != http.StatusNotFound {
		t.Errorf("regenerate missing sub = %d, want 404: %s", w.Code, w.Body.String())
	}
}

// TestSubscriptionListJSON_hasNoSecret guards against leaking the internal
// version counter (and certainly any secret) through the list API.
func TestSubscriptionListJSON_hasNoSecret(t *testing.T) {
	srv, s, _ := setupTestServer(t)
	createTestUserSession(t, s, "list-secret@example.com", "list-secret-session")
	mux := testMux(t, srv)

	createWebhookSub(t, mux, "list-secret-session", "listsub", "FFFF", "https://hooks.example.com/l")

	req := httptest.NewRequest(http.MethodGet, routeAPISubscriptions, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "list-secret-session"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, banned := range []string{"secret", "whsec_", "WebhookSecretVersion", "webhook_secret_version"} {
		if strings.Contains(body, banned) {
			t.Errorf("subscription list JSON leaks %q: %s", banned, body)
		}
	}
}
