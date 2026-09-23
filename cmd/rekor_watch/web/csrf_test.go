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
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
)

func TestRegenerateSecret_CrossOriginProtection(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		fetchSite  string
		noSession  bool
		wantStatus int
	}{
		{name: "same origin", origin: "https://watch.example.com", fetchSite: "same-origin", wantStatus: http.StatusOK},
		{name: "same origin fallback", origin: "https://watch.example.com", wantStatus: http.StatusOK},
		{name: "non-browser client", wantStatus: http.StatusOK},
		{name: "authentication still required", fetchSite: "same-origin", noSession: true, wantStatus: http.StatusUnauthorized},
		{name: "sibling subdomain", origin: "https://attacker.example.com", fetchSite: "same-site", wantStatus: http.StatusForbidden},
		{name: "same site without origin", fetchSite: "same-site", wantStatus: http.StatusForbidden},
		{name: "cross site", origin: "https://attacker.test", fetchSite: "cross-site", wantStatus: http.StatusForbidden},
		{name: "sibling origin fallback", origin: "https://attacker.example.com", wantStatus: http.StatusForbidden},
		{name: "cross origin fallback", origin: "https://attacker.test", wantStatus: http.StatusForbidden},
		{name: "different port fallback", origin: "https://watch.example.com:8443", wantStatus: http.StatusForbidden},
		{name: "opaque origin", origin: "null", wantStatus: http.StatusForbidden},
		{name: "malformed origin", origin: "://invalid", wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, db, _ := setupTestServer(t)
			user := createTestUserSession(t, db, "owner@example.com", "owner-session")
			sub := &store.Subscription{
				UserID:           user.ID,
				Name:             "webhook",
				MonitoredValue:   identity.FingerprintValue{Fingerprint: "ABCD"},
				NotificationType: store.NotificationTypeWebhook,
				WebhookURL:       "https://hooks.example.com/notify",
			}
			ctx := context.Background()
			if err := db.SaveSubscription(ctx, sub); err != nil {
				t.Fatal(err)
			}

			// A cross-origin HTML form can issue this POST without a preflight.
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("https://watch.example.com/api/subscriptions/%d/regenerate-secret", sub.ID), nil)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			if !tt.noSession {
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "owner-session"})
			}
			w := httptest.NewRecorder()
			testMux(t, srv).ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			wantVersion := sub.WebhookSecretVersion
			if tt.wantStatus == http.StatusOK {
				wantVersion++
				var response secretResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				wantSecret, err := srv.secretDeriver.Secret(sub.ID, wantVersion)
				if err != nil {
					t.Fatal(err)
				}
				if response.Secret != wantSecret {
					t.Error("response secret does not match the rotated version")
				}
			}
			subs, err := db.ListSubscriptionsByUser(ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(subs) != 1 {
				t.Fatalf("subscription count = %d, want 1", len(subs))
			}
			if subs[0].WebhookSecretVersion != wantVersion {
				t.Errorf("persisted version = %d, want %d", subs[0].WebhookSecretVersion, wantVersion)
			}
		})
	}
}

func TestCrossOriginProtection_AllMutatingRoutes(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, routeLogin},
		{http.MethodPost, routeAuthCallback},
		{http.MethodPost, routeLogout},
		{http.MethodPost, routeAPISubscriptions},
		{http.MethodPut, "/api/subscriptions/1"},
		{http.MethodDelete, "/api/subscriptions/1"},
		{http.MethodPost, "/api/subscriptions/1/enable"},
		{http.MethodPost, "/api/subscriptions/1/disable"},
		{http.MethodPost, "/api/subscriptions/1/regenerate-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			srv, db, _ := setupTestServer(t)
			createTestUserSession(t, db, "owner@example.com", "owner-session")
			handler := testMux(t, srv)
			req := httptest.NewRequest(tt.method, "https://watch.example.com"+tt.path, nil)
			req.Header.Set("Origin", "https://attacker.example.com")
			req.Header.Set("Sec-Fetch-Site", "same-site")
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "owner-session"})
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", w.Code)
			}
		})
	}
}
