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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readEmbedded returns the contents of an embedded template/static file.
func readEmbedded(t *testing.T, name string) string {
	t.Helper()
	data, err := content.ReadFile(name)
	if err != nil {
		t.Fatalf("failed to read embedded %s: %v", name, err)
	}
	return string(data)
}

// TestDocsPage_servesVerificationGuide checks the public docs page renders and
// covers the verification essentials a subscriber needs.
func TestDocsPage_servesVerificationGuide(t *testing.T) {
	srv, _, _ := setupTestServer(t)
	mux := testMux(t, srv)

	req := httptest.NewRequest(http.MethodGet, "/docs/webhooks", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /docs/webhooks = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"webhook-signature",
		"webhook-timestamp",
		"webhook-id",
		"HMAC",
		"whsec_",
		"Standard Webhooks",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("docs page missing %q", want)
		}
	}
}

// TestDashboard_hasVerifyDocsLink pins the helper link from the subscription
// form to the verification docs.
func TestDashboard_hasVerifyDocsLink(t *testing.T) {
	html := readEmbedded(t, "templates/dashboard.html")
	if !strings.Contains(html, "/docs/webhooks") {
		t.Error("dashboard.html is missing a link to /docs/webhooks")
	}
}
