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
	"strings"
	"testing"
)

func readEmbedded(t *testing.T, name string) string {
	t.Helper()
	data, err := content.ReadFile(name)
	if err != nil {
		t.Fatalf("failed to read embedded %s: %v", name, err)
	}
	return string(data)
}

// TestDashboard_hasRevealOnceContainer pins the reveal-once UI element the JS
// writes the freshly created/regenerated secret into.
func TestDashboard_hasRevealOnceContainer(t *testing.T) {
	html := readEmbedded(t, "templates/dashboard.html")
	if !strings.Contains(html, `id="secret-reveal"`) {
		t.Error("dashboard.html is missing the #secret-reveal reveal-once container")
	}
}

// TestDashboardJS_wiresRegenerateAndReveal pins the client wiring: a regenerate
// call against the new endpoint and a reveal-once display of the returned
// secret.
func TestDashboardJS_wiresRegenerateAndReveal(t *testing.T) {
	js := readEmbedded(t, "static/js/main.js")
	for _, want := range []string{"regenerate-secret", "showRevealedSecret", "won't be shown again"} {
		if !strings.Contains(js, want) {
			t.Errorf("main.js is missing %q wiring", want)
		}
	}
}
