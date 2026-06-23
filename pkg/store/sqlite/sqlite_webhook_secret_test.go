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

package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/sigstore/rekor-monitor/pkg/identity"
	"github.com/sigstore/rekor-monitor/pkg/store"
)

// TestSaveSubscription_DefaultsWebhookSecretVersionTo1 pins the migration
// default: a freshly created subscription reads back at version 1 so its
// secret can be derived immediately.
func TestSaveSubscription_DefaultsWebhookSecretVersionTo1(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, userID := createTestSubscription(ctx, t, s)

	subs, err := s.ListSubscriptionsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListSubscriptionsByUser() error: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != subID {
		t.Fatalf("expected the one created subscription, got %d", len(subs))
	}
	if subs[0].WebhookSecretVersion != 1 {
		t.Errorf("WebhookSecretVersion = %d, want 1", subs[0].WebhookSecretVersion)
	}
}

// TestSaveSubscription_PopulatesWebhookSecretVersion pins that SaveSubscription
// reflects the persisted version (1) back onto the in-memory struct, so a
// caller that derives the reveal-once secret right after create uses the same
// version dispatch will sign with. Without this the create-revealed secret
// (version 0) would not match delivered signatures (version 1).
func TestSaveSubscription_PopulatesWebhookSecretVersion(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	user := &store.User{Email: "save-version@example.com"}
	if err := s.SaveUser(ctx, user); err != nil {
		t.Fatalf("SaveUser() error: %v", err)
	}
	sub := &store.Subscription{
		UserID:           user.ID,
		Name:             "v",
		MonitoredValue:   identity.SubjectValue{Subject: "x@example.com"},
		WebhookURL:       "https://hooks.example.com/v",
		NotificationType: store.NotificationTypeWebhook,
	}
	if err := s.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("SaveSubscription() error: %v", err)
	}
	if sub.WebhookSecretVersion != 1 {
		t.Errorf("after SaveSubscription, in-memory WebhookSecretVersion = %d, want 1", sub.WebhookSecretVersion)
	}
}

// TestGetSubscription_OwnerScoped returns the owner's subscription and
// ErrNotFound for a non-owner or a missing ID.
func TestGetSubscription_OwnerScoped(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, ownerID := createTestSubscription(ctx, t, s)

	got, err := s.GetSubscription(ctx, subID, ownerID)
	if err != nil {
		t.Fatalf("GetSubscription() error: %v", err)
	}
	if got.ID != subID || got.WebhookSecretVersion != 1 {
		t.Errorf("GetSubscription() = id %d version %d, want id %d version 1", got.ID, got.WebhookSecretVersion, subID)
	}

	other := &store.User{Email: "other-get@example.com"}
	if err := s.SaveUser(ctx, other); err != nil {
		t.Fatalf("SaveUser() error: %v", err)
	}
	if _, err := s.GetSubscription(ctx, subID, other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetSubscription() non-owner err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetSubscription(ctx, 99999, ownerID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetSubscription() missing err = %v, want ErrNotFound", err)
	}
}

// TestRegenerateWebhookSecret_BumpsVersion verifies the counter advances and
// the new value is both returned and persisted.
func TestRegenerateWebhookSecret_BumpsVersion(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, userID := createTestSubscription(ctx, t, s)

	newVersion, err := s.RegenerateWebhookSecret(ctx, subID, userID)
	if err != nil {
		t.Fatalf("RegenerateWebhookSecret() error: %v", err)
	}
	if newVersion != 2 {
		t.Errorf("RegenerateWebhookSecret() returned version %d, want 2", newVersion)
	}

	subs, err := s.ListSubscriptionsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListSubscriptionsByUser() error: %v", err)
	}
	if subs[0].WebhookSecretVersion != 2 {
		t.Errorf("persisted WebhookSecretVersion = %d, want 2", subs[0].WebhookSecretVersion)
	}
}

// TestRegenerateWebhookSecret_RejectsNonOwner refuses to bump a subscription
// the caller does not own and leaves the version untouched.
func TestRegenerateWebhookSecret_RejectsNonOwner(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, ownerID := createTestSubscription(ctx, t, s)

	other := &store.User{Email: "intruder@example.com"}
	if err := s.SaveUser(ctx, other); err != nil {
		t.Fatalf("failed to save other user: %v", err)
	}

	if _, err := s.RegenerateWebhookSecret(ctx, subID, other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RegenerateWebhookSecret() for non-owner err = %v, want ErrNotFound", err)
	}

	// Owner's version must be unchanged.
	subs, err := s.ListSubscriptionsByUser(ctx, ownerID)
	if err != nil {
		t.Fatalf("ListSubscriptionsByUser() error: %v", err)
	}
	if subs[0].WebhookSecretVersion != 1 {
		t.Errorf("WebhookSecretVersion after rejected regenerate = %d, want 1", subs[0].WebhookSecretVersion)
	}
}

// TestRegenerateWebhookSecret_MissingSubscription returns ErrNotFound for an
// unknown subscription ID.
func TestRegenerateWebhookSecret_MissingSubscription(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	_, userID := createTestSubscription(ctx, t, s)

	if _, err := s.RegenerateWebhookSecret(ctx, 99999, userID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RegenerateWebhookSecret() for missing sub err = %v, want ErrNotFound", err)
	}
}

// TestListPendingMatches_PopulatesWebhookSecretVersion ensures the dispatch
// JOIN carries the version so the dispatcher can derive the current secret.
func TestListPendingMatches_PopulatesWebhookSecretVersion(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer s.Close()

	subID, userID := createTestSubscription(ctx, t, s)
	if _, err := s.RegenerateWebhookSecret(ctx, subID, userID); err != nil {
		t.Fatalf("RegenerateWebhookSecret() error: %v", err)
	}

	match := &store.Match{
		Origin:         "o",
		LogIndex:       1,
		UUID:           "uuid",
		CertSubject:    "test@example.com",
		SubscriptionID: subID,
	}
	if err := s.SaveMatch(ctx, match); err != nil {
		t.Fatalf("SaveMatch() error: %v", err)
	}

	pending, err := s.ListPendingMatches(ctx)
	if err != nil {
		t.Fatalf("ListPendingMatches() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending match, got %d", len(pending))
	}
	if pending[0].Subscription.WebhookSecretVersion != 2 {
		t.Errorf("pending Subscription.WebhookSecretVersion = %d, want 2", pending[0].Subscription.WebhookSecretVersion)
	}
}
