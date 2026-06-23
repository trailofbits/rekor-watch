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
	"errors"
	"testing"

	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
	"github.com/sigstore/sigstore-go/pkg/root"
)

func shardSet(origins ...string) map[string]rekor_v2.ShardInfo {
	m := make(map[string]rekor_v2.ShardInfo, len(origins))
	for _, o := range origins {
		m[o] = rekor_v2.ShardInfo{}
	}
	return m
}

func TestShardTrackerRefresh_NoUpdate(t *testing.T) {
	fetched := false
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		refreshSigningConfig: func() (*root.SigningConfig, error) {
			return &root.SigningConfig{}, nil
		},
		shardsNeedUpdating: func(map[string]rekor_v2.ShardInfo, *root.SigningConfig) (bool, error) {
			return false, nil
		},
		fetchShards: func(context.Context, *root.SigningConfig) (map[string]rekor_v2.ShardInfo, string, error) {
			fetched = true
			return nil, "", nil
		},
	}

	if err := tr.refresh(context.Background()); err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if fetched {
		t.Fatal("fetchShards was called even though no update was needed")
	}
	if tr.latestShardOrigin != "origin-A" {
		t.Fatalf("latestShardOrigin changed to %q, want origin-A", tr.latestShardOrigin)
	}
	if _, ok := tr.shards["origin-A"]; !ok || len(tr.shards) != 1 {
		t.Fatalf("shards changed unexpectedly: %v", keys(tr.shards))
	}
}

func TestShardTrackerRefresh_Update(t *testing.T) {
	wantConfig := &root.SigningConfig{}
	var gotCurrentLen int
	var decideConfig, fetchConfig *root.SigningConfig

	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		refreshSigningConfig: func() (*root.SigningConfig, error) {
			return wantConfig, nil
		},
		shardsNeedUpdating: func(current map[string]rekor_v2.ShardInfo, sc *root.SigningConfig) (bool, error) {
			gotCurrentLen = len(current)
			decideConfig = sc
			return true, nil
		},
		fetchShards: func(_ context.Context, sc *root.SigningConfig) (map[string]rekor_v2.ShardInfo, string, error) {
			fetchConfig = sc
			return shardSet("origin-A", "origin-B"), "origin-B", nil
		},
	}

	if err := tr.refresh(context.Background()); err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}
	if gotCurrentLen != 1 {
		t.Fatalf("shardsNeedUpdating saw %d current shards, want 1", gotCurrentLen)
	}
	if decideConfig != wantConfig || fetchConfig != wantConfig {
		t.Fatal("refreshed SigningConfig was not threaded through to decide/fetch")
	}
	if tr.latestShardOrigin != "origin-B" {
		t.Fatalf("latestShardOrigin = %q, want origin-B", tr.latestShardOrigin)
	}
	if _, ok := tr.shards["origin-B"]; !ok || len(tr.shards) != 2 {
		t.Fatalf("shards not updated: %v", keys(tr.shards))
	}
}

func TestShardTrackerRefresh_SigningConfigError(t *testing.T) {
	decided := false
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		refreshSigningConfig: func() (*root.SigningConfig, error) {
			return nil, errors.New("boom")
		},
		shardsNeedUpdating: func(map[string]rekor_v2.ShardInfo, *root.SigningConfig) (bool, error) {
			decided = true
			return false, nil
		},
		fetchShards: func(context.Context, *root.SigningConfig) (map[string]rekor_v2.ShardInfo, string, error) {
			t.Fatal("fetchShards must not run after a SigningConfig error")
			return nil, "", nil
		},
	}

	if err := tr.refresh(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
	if decided {
		t.Fatal("shardsNeedUpdating must not run after a SigningConfig error")
	}
	assertUnchanged(t, tr)
}

func TestShardTrackerRefresh_NeedUpdatingError(t *testing.T) {
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		refreshSigningConfig: func() (*root.SigningConfig, error) {
			return &root.SigningConfig{}, nil
		},
		shardsNeedUpdating: func(map[string]rekor_v2.ShardInfo, *root.SigningConfig) (bool, error) {
			return false, errors.New("boom")
		},
		fetchShards: func(context.Context, *root.SigningConfig) (map[string]rekor_v2.ShardInfo, string, error) {
			t.Fatal("fetchShards must not run after a comparison error")
			return nil, "", nil
		},
	}

	if err := tr.refresh(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
	assertUnchanged(t, tr)
}

func TestShardTrackerRefresh_FetchError(t *testing.T) {
	tr := &shardTracker{
		shards:            shardSet("origin-A"),
		latestShardOrigin: "origin-A",
		refreshSigningConfig: func() (*root.SigningConfig, error) {
			return &root.SigningConfig{}, nil
		},
		shardsNeedUpdating: func(map[string]rekor_v2.ShardInfo, *root.SigningConfig) (bool, error) {
			return true, nil
		},
		fetchShards: func(context.Context, *root.SigningConfig) (map[string]rekor_v2.ShardInfo, string, error) {
			return nil, "", errors.New("boom")
		},
	}

	if err := tr.refresh(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
	assertUnchanged(t, tr)
}

func assertUnchanged(t *testing.T, tr *shardTracker) {
	t.Helper()
	if tr.latestShardOrigin != "origin-A" {
		t.Fatalf("latestShardOrigin changed to %q, want origin-A", tr.latestShardOrigin)
	}
	if _, ok := tr.shards["origin-A"]; !ok || len(tr.shards) != 1 {
		t.Fatalf("shards mutated on failure: %v", keys(tr.shards))
	}
}

func keys(m map[string]rekor_v2.ShardInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
