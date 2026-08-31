// Copyright 2025 The Sigstore Authors.
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

package v2

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/sigstore/rekor-monitor/pkg/tiles"
	"github.com/sigstore/rekor-monitor/pkg/util"
	tiles_client "github.com/sigstore/rekor-tiles/v2/pkg/client"
	"github.com/sigstore/rekor-tiles/v2/pkg/client/read"
	"github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

type ShardInfo struct {
	client      *read.Client
	verifier    *signature.Verifier
	validityEnd time.Time
}

func (s ShardInfo) ReadCheckpoint(ctx context.Context) (*log.Checkpoint, *note.Note, error) {
	return (*s.client).ReadCheckpoint(ctx)
}

func (s ShardInfo) ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
	return (*s.client).ReadTile(ctx, level, index, p)
}

func (s ShardInfo) ReadEntryBundle(ctx context.Context, index uint64, p uint8) ([]byte, error) {
	return (*s.client).ReadEntryBundle(ctx, index, p)
}

type Entry struct {
	ProtoEntry *protobuf.Entry
	Index      int64
}

func RefreshSigningConfig(tufClient *tuf.Client) (*root.SigningConfig, error) {
	err := tufClient.Refresh()
	if err != nil {
		return nil, fmt.Errorf("error refreshing TUF client: %v", err)
	}

	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return nil, fmt.Errorf("error getting SigningConfig target: %v", err)
	}
	return signingConfig, nil
}

// ShardTarget is a Rekor v2 shard to monitor. Origin is carried alongside the
// read URL rather than derived from it, because a log's checkpoints keep their
// origin even when read from somewhere else. A signing config cannot express
// that, since it carries only URLs; a monitor config states both.
type ShardTarget struct {
	ReadURL string
	Origin  string
	// ValidityStart orders targets from newest to oldest. ValidityEnd is the
	// zero time for a shard that has not been retired.
	ValidityStart time.Time
	ValidityEnd   time.Time
}

func filterV2Shards(rekorServices []root.Service) []root.Service {
	// First we sort and filter the Rekor services so that they're ordered from
	// newest to oldest. We filter them so that we:
	// - only include the v2 logs.
	// - only include shards that are (or were) valid. No shards that will be valid in the future
	sortedServices := make([]root.Service, len(rekorServices))
	copy(sortedServices, rekorServices)
	slices.SortFunc(sortedServices, func(i, j root.Service) int {
		return i.ValidityPeriodStart.Compare(j.ValidityPeriodStart)
	})

	var rekorV2Services []root.Service
	now := time.Now()
	for _, s := range slices.Backward(sortedServices) {
		if s.MajorAPIVersion == 2 && !s.ValidityPeriodStart.IsZero() && s.ValidityPeriodStart.Before(now) {
			rekorV2Services = append(rekorV2Services, s)
		}
	}

	return rekorV2Services
}

// shardTargetsFromServices converts the Rekor services of a signing config
// into shard targets, ordered from newest to oldest. The origin is derived from
// the service URL, which is the only origin a signing config offers.
func shardTargetsFromServices(rekorServices []root.Service) ([]ShardTarget, error) {
	v2Services := filterV2Shards(rekorServices)
	targets := make([]ShardTarget, 0, len(v2Services))
	for _, service := range v2Services {
		origin, err := tiles.GetOrigin(service.URL)
		if err != nil {
			return nil, err
		}
		targets = append(targets, ShardTarget{
			ReadURL:       service.URL,
			Origin:        origin,
			ValidityStart: service.ValidityPeriodStart,
			ValidityEnd:   service.ValidityPeriodEnd,
		})
	}
	return targets, nil
}

// ShardsNeedUpdating deliberately does not delegate to TargetsNeedUpdating.
// It resolves origins lazily, one shard at a time, so that a resized shard set
// or an early mismatch is reported without parsing the remaining URLs. Routing
// it through TargetsNeedUpdating would resolve every origin up front and turn
// an unparseable URL in a later shard into an error where this reports an
// update.
func ShardsNeedUpdating(currentShards map[string]ShardInfo, newSigningConfig *root.SigningConfig) (bool, error) {
	newShards := newSigningConfig.RekorLogURLs()
	newV2Shards := filterV2Shards(newShards)

	if len(newV2Shards) == 0 {
		return false, fmt.Errorf("error fetching Rekor shards: no v2 shards found in SigningConfig")
	}

	if len(currentShards) != len(newV2Shards) {
		// Shards were added/removed, need to update
		return true, nil
	}

	for _, newShard := range newV2Shards {
		newShardOrigin, err := tiles.GetOrigin(newShard.URL)
		if err != nil {
			return false, err
		}

		matchingShard, ok := currentShards[newShardOrigin]
		switch {
		case !ok:
			// The shard in the new SigningConfig is not present
			// in the existing shards, so we need to update
			return true, nil
		case matchingShard.validityEnd != newShard.ValidityPeriodEnd:
			// The newest shard in the SigningConfig is present in
			// the existing shards, but the end validity time changed
			return true, nil
		}
	}

	// All the shards in the new SigningConfig are present in
	// the existing shards, and they have the same validity end time
	return false, nil
}

// TargetsNeedUpdating reports whether the monitored shards no longer match
// targets, either because a shard was added or removed or because a shard's
// validity end time changed.
func TargetsNeedUpdating(currentShards map[string]ShardInfo, targets []ShardTarget) bool {
	if len(currentShards) != len(targets) {
		return true
	}

	for _, target := range targets {
		matchingShard, ok := currentShards[target.Origin]
		switch {
		case !ok:
			// The target is not among the shards being monitored
			return true
		case matchingShard.validityEnd != target.ValidityEnd:
			// The target is being monitored, but its end validity time changed
			return true
		}
	}

	// Every target is already being monitored with the same validity end time
	return false
}

func GetRekorShards(ctx context.Context, trustedRoot *root.TrustedRoot, rekorServices []root.Service, userAgent, certChain string) (map[string]ShardInfo, string, error) {
	targets, err := shardTargetsFromServices(rekorServices)
	if err != nil {
		return nil, "", err
	}
	return GetRekorShardsForTargets(ctx, trustedRoot, targets, userAgent, certChain)
}

// GetRekorShardsForTargets builds a read client for each target and returns the
// clients keyed by log origin, along with the origin of the latest shard.
// targets must be ordered from newest to oldest.
func GetRekorShardsForTargets(ctx context.Context, trustedRoot *root.TrustedRoot, targets []ShardTarget, userAgent, certChain string) (map[string]ShardInfo, string, error) {
	if len(targets) == 0 {
		return nil, "", fmt.Errorf("failed to find any Rekor v2 shards")
	}

	clientOpts := []tiles_client.Option{tiles_client.WithUserAgent(userAgent)}
	var tlsConfig *tls.Config
	if certChain != "" {
		var err error
		tlsConfig, err = util.TLSConfigForCA(certChain)
		if err != nil {
			return nil, "", fmt.Errorf("getting TLS config: %w", err)
		}
		clientOpts = append(clientOpts, tiles_client.WithTLSConfig(tlsConfig))
	}

	rekorShards := make(map[string]ShardInfo)
	// targets are ordered from newest to oldest, so the first one is the
	// latest shard
	latestShardOrigin := targets[0].Origin
	for _, target := range targets {
		parsedURL, err := url.Parse(target.ReadURL)
		if err != nil {
			return nil, "", fmt.Errorf("error parsing Rekor url: %v", err)
		}

		verifier, err := GetLogVerifier(ctx, parsedURL, trustedRoot, userAgent, tlsConfig)
		if err != nil {
			return nil, "", err
		}

		rekorClient, err := read.NewReader(target.ReadURL, target.Origin, verifier, clientOpts...)
		if err != nil {
			return nil, "", fmt.Errorf("getting Rekor client: %v", err)
		}

		// ReadCheckpoint fetches and verifies the current checkpoint
		// We verify the checkpoints of all v2 shards
		checkpoint, _, err := rekorClient.ReadCheckpoint(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to get current checkpoint for log '%v': %v", target.Origin, err)
		}

		rekorShards[checkpoint.Origin] = ShardInfo{&rekorClient, &verifier, target.ValidityEnd}
	}
	return rekorShards, latestShardOrigin, nil
}

func getEntriesFromTile(ctx context.Context, client tiles.Client, fullTileIndex int64, partialTileWidth uint8) ([]Entry, error) {
	bundleBytes, err := client.ReadEntryBundle(ctx, uint64(fullTileIndex), partialTileWidth) //nolint: gosec // G115
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entry bundle")
	}
	var bundle api.EntryBundle
	err = bundle.UnmarshalText(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse entry bundle")
	}
	var entries []Entry
	for i, entryBytes := range bundle.Entries {
		logEntry := protobuf.Entry{}
		err = protojson.Unmarshal(entryBytes, &logEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse entry")
		}
		entries = append(entries, Entry{ProtoEntry: &logEntry, Index: fullTileIndex*layout.TileWidth + int64(i)})
	}
	return entries, nil
}
