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

package v2

import (
	"fmt"
	"slices"
	"time"

	monitor_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/monitor/v1"
	"github.com/sigstore/rekor-monitor/pkg/tiles"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// ShardTargetsFromMonitorConfig resolves the Rekor v2 logs of a monitor config
// against the trusted root, ordered from newest to oldest.
//
// A monitor config states where to read a log and what origin its checkpoints
// carry, but not how long the log is valid, so the validity period comes from
// the trusted root entry for the same log. Shards whose validity has not
// started yet are left out: they hold no entries to monitor, and treating one
// as the latest shard would stall monitoring on an empty log.
func ShardTargetsFromMonitorConfig(config *monitor_v1.MonitorConfig, trustedRoot root.TrustedMaterial, now time.Time) ([]ShardTarget, error) {
	var targets []ShardTarget
	for _, logConfig := range config.GetRekorLogs() {
		if logConfig.GetMajorApiVersion() != 2 {
			continue
		}
		origin := logConfig.GetLogOrigin()
		logInstance, err := findLogByOrigin(trustedRoot, origin, now)
		if err != nil {
			return nil, err
		}
		if logInstance == nil {
			continue
		}
		targets = append(targets, ShardTarget{
			ReadURL:       logConfig.GetReadUrl(),
			Origin:        origin,
			ValidityStart: logInstance.ValidityPeriodStart,
			ValidityEnd:   logInstance.ValidityPeriodEnd,
		})
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("error fetching Rekor shards: no v2 shards found in monitor config")
	}

	slices.SortFunc(targets, func(a, b ShardTarget) int {
		return b.ValidityStart.Compare(a.ValidityStart)
	})
	return targets, nil
}

// findLogByOrigin returns the trusted root entry for the log with the given
// origin, or nil if the log has one but its validity has not started yet.
//
// The trusted root identifies a log by base URL, which cannot be compared
// against a read URL, so the origin derived from the base URL is the join key.
// A log that rotated its key has one entry per key, all with the same origin;
// the entry that started most recently is the one signing checkpoints now.
func findLogByOrigin(trustedRoot root.TrustedMaterial, origin string, now time.Time) (*root.TransparencyLog, error) {
	var match *root.TransparencyLog
	found := false
	for _, logInstance := range trustedRoot.RekorLogs() {
		logOrigin, err := tiles.GetOrigin(logInstance.BaseURL)
		if err != nil || logOrigin != origin {
			continue
		}
		found = true
		if logInstance.ValidityPeriodStart.IsZero() || logInstance.ValidityPeriodStart.After(now) {
			continue
		}
		if match == nil || logInstance.ValidityPeriodStart.After(match.ValidityPeriodStart) {
			match = logInstance
		}
	}

	// A log named by the monitor config but absent from the trusted root has no
	// key to verify its checkpoints with, so monitoring it is not possible.
	if !found {
		return nil, fmt.Errorf("log %q in monitor config is not in the trusted root", origin)
	}
	return match, nil
}
