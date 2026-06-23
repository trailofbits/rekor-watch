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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"net/http"

	"github.com/sigstore/rekor-monitor/cmd/rekor_watch/web"
	"github.com/sigstore/rekor-monitor/pkg/email"
	"github.com/sigstore/rekor-monitor/pkg/identity"
	safenet "github.com/sigstore/rekor-monitor/pkg/net"
	rekor_v2 "github.com/sigstore/rekor-monitor/pkg/rekor/v2"
	"github.com/sigstore/rekor-monitor/pkg/store"
	"github.com/sigstore/rekor-monitor/pkg/store/sqlite"
	"github.com/sigstore/rekor-monitor/pkg/tiles"
	rmutil "github.com/sigstore/rekor-monitor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	tdlog "github.com/transparency-dev/formats/log"
	"sigs.k8s.io/release-utils/version"
)

// Default values for monitoring job parameters
const (
	publicRekorServerURL = "https://log2025-alpha3.rekor.sigstage.dev"
	TUFRepository        = "staging"
	defaultDBPath        = "rekor_watch.db"
	defaultWebPort       = 8080
	defaultBaseURL       = "http://localhost:8080"
	defaultSMTPHost      = "localhost"
	defaultSMTPPort      = 1025
	defaultSMTPFrom      = "rekor-watch@localhost"
	defaultSMTPHelo      = "rekor-watch.sigstore.org"
	defaultInterval      = 5 * time.Minute

	// Subscription cap defaults.
	defaultMaxSubscriptionsPerUser = 20

	// Match cap defaults. The cap is per-subscription; older matches are
	// evicted FIFO when the cap is exceeded.
	defaultMaxMatchesPerSubscription = 1000

	// Rate limiting defaults.
	defaultIPRate           = 60
	defaultIPWindow         = 1 * time.Minute
	defaultLoginEmailRate   = 20
	defaultLoginEmailWindow = 15 * time.Minute
	defaultPollIPRate       = 100
	defaultPollIPWindow     = 1 * time.Minute
	defaultAuthEmailRate    = 60
	defaultAuthEmailWindow  = 1 * time.Minute
)

// Environment variable names for configuration overrides
const (
	envServerURL            = "REKOR_WATCH_SERVER_URL"
	envInterval             = "REKOR_WATCH_INTERVAL"
	envUserAgent            = "REKOR_WATCH_USER_AGENT_STRING"
	envTUFRepository        = "REKOR_WATCH_TUF_REPOSITORY"
	envTUFRootPath          = "REKOR_WATCH_TUF_ROOT_PATH"
	envCARoots              = "REKOR_WATCH_CA_ROOTS"
	envCAIntermediates      = "REKOR_WATCH_CA_INTERMEDIATES"
	envHTTPSChain           = "REKOR_WATCH_HTTPS_CHAIN"
	envDBPath               = "REKOR_WATCH_DB_PATH"
	envWebPort              = "REKOR_WATCH_WEB_PORT"
	envBaseURL              = "REKOR_WATCH_BASE_URL"
	envSMTPHost             = "REKOR_WATCH_SMTP_HOST"
	envSMTPPort             = "REKOR_WATCH_SMTP_PORT"
	envSMTPFrom             = "REKOR_WATCH_SMTP_FROM"
	envSMTPUsername         = "REKOR_WATCH_SMTP_USERNAME"
	envSMTPPassword         = "REKOR_WATCH_SMTP_PASSWORD" //nolint:gosec // G101: env var name, not a credential
	envSMTPUseTLS           = "REKOR_WATCH_SMTP_USE_TLS"
	envSMTPHELO             = "REKOR_WATCH_SMTP_HELO"
	envSMTPAuthType         = "REKOR_WATCH_SMTP_AUTH_TYPE"
	envAllowPrivateWebhooks = "REKOR_WATCH_ALLOW_PRIVATE_WEBHOOKS"

	envMaxSubscriptionsPerUser   = "REKOR_WATCH_MAX_SUBSCRIPTIONS_PER_USER"
	envMaxMatchesPerSubscription = "REKOR_WATCH_MAX_MATCHES_PER_SUBSCRIPTION"

	envRateLimitEnabled          = "REKOR_WATCH_RATE_LIMIT_ENABLED"
	envRateLimitIPRate           = "REKOR_WATCH_RATE_LIMIT_IP_RATE"
	envRateLimitIPWindow         = "REKOR_WATCH_RATE_LIMIT_IP_WINDOW" //nolint:gosec // G101: env var name, not a credential
	envRateLimitLoginEmailRate   = "REKOR_WATCH_RATE_LIMIT_LOGIN_EMAIL_RATE"
	envRateLimitLoginEmailWindow = "REKOR_WATCH_RATE_LIMIT_LOGIN_EMAIL_WINDOW"
	envRateLimitPollIPRate       = "REKOR_WATCH_RATE_LIMIT_POLL_IP_RATE"
	envRateLimitPollIPWindow     = "REKOR_WATCH_RATE_LIMIT_POLL_IP_WINDOW" //nolint:gosec // G101: env var name, not a credential
	envRateLimitAuthEmailRate    = "REKOR_WATCH_RATE_LIMIT_AUTH_EMAIL_RATE"
	envRateLimitAuthEmailWindow  = "REKOR_WATCH_RATE_LIMIT_AUTH_EMAIL_WINDOW"
	envTrustProxyHeaders         = "REKOR_WATCH_TRUST_PROXY_HEADERS"
)

// envUsage appends the environment variable name to a flag usage string.
func envUsage(envKey, usage string) string {
	return fmt.Sprintf("%s (env: %s)", usage, envKey)
}

// envOrDefault returns the environment variable value if set, otherwise the fallback.
func envOrDefault(envKey, fallback string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return fallback
}

// envOrDefaultInt returns the environment variable value as an int if set, otherwise the fallback.
func envOrDefaultInt(envKey string, fallback int) int {
	if v := os.Getenv(envKey); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		log.Fatalf("Warning: %s env variable does not contain a number", envKey)
	}
	return fallback
}

// envOrDefaultBool returns the environment variable value as a bool if set, otherwise the fallback.
func envOrDefaultBool(envKey string, fallback bool) bool {
	if v := os.Getenv(envKey); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
		log.Fatalf("Warning: %s env variable does not contain a bool\n", envKey)
	}
	return fallback
}

// validateMaxSubscriptionsPerUser rejects non-positive caps. Zero/negative
// would either disable the cap silently or insert junk rows; the design
// chooses to fail closed at startup.
func validateMaxSubscriptionsPerUser(v int) error {
	if v <= 0 {
		return fmt.Errorf("--max-subscriptions-per-user must be > 0, got %d", v)
	}
	return nil
}

// validateMaxMatchesPerSubscription rejects non-positive caps for the same
// reason as the subscription cap: silently disabling the cap by passing 0
// is too easy to miss.
func validateMaxMatchesPerSubscription(v int) error {
	if v <= 0 {
		return fmt.Errorf("--max-matches-per-subscription must be > 0, got %d", v)
	}
	return nil
}

// envOrDefaultDuration returns the environment variable value as a time.Duration if set, otherwise the fallback.
func envOrDefaultDuration(envKey string, fallback time.Duration) time.Duration {
	if v := os.Getenv(envKey); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Fatalf("Warning: %s env variable does not contain a valid duration", envKey)
	}
	return fallback
}

func getRekorVersion(allRekorServices []root.Service, serverURL string) uint32 {
	rekorVersion := uint32(1)
	for _, service := range allRekorServices {
		if serverURL == service.URL {
			rekorVersion = service.MajorAPIVersion
			log.Printf("Found matching Rekor service for URL %s with API version %d", serverURL, rekorVersion)
		}
	}
	log.Printf("Using Rekor API version: %d", rekorVersion)
	return rekorVersion
}

func mainWithReturn() int {
	log.Println("Starting rekor-watch...")

	serverURL := flag.String("url", envOrDefault(envServerURL, publicRekorServerURL), envUsage(envServerURL, "URL to the server that is to be monitored"))
	interval := flag.Duration("interval", envOrDefaultDuration(envInterval, defaultInterval), envUsage(envInterval, "Length of interval between each periodical consistency check"))
	userAgentString := flag.String("user-agent", envOrDefault(envUserAgent, ""), envUsage(envUserAgent, "details to include in the user agent string"))
	tufRepository := flag.String("tuf-repository", envOrDefault(envTUFRepository, TUFRepository), envUsage(envTUFRepository, "TUF repository to use. Can be 'default', 'staging' or a custom TUF repository URL."))
	tufRootPath := flag.String("tuf-root-path", envOrDefault(envTUFRootPath, ""), envUsage(envTUFRootPath, "path to the trusted root file (passed out of bounds), if custom TUF repository is used"))
	caRootsFilePath := flag.String("ca-roots", envOrDefault(envCARoots, ""), envUsage(envCARoots, "path to a bundle file of CA certificates in PEM format"))
	caIntermediatesFilePath := flag.String("ca-intermediates", envOrDefault(envCAIntermediates, ""), envUsage(envCAIntermediates, "path to a bundle file of CA intermediate certificates in PEM format. The flag must be used together with --ca-roots"))
	httpsChainPath := flag.String("https-cert-chain", envOrDefault(envHTTPSChain, ""), envUsage(envHTTPSChain, "path to a list of CA certificates in PEM format for the HTTPS connection to the log server"))
	dbPath := flag.String("db", envOrDefault(envDBPath, defaultDBPath), envUsage(envDBPath, "path to SQLite database file for storing checkpoints (use :memory: for in-memory)"))
	webPort := flag.Int("web-port", envOrDefaultInt(envWebPort, defaultWebPort), envUsage(envWebPort, "port for web UI server (0 to disable)"))
	baseURL := flag.String("base-url", envOrDefault(envBaseURL, defaultBaseURL), envUsage(envBaseURL, "base URL for the web server (used in magic link emails)"))
	smtpHost := flag.String("smtp-host", envOrDefault(envSMTPHost, defaultSMTPHost), envUsage(envSMTPHost, "SMTP server host"))
	smtpPort := flag.Int("smtp-port", envOrDefaultInt(envSMTPPort, defaultSMTPPort), envUsage(envSMTPPort, "SMTP server port"))
	smtpFrom := flag.String("smtp-from", envOrDefault(envSMTPFrom, defaultSMTPFrom), envUsage(envSMTPFrom, "SMTP sender address"))
	smtpUsername := flag.String("smtp-username", envOrDefault(envSMTPUsername, ""), envUsage(envSMTPUsername, "SMTP username for authentication"))
	smtpPassword := flag.String("smtp-password", "", envUsage(envSMTPPassword, "SMTP password for authentication"))
	smtpUseTLS := flag.Bool("smtp-use-tls", envOrDefaultBool(envSMTPUseTLS, false), envUsage(envSMTPUseTLS, "use TLS for SMTP connection"))
	smtpHELO := flag.String("smtp-helo", envOrDefault(envSMTPHELO, defaultSMTPHelo), envUsage(envSMTPHELO, "SMTP HELO domain"))
	smtpAuthType := flag.String("smtp-auth-type", envOrDefault(envSMTPAuthType, "PLAIN"), envUsage(envSMTPAuthType, "SMTP authentication type (PLAIN, XOAUTH2)"))
	maxSubscriptionsPerUser := flag.Int("max-subscriptions-per-user", envOrDefaultInt(envMaxSubscriptionsPerUser, defaultMaxSubscriptionsPerUser), envUsage(envMaxSubscriptionsPerUser, "maximum subscriptions a single user may own (must be > 0)"))
	maxMatchesPerSubscription := flag.Int("max-matches-per-subscription", envOrDefaultInt(envMaxMatchesPerSubscription, defaultMaxMatchesPerSubscription), envUsage(envMaxMatchesPerSubscription, "maximum matches retained per subscription; older matches are evicted FIFO when exceeded (must be > 0)"))
	flag.Parse()

	if err := validateMaxSubscriptionsPerUser(*maxSubscriptionsPerUser); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}
	if err := validateMaxMatchesPerSubscription(*maxMatchesPerSubscription); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	if *smtpPassword == "" {
		*smtpPassword = os.Getenv(envSMTPPassword)
	}

	log.Printf("Configuration: serverURL=%s, interval=%v, tufRepository=%s, dbPath=%s, webPort=%d", *serverURL, *interval, *tufRepository, *dbPath, *webPort)

	if *caIntermediatesFilePath != "" && *caRootsFilePath == "" {
		log.Fatalf("ca-intermediates must be used together with --ca-roots")
	}

	finalUserAgent := strings.TrimSpace(fmt.Sprintf("%s/%s (%s; %s) %s",
		"rekor-watch",
		version.GetVersionInfo().GitVersion,
		runtime.GOOS,
		runtime.GOARCH,
		*userAgentString,
	))
	log.Printf("User-Agent: %s", finalUserAgent)

	ctx := context.Background()

	log.Printf("Initializing TUF client with repository: %s", *tufRepository)
	tufClient, err := rmutil.GetTUFClient(*tufRepository, *tufRootPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TUF client initialized successfully")

	log.Println("Fetching trusted root from TUF...")
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Trusted root fetched successfully")

	log.Println("Fetching signing config from TUF...")
	signingConfig, err := root.GetSigningConfig(tufClient)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Signing config fetched successfully")

	log.Println("Configuring trusted CAs...")
	newCARootsFile, newCAIntermediatesFile, cleanupTrustedCAs, err := rmutil.ConfigureTrustedCAs(*caRootsFilePath, *caIntermediatesFilePath, trustedRoot)
	if err != nil {
		log.Fatal(err)
	}
	*caRootsFilePath = newCARootsFile
	*caIntermediatesFilePath = newCAIntermediatesFile
	defer cleanupTrustedCAs()
	log.Printf("Trusted CAs configured: roots=%s, intermediates=%s", newCARootsFile, newCAIntermediatesFile)

	// Initialize SQLite store for checkpoints and matches
	log.Printf("Initializing SQLite store at: %s", *dbPath)
	dbStore, err := sqlite.NewStore(ctx, *dbPath)
	if err != nil {
		log.Printf("Failed to initialize database store: %v", err)
		return 1
	}
	defer dbStore.Close()
	log.Println("SQLite store initialized successfully")

	smtpSender, err := email.NewSender(email.Config{
		Host:         *smtpHost,
		Port:         *smtpPort,
		From:         *smtpFrom,
		Username:     *smtpUsername,
		SMTPPassword: *smtpPassword,
		SMTPHELO:     *smtpHELO,
		UseTLS:       *smtpUseTLS,
		SMTPAuthType: *smtpAuthType,
	})
	if err != nil {
		log.Printf("Failed to initialize SMTP sender: %v", err)
		return 1
	}

	allowPrivateWebhooks := envOrDefaultBool(envAllowPrivateWebhooks, false)

	if *webPort > 0 {
		webCfg := web.ServerConfig{
			Store:                   dbStore,
			SMTP:                    smtpSender,
			BaseURL:                 *baseURL,
			AllowPrivateWebhooks:    allowPrivateWebhooks,
			TrustProxyHeaders:       envOrDefaultBool(envTrustProxyHeaders, false),
			MaxSubscriptionsPerUser: *maxSubscriptionsPerUser,
		}

		if envOrDefaultBool(envRateLimitEnabled, true) {
			ipRate := envOrDefaultInt(envRateLimitIPRate, defaultIPRate)
			ipWin := envOrDefaultDuration(envRateLimitIPWindow, defaultIPWindow)
			loginEmailRate := envOrDefaultInt(envRateLimitLoginEmailRate, defaultLoginEmailRate)
			loginEmailWin := envOrDefaultDuration(envRateLimitLoginEmailWindow, defaultLoginEmailWindow)
			pollIPRate := envOrDefaultInt(envRateLimitPollIPRate, defaultPollIPRate)
			pollIPWin := envOrDefaultDuration(envRateLimitPollIPWindow, defaultPollIPWindow)
			authEmailRate := envOrDefaultInt(envRateLimitAuthEmailRate, defaultAuthEmailRate)
			authEmailWin := envOrDefaultDuration(envRateLimitAuthEmailWindow, defaultAuthEmailWindow)

			webCfg.IPLimiter = web.NewRateLimiter(ipRate, ipWin)
			webCfg.LoginEmailLimiter = web.NewRateLimiter(loginEmailRate, loginEmailWin)
			webCfg.PollIPLimiter = web.NewRateLimiter(pollIPRate, pollIPWin)
			webCfg.AuthEmailLimiter = web.NewRateLimiter(authEmailRate, authEmailWin)

			log.Printf("Rate limiting enabled: IP %d req/%v, login-email %d req/%v, poll-IP %d req/%v, auth-email %d req/%v",
				ipRate, ipWin, loginEmailRate, loginEmailWin, pollIPRate, pollIPWin, authEmailRate, authEmailWin)
		} else {
			log.Println("Rate limiting disabled")
		}

		webServer := web.NewServer(webCfg)
		if err := webServer.Start(ctx, *webPort); err != nil {
			log.Printf("Failed to start web server: %v", err)
			return 1
		}
	}

	searchOpts := []identity.SearchOption{
		identity.WithCARootsFile(newCARootsFile),
		identity.WithCAIntermediatesFile(newCAIntermediatesFile),
	}

	allRekorServices := signingConfig.RekorLogURLs()
	log.Printf("Found %d Rekor services", len(allRekorServices))
	rekorVersion := getRekorVersion(allRekorServices, *serverURL)
	switch rekorVersion {
	case 1:
		log.Println("Rekor v1 selected - not yet implemented")
		// TODO: Implement Rekor watch logic for rekor v1
	case 2:
		log.Println("Starting Rekor v2 main loop...")
		return mainLoopV2(ctx, tufClient, finalUserAgent, *httpsChainPath, *interval, dbStore, searchOpts, allowPrivateWebhooks, *maxMatchesPerSubscription, smtpSender)
	default:
		log.Printf("Unsupported server version %v, only '1' and '2' are supported\n", rekorVersion)
		return 1
	}
	return 0
}

// IterationFunc is a function that performs a single monitoring iteration.
// Returns nil on success, error on failure.
type IterationFunc func(ctx context.Context) error

// monitorLoop runs the monitoring loop with the given iteration function.
// It handles the ticker, signal handling, and graceful shutdown.
// After each iteration, notifyFn is called to deliver pending notifications.
func monitorLoop(ctx context.Context, interval time.Duration, iterationFn, notifyFn IterationFunc) int {
	// Set up signal handling for graceful shutdown
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run the monitoring loop
	for {
		log.Printf("New monitor run at %s", time.Now().Format(time.RFC3339))

		if err := iterationFn(ctx); err != nil {
			log.Printf("Monitoring iteration failed: %v", err)
			// Continue to next iteration on error
		} else {
			log.Println("Monitoring iteration completed successfully")
		}

		if err := notifyFn(ctx); err != nil {
			log.Printf("Notification delivery failed: %v", err)
		}

		log.Printf("Waiting %v until next iteration...", interval)
		select {
		case <-ticker.C:
			continue
		case <-ctx.Done():
			log.Println("Shutting down gracefully...")
			return 0
		}
	}
}

// runMonitoringIterationV2 catches up every shard the tracker knows about, not
// just the active one: a rollover otherwise strands the tail of the previous
// shard and skips the entries already on the new shard.
func runMonitoringIterationV2(ctx context.Context, rekorShards map[string]rekor_v2.ShardInfo, dbStore store.TransactionalStore, searchOpts []identity.SearchOption, maxMatchesPerSubscription int) error {
	// Load all subscriptions so matches continue to be recorded even when
	// webhook delivery is temporarily disabled or backing off.
	subs, err := dbStore.ListSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("error loading subscriptions: %w", err)
	}
	monitoredValues := collectMonitoredValues(subs)
	subsByValue := groupSubscriptionsByValue(subs)
	log.Printf("Loaded %d unique monitored values from %d subscriptions", len(monitoredValues), len(subs))

	// Computed once per iteration: a multi-shard first deploy must not see its
	// own just-saved checkpoint and mistake a later shard for a rollover.
	hasAnyCheckpoint, err := dbStore.HasAnyCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("error checking for existing checkpoints in database: %w", err)
	}

	// Each shard is caught up in its own transaction, so the order is irrelevant.
	var errs error
	for origin := range rekorShards {
		if err := catchUpShard(ctx, dbStore, rekorShards, origin, hasAnyCheckpoint, monitoredValues, subsByValue, searchOpts, maxMatchesPerSubscription); err != nil {
			errs = errors.Join(errs, fmt.Errorf("shard %s: %w", origin, err))
		}
	}
	return errs
}

// decideSearchRange returns the (startIdx, endIdx] range to scan on the shard
// being processed this iteration, or search=false to skip the scan entirely.
// When search is false the index values carry no meaning.
//
// When there is no checkpoint for this shard's origin, hasAnyCheckpoint
// distinguishes a true first-time deploy (no checkpoints anywhere, monitor
// going forward only) from a rollover to a new shard while checkpoints for
// prior origins still exist (back-search the new shard so pre-existing
// entries match subscriptions).
func decideSearchRange(prev, current *tdlog.Checkpoint, hasAnyCheckpoint bool) (startIdx, endIdx int64, search bool) {
	if prev == nil {
		if !hasAnyCheckpoint || current.Size == 0 {
			return 0, 0, false
		}
		// Rollover: (-1, current.Size-1] covers indices [0, current.Size).
		return -1, int64(current.Size) - 1, true //nolint: gosec // G115, log will never be large enough to overflow
	}
	startIdx = int64(prev.Size) - 1  //nolint: gosec // G115, log will never be large enough to overflow
	endIdx = int64(current.Size) - 1 //nolint: gosec // G115, log will never be large enough to overflow
	return startIdx, endIdx, startIdx < endIdx
}

// catchUpShard scans a single shard's new entries and records any matches and
// its updated checkpoint in one transaction.
func catchUpShard(ctx context.Context, dbStore store.TransactionalStore, rekorShards map[string]rekor_v2.ShardInfo, origin string, hasAnyCheckpoint bool, monitoredValues identity.MonitoredValues, subsByValue map[string][]*store.Subscription, searchOpts []identity.SearchOption, maxMatchesPerSubscription int) error {
	// Load previous checkpoint from database
	log.Printf("Loading checkpoint for origin: %s", origin)
	prevCheckpoint, err := dbStore.LoadCheckpoint(ctx, origin)
	if err != nil {
		return fmt.Errorf("error loading checkpoint from database: %w", err)
	}

	switch {
	case prevCheckpoint != nil:
		log.Printf("Previous checkpoint loaded: size=%d", prevCheckpoint.Size)
	case hasAnyCheckpoint:
		log.Printf("No checkpoint for origin %s but prior origins exist; treating as a shard rollover", origin)
	default:
		log.Println("No previous checkpoint found in database")
	}

	// Run consistency check (verifies log hasn't been tampered with)
	log.Println("Running consistency check...")
	currentCheckpoint, err := tiles.VerifyConsistencyWithCheckpoint(ctx, rekorShards, origin, prevCheckpoint)
	if err != nil {
		return fmt.Errorf("error running consistency check: %w", err)
	}
	log.Printf("Consistency check passed for %s. Current log size: %d", origin, currentCheckpoint.Size)

	// Already caught up: skip the scan and a redundant, identical checkpoint write.
	if prevCheckpoint != nil && prevCheckpoint.Size == currentCheckpoint.Size {
		log.Printf("No new entries to process for %s (size %d unchanged)", origin, prevCheckpoint.Size)
		return nil
	}

	foundEntries := []identity.MonitoredIdentity{}
	failedEntries := []identity.FailedLogEntry{}

	startIndex, endIndex, shouldSearch := decideSearchRange(prevCheckpoint, currentCheckpoint, hasAnyCheckpoint)

	switch {
	case shouldSearch && prevCheckpoint != nil:
		log.Printf("Resuming from saved checkpoint at size %d (startIndex: %d)", prevCheckpoint.Size, startIndex)
	case shouldSearch:
		log.Printf("Back-searching new shard %s after rollover (range (%d, %d])", origin, startIndex, endIndex)
	default:
		log.Println("No previous checkpoint found, this is the first run")
	}

	if shouldSearch {
		log.Printf("Searching entries with index in range (%d, %d] (%d new entries)", startIndex, endIndex, endIndex-startIndex)
		if err := identity.VerifyMonitoredValues(monitoredValues); err == nil {
			log.Println("Starting identity search...")
			foundEntries, failedEntries, err = rekor_v2.IdentitySearch(ctx, rekorShards, origin, monitoredValues, startIndex, endIndex, searchOpts...)
			if err != nil {
				return fmt.Errorf("error searching for identities: %w", err)
			}
			log.Printf("Identity search completed: found %d matching entries, %d failed entries", len(foundEntries), len(failedEntries))
		} else {
			log.Printf("Error verifying monitored values: %v, skipping identity search", err)
		}
	}

	if len(failedEntries) > 0 {
		log.Printf("Warning: %d entries failed to parse; persisting them for later investigation", len(failedEntries))
	}

	// Start transaction for saving matches, failed entries, and checkpoint
	tx, err := dbStore.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Save matches as we process them — one per (entry, subscription) pair.
	// Track which subscriptions received matches so we can trim them once
	// per iteration before commit, keeping retention atomic with the inserts.
	matchCount := 0
	affectedSubs := make(map[int64]bool)
	if len(foundEntries) > 0 {
		log.Printf("Processing %d found identity entries...", len(foundEntries))
		for _, monitoredEntry := range foundEntries {
			fmt.Printf("\tIdentity: %s\n", monitoredEntry.Identity)
			for _, entry := range monitoredEntry.FoundIdentityEntries {
				fmt.Printf("LogEntry:\n")
				matchedStr, err := entry.MatchedIdentity.String()
				if err != nil {
					return fmt.Errorf("error getting string representation of matched identity: %w", err)
				}
				fmt.Printf("\tMatchedIdentity: %s\n", matchedStr)
				fmt.Printf("\tIndex: %d\n", entry.Index)
				fmt.Printf("\tUUID: %s\n", entry.UUID)
				fmt.Printf("\tCertSubject: %s\n", entry.CertSubject)
				fmt.Printf("\tIssuer: %s\n", entry.Issuer)
				fmt.Printf("\tFingerprint: %s\n", entry.Fingerprint)
				fmt.Printf("\tSubject: %s\n", entry.Subject)
				fmt.Printf("\tOIDExtension: %s\n", entry.OIDExtension)
				fmt.Printf("\tExtensionValue: %s\n\n", entry.ExtensionValue)
				fmt.Println("--------------------------------")
				for _, sub := range subsByValue[matchedStr] {
					match := &store.Match{
						Origin:         origin,
						LogIndex:       entry.Index,
						UUID:           entry.UUID,
						CertSubject:    entry.CertSubject,
						Issuer:         entry.Issuer,
						Fingerprint:    entry.Fingerprint,
						Subject:        entry.Subject,
						OIDExtension:   entry.OIDExtension.String(),
						ExtensionValue: entry.ExtensionValue,
						SubscriptionID: sub.ID,
					}
					if err := tx.SaveMatch(ctx, match); err != nil {
						return fmt.Errorf(
							"error saving match (index %d, sub %d): %w",
							entry.Index, sub.ID, err,
						)
					}
					affectedSubs[sub.ID] = true
					matchCount++
					log.Printf(
						"Saved match: origin=%s, index=%d, identity=%s, subscription=%d",
						origin, entry.Index, matchedStr, sub.ID,
					)
				}
			}
		}
	} else {
		log.Println("No matching identities found in the searched range")
	}

	// Persist entries that failed to parse so operators can investigate them
	// later instead of losing them to log output. Kept in the same
	// transaction as matches and the checkpoint so a write failure rolls the
	// whole iteration back rather than advancing past unrecorded failures.
	for _, fe := range failedEntries {
		if err := tx.SaveFailedEntry(ctx, &store.FailedEntry{
			Origin:   origin,
			LogIndex: fe.Index,
			UUID:     fe.UUID,
			Error:    fe.Error,
		}); err != nil {
			return fmt.Errorf("error saving failed entry (index %d): %w", fe.Index, err)
		}
	}

	// Enforce per-subscription retention: cap how many matches each affected
	// subscription retains, evicting the oldest FIFO. Runs inside the same
	// transaction so the cap is observed atomically with the inserts.
	for subID := range affectedSubs {
		if err := tx.TrimMatches(ctx, subID, maxMatchesPerSubscription); err != nil {
			return fmt.Errorf("error trimming matches for subscription %d: %w", subID, err)
		}
	}

	// Save the current checkpoint after successful processing
	log.Printf("Saving checkpoint for %s at size %d", origin, currentCheckpoint.Size)
	if err := tx.SaveCheckpoint(ctx, currentCheckpoint); err != nil {
		return fmt.Errorf("error saving checkpoint: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	log.Printf("Transaction committed for %s: %d matches saved, %d failed entries saved, checkpoint at size %d", origin, matchCount, len(failedEntries), currentCheckpoint.Size)
	return nil
}

// collectMonitoredValues extracts deduplicated MonitoredValues from
// subscriptions. Values are keyed by their string representation;
// subscriptions with unparseable values are skipped.
func collectMonitoredValues(subs []*store.Subscription) identity.MonitoredValues {
	seen := make(map[string]bool)
	var vals identity.MonitoredValues
	for _, sub := range subs {
		key, err := sub.MonitoredValue.String()
		if err != nil {
			log.Printf("error getting string representation of monitored value: %v, skipping", err)
			continue
		}
		if !seen[key] {
			seen[key] = true
			vals = append(vals, sub.MonitoredValue)
		}
	}
	return vals
}

// groupSubscriptionsByValue indexes subscriptions by their
// MonitoredValue string representation, so callers can look up which
// subscriptions (and webhook URLs) correspond to a matched identity.
func groupSubscriptionsByValue(
	subs []*store.Subscription,
) map[string][]*store.Subscription {
	m := make(map[string][]*store.Subscription)
	for _, sub := range subs {
		key, err := sub.MonitoredValue.String()
		if err != nil {
			log.Printf("error getting string representation of monitored value: %v, skipping", err)
			continue
		}
		m[key] = append(m[key], sub)
	}
	return m
}

func mainLoopV2(ctx context.Context, tufClient *tuf.Client, userAgentString string, httpsChainPath string, interval time.Duration, dbStore store.TransactionalStore, searchOpts []identity.SearchOption, allowPrivateWebhooks bool, maxMatchesPerSubscription int, emailSender web.EmailSender) int {
	tracker, err := newShardTracker(ctx, tufClient, userAgentString, httpsChainPath)
	if err != nil {
		log.Printf("error getting Rekor shards: %v\n", err)
		return 1
	}

	// Create the iteration function that captures the v2-specific state.
	// Subscriptions are loaded fresh on each iteration so changes are picked up.
	iterationFnV2 := func(ctx context.Context) error {
		if err := tracker.refresh(ctx); err != nil {
			// A refresh failure (e.g. transient TUF/network error) must not halt
			// monitoring: the existing shards are still valid, so continue and
			// retry on the next iteration.
			log.Printf("WARNING: refreshing Rekor shards failed, continuing with existing shards: %v\n", err)
		}
		return runMonitoringIterationV2(ctx, tracker.shards, dbStore, searchOpts, maxMatchesPerSubscription)
	}

	var webhookClient *http.Client
	if allowPrivateWebhooks {
		log.Printf("WARNING: %s is set — SSRF protection disabled\n", envAllowPrivateWebhooks)
		webhookClient = &http.Client{}
	} else {
		webhookClient = safenet.NewSafeHTTPClient()
	}

	// Rate-limit outbound notifications to 5 per second per destination
	// host to avoid overwhelming subscriber endpoints.
	notificationLimiter := web.NewRateLimiter(5, 1*time.Second)

	notifyFn := func(ctx context.Context) error {
		return sendNotifications(ctx, dbStore, time.Now(), userAgentString, webhookClient, notificationLimiter, emailSender)
	}

	return monitorLoop(ctx, interval, iterationFnV2, notifyFn)
}

func main() {
	os.Exit(mainWithReturn())
}
