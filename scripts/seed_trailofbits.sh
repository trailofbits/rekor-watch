#!/usr/bin/env bash
#
# Copyright 2026 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

DB="${1:-rekor_watch.db}"

EMAIL="rekor-watch@trailofbits.com"
WEBHOOK_URL="http://localhost:12345"

sqlite3 "$DB" <<SQL
INSERT OR IGNORE INTO users (email) VALUES ('${EMAIL}');

INSERT INTO subscriptions (user_id, name, monitored_value, webhook_url)
VALUES (
  (SELECT id FROM users WHERE email = '${EMAIL}'),
  'Trail of Bits cert identities',
  '{"type":"certIdentity","certSubject":".*@trailofbits\\\\.com","issuers":[]}',
  '${WEBHOOK_URL}'
);

INSERT INTO subscriptions (user_id, name, monitored_value, webhook_url)
VALUES (
  (SELECT id FROM users WHERE email = '${EMAIL}'),
  'Riccardo Schirone cert identity',
  '{"type":"certIdentity","certSubject":"r.*schirone.*","issuers":[]}',
  '${WEBHOOK_URL}'
);

INSERT INTO subscriptions (user_id, name, monitored_value, webhook_url)
VALUES (
  (SELECT id FROM users WHERE email = '${EMAIL}'),
  'Riccardo Schirone subject',
  '{"type":"subject","subject":"riccardo.schirone@trailofbits.com"}',
  '${WEBHOOK_URL}'
);
SQL

echo "Done. User and subscriptions seeded for Trail of Bits."
