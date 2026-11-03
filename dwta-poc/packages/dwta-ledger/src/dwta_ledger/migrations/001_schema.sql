-- 001: ledger schema v1 (spec §6.3 + §5.11.6 version tracking + pre-restore review).
-- Plain, portable SQL; Postgres-specific features limited to JSONB, INET, arrays and ON CONFLICT (LED-05).

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- one "index card" per logical file; metadata only, never content (FW-L1)
CREATE TABLE files (
  file_id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  volume             TEXT NOT NULL,
  current_path       TEXT NOT NULL,
  first_seen_sim_ts  TIMESTAMPTZ NOT NULL,
  latest_artifact_id BIGINT,
  version_count      INTEGER NOT NULL DEFAULT 0,
  status             TEXT NOT NULL CHECK (status IN ('present', 'deleted', 'replaced'))
);
CREATE UNIQUE INDEX ux_files_live ON files (volume, current_path) WHERE status = 'present';

-- one row per file VERSION written (B5)
CREATE TABLE artifacts (
  artifact_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id           TEXT UNIQUE NOT NULL,
  file_id            BIGINT NOT NULL REFERENCES files,
  version_no         INTEGER NOT NULL,
  change_kind        TEXT NOT NULL CHECK (change_kind IN ('new_file', 'overwrite')),
  prev_artifact_id   BIGINT REFERENCES artifacts,
  prev_sha256        CHAR(64),
  prev_type_rules    TEXT,
  prev_type_ai       TEXT,
  same_content       BOOLEAN NOT NULL DEFAULT FALSE,
  volume             TEXT NOT NULL,
  share_kind         TEXT NOT NULL,
  path               TEXT NOT NULL,
  ext                TEXT,
  content_status     TEXT NOT NULL CHECK (content_status IN ('ok', 'gone_before_read', 'changed_since_event')),
  size               BIGINT,
  sha256             CHAR(64),
  type_rules         TEXT,
  type_ai            TEXT,
  ai_label           TEXT,
  ai_score           REAL,
  ext_mismatch_rules BOOLEAN,
  ext_mismatch_ai    BOOLEAN,
  signals            JSONB NOT NULL DEFAULT '[]',
  analysis           TEXT NOT NULL DEFAULT 'full' CHECK (analysis IN ('full', 'partial', 'none')),
  "user"             TEXT,
  client_ip          INET,
  client_name        TEXT,
  client_origin      TEXT,
  source             TEXT NOT NULL,
  ts                 TIMESTAMPTZ NOT NULL,
  sim_ts             TIMESTAMPTZ NOT NULL,
  classified_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  classifier_version TEXT NOT NULL
);
CREATE INDEX ix_art_sha  ON artifacts (sha256);
CREATE INDEX ix_art_win  ON artifacts (volume, sim_ts);
CREATE INDEX ix_art_user ON artifacts (volume, "user", sim_ts);
CREATE INDEX ix_art_file ON artifacts (file_id, version_no);
ALTER TABLE files ADD CONSTRAINT fk_files_latest FOREIGN KEY (latest_artifact_id) REFERENCES artifacts DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE feed_entries (
  feed_id        TEXT NOT NULL,
  sha256         CHAR(64) NOT NULL,
  first_seen_sim TIMESTAMPTZ,
  signature      TEXT,
  file_name      TEXT,
  reporter       TEXT,
  imported_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (feed_id, sha256)
);
CREATE INDEX ix_feed_sha ON feed_entries (sha256);

CREATE TABLE feed_matches (
  match_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  artifact_id    BIGINT NOT NULL REFERENCES artifacts,
  sha256         CHAR(64) NOT NULL,
  feed_id        TEXT NOT NULL,
  matched_sim_ts TIMESTAMPTZ,
  matched_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (artifact_id, sha256)
);

CREATE TABLE incidents (
  incident_id         TEXT PRIMARY KEY,
  source              TEXT NOT NULL,
  kind                TEXT NOT NULL,
  detected_sim_ts     TIMESTAMPTZ NOT NULL,
  "user"              TEXT,
  client_ip           INET,
  client_name         TEXT,
  volumes             TEXT[] NOT NULL,
  restore_time_sim_ts TIMESTAMPTZ,
  description         TEXT,
  state               TEXT NOT NULL CHECK (state IN ('awaiting_restore_time', 'under_review', 'finalized', 'rejected')),
  reject_reason       TEXT,
  config_version      TEXT,
  config_sha256       TEXT,
  incomplete          BOOLEAN NOT NULL DEFAULT FALSE,
  finalized_by        TEXT,
  finalized_at        TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (restore_time_sim_ts IS NULL OR restore_time_sim_ts < detected_sim_ts)
);

-- one row per listed item per mode; item_key = 'artifact:<id>' or 'group:attack_outputs'
CREATE TABLE review_items (
  incident_id     TEXT NOT NULL REFERENCES incidents,
  mode            TEXT NOT NULL CHECK (mode IN ('rules', 'rules_ai')),
  item_key        TEXT NOT NULL,
  rank            INTEGER NOT NULL,
  item_kind       TEXT NOT NULL CHECK (item_kind IN ('file', 'attack_outputs_group')),
  artifact_id     BIGINT REFERENCES artifacts,
  group_members   BIGINT[],
  change_kind     TEXT,
  score           INTEGER NOT NULL,
  suspicion_level TEXT NOT NULL,
  reasons         JSONB NOT NULL,
  PRIMARY KEY (incident_id, mode, item_key)
);

-- admin decisions are per item, independent of mode, and survive a replan (ENG-05)
CREATE TABLE review_decisions (
  incident_id TEXT NOT NULL REFERENCES incidents,
  item_key    TEXT NOT NULL,
  decision    TEXT NOT NULL CHECK (decision IN ('remove', 'keep')),
  decided_by  TEXT NOT NULL,
  decided_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (incident_id, item_key)
);

CREATE TABLE alerts (
  alert_id    CHAR(64) PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('write_time', 'feed_match', 'incident')),
  severity    TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  mode        TEXT NOT NULL CHECK (mode IN ('rules', 'rules_ai', 'both')),
  artifact_id BIGINT REFERENCES artifacts,
  incident_id TEXT,
  rule_ids    TEXT[] NOT NULL,
  reasons     JSONB NOT NULL,
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  sim_ts      TIMESTAMPTZ
);

CREATE TABLE consumer_offsets (
  consumer          TEXT PRIMARY KEY,
  segment           TEXT NOT NULL DEFAULT '',
  line              BIGINT NOT NULL DEFAULT 0,
  high_water_ts     TIMESTAMPTZ,
  high_water_sim_ts TIMESTAMPTZ,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
