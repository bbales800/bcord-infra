-- Presence table: last_seen per (channel,user)
CREATE TABLE IF NOT EXISTS presence (
  channel_id  BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_name   TEXT   NOT NULL,
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (channel_id, user_name)
);

-- Helpful index for recency queries
CREATE INDEX IF NOT EXISTS idx_presence_recent
  ON presence(channel_id, last_seen DESC);

