-- 004_channel_acls.sql
-- Members-only channels; #general remains open by convention (enforced in server).
-- Minimal roles for now: 'owner' or 'member'.

CREATE TABLE IF NOT EXISTS channel_members (
  channel_id   BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_name    TEXT   NOT NULL,
  role         TEXT   NOT NULL DEFAULT 'member',
  added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, user_name)
);

CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members(user_name);

