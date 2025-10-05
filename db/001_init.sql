-- Channels and messages for durable chat
CREATE TABLE IF NOT EXISTS channels (
  id      BIGSERIAL PRIMARY KEY,
  name    TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS messages (
  id          BIGSERIAL PRIMARY KEY,
  channel_id  BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  sender      TEXT NOT NULL,
  body        TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_channel_time ON messages(channel_id, created_at DESC);

-- seed a default channel
INSERT INTO channels(name)
VALUES ('general')
ON CONFLICT (name) DO NOTHING;

