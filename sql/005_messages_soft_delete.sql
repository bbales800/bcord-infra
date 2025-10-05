-- 005_messages_soft_delete.sql
-- Adds soft-delete and edit metadata to messages.

ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_by TEXT,
  ADD COLUMN IF NOT EXISTS edited_at  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS edited_by  TEXT;

-- Optional helper index if you later want quick admin views
-- CREATE INDEX IF NOT EXISTS idx_messages_deleted ON messages (channel_id, deleted_at);

