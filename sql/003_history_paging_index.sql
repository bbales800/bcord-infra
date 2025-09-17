-- 003_history_paging_index.sql
-- Purpose: Speed up /api/history pagination using a single composite btree.
-- Rationale: One index on (channel_id, id) serves both:
--   - Older page:  WHERE c.name=$1 AND m.id < $2 ORDER BY m.id DESC LIMIT $3
--   - Newer page:  WHERE c.name=$1 AND m.id > $2 ORDER BY m.id ASC  LIMIT $3
-- Postgres can scan the same btree in both directions, so we avoid duplicate ASC/DESC indexes.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_chan_id
ON messages (channel_id, id);

