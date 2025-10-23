-- Channels
CREATE TABLE IF NOT EXISTS channels (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

-- Messages
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    channel_id INT REFERENCES channels(id) ON DELETE CASCADE,
    sender TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Insert base channels
INSERT INTO channels (name) VALUES ('general') ON CONFLICT DO NOTHING;
INSERT INTO channels (name) VALUES ('random') ON CONFLICT DO NOTHING;

