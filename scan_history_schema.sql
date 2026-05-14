-- Run this SQL in your Supabase Dashboard's SQL Editor to create the necessary table

CREATE TABLE IF NOT EXISTS scan_history (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  result JSONB NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL
);

-- Enable Row Level Security (RLS)
ALTER TABLE scan_history ENABLE ROW LEVEL SECURITY;

-- For demo purposes (since the app previously used unauthenticated local storage),
-- we are enabling public access. In a production scenario, you should replace 'true'
-- with auth.uid() checks and attach scans to a specific user.
CREATE POLICY "Enable read access for all users" ON scan_history FOR SELECT USING (true);
CREATE POLICY "Enable insert for all users" ON scan_history FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable delete for all users" ON scan_history FOR DELETE USING (true);
