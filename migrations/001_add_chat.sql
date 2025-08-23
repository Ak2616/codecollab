-- 1) messages table
CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  content TEXT NOT NULL,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  edited_at TIMESTAMPTZ,
  deleted BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_messages_project_created_at 
  ON messages (project_id, created_at DESC);

-- 2) last_read_at column on project_members for unread counts
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name='project_members' AND column_name='last_read_at'
  ) THEN
    ALTER TABLE project_members ADD COLUMN last_read_at TIMESTAMPTZ;
  END IF;
END$$;

-- 3) optional: project preview columns to speed ordering
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name='projects' AND column_name='last_message_at'
  ) THEN
    ALTER TABLE projects ADD COLUMN last_message_at TIMESTAMPTZ;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name='projects' AND column_name='last_message_id'
  ) THEN
    ALTER TABLE projects ADD COLUMN last_message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL;
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_projects_last_message_at 
  ON projects (last_message_at DESC);

-- 4) unique constraint on join_requests(user_id, project_id)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint 
    WHERE conname = 'unique_user_project'
  ) THEN
    ALTER TABLE join_requests 
    ADD CONSTRAINT unique_user_project UNIQUE (user_id, project_id);
  END IF;
END$$;
