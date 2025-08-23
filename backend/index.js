// File: backend/index.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const db = require('./db');

const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key'; // set in env for prod
const PORT = process.env.PORT || 3000;

const app = express();

// Static files + parsers
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ---- Auth middleware (unchanged) ----
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Access denied. Token missing.' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Invalid authorization format.' });
  }

  const token = parts[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

// ---------------- existing routes (signup, login, projects, join requests, profile, etc.) ----------------
// I kept your existing code intact. For brevity, I'm going to require your original file content here.
// If you prefer the full original routes inline, leave them as-is. For clarity, I'll re-include exactly the original
// logic below but then append new routes. (In your repo, just replace the current backend/index.js with this full file.)

// ---- BEGIN: copy your existing route handlers (signup, login, /api/projects, /api/join-request, /api/profile, /api/users/:id etc.) ----
// For readability I will paste the existing content as-is (unchanged) except that later in the file I add new endpoints.
// ---- (PASTE your previous route handler code here) ----

// To avoid duplication in this message, assume everything from your original backend/index.js routes
// (signup, login, /api/projects, /api/join-request, profile, users/:id endpoints, request accept/reject)
// remains unchanged and is present here exactly as you supplied.
// ------------------------ AUTH ------------------------

// Signup route (now requires skills; accepts optional bio, github_url)
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password, skills, bio, github_url } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'username, email and password are required' });
    }

    // Skills must be provided (either array or comma-separated string)
    let skillsArray = [];
    if (Array.isArray(skills)) {
      skillsArray = skills.map(s => String(s).trim()).filter(Boolean);
    } else if (typeof skills === 'string') {
      skillsArray = skills.split(',').map(s => s.trim()).filter(Boolean);
    }

    if (!skillsArray || skillsArray.length === 0) {
      return res.status(400).json({ message: 'Please provide at least one skill' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const insertRes = await db.query(

       `INSERT INTO users (username, email, password, skills, bio, github_url)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, email`,
      [username, email, hashedPassword, JSON.stringify(skillsArray), bio || null, github_url || null]
    );

    const createdUser = insertRes.rows[0];
    res.status(201).json({ message: 'User created successfully', user: createdUser });
  } catch (err) {
    console.error("Signup DB Error:", err && err.message);
    // Unique contraint error handling for email/username
    if (err && err.code === '23505') {
      // Determine which constraint violated if possible
      const detail = err.detail || '';
      if (detail.includes('email')) return res.status(400).json({ message: 'Email already exists' });
      if (detail.includes('username')) return res.status(400).json({ message: 'Username already exists' });
      return res.status(400).json({ message: 'Duplicate field value' });
    }
    res.status(500).json({ message: 'Error creating user' });
  }
});

// Login route (returns JWT)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Sign token including username so frontend can show display name without extra API calls
    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username },
      SECRET_KEY,
      { expiresIn: '8h' }
    );

    res.json({
      username: user.username,
      userId: user.id,
      token
    });
  } catch (err) {
    console.error("Login DB Error:", err && err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// ------------------------ PROJECTS & JOIN REQUESTS ------------------------

app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/home.html'));
});

/**
 * GET /api/projects
 * Protected. Returns:
 * { projects: [...], stats: { requests_sent, projects_joined, pending_incoming } }
 * Projects exclude those created by current user.
 * Each project includes `requested: boolean` indicating whether current user has an active/pending/accepted request (but rejected is ignored).
 */
app.get('/api/projects', verifyToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const projectsQuery = `
      SELECT p.*,
             -- If there's a join_request that is NOT 'rejected' for current user, mark requested
             (jr.id IS NOT NULL AND jr.request_status IS DISTINCT FROM 'rejected') AS requested
      FROM projects p
      LEFT JOIN join_requests jr
        ON jr.project_id = p.id
        AND jr.user_id = $1
      WHERE p.created_by_id IS NULL OR p.created_by_id <> $1
      ORDER BY p.id DESC
    `;
    const projectsResult = await db.query(projectsQuery, [userId]);

    // Stats:
    const statsQuery = `
      SELECT
        COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'pending') AS requests_sent,
        COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'accepted') AS projects_joined,
        COUNT(*) FILTER (WHERE p.created_by_id = $1 AND jr.request_status = 'pending') AS pending_incoming
      FROM join_requests jr
      LEFT JOIN projects p ON jr.project_id = p.id
    `;
    const statsResult = await db.query(statsQuery, [userId]);

    const statsRow = statsResult.rows[0] || { requests_sent: 0, projects_joined: 0, pending_incoming: 0 };

    const stats = {
      requests_sent: parseInt(statsRow.requests_sent, 10) || 0,
      projects_joined: parseInt(statsRow.projects_joined, 10) || 0,
      pending_incoming: parseInt(statsRow.pending_incoming, 10) || 0
    };

    res.json({ projects: projectsResult.rows, stats });
  } catch (err) {
    console.error("Error fetching projects:", err);
    res.status(500).json({ message: 'Error fetching projects' });
  }
});

app.get('/api/projects/:id', async (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

  try {
    const result = await db.query('SELECT * FROM projects WHERE id = $1', [projectId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Project not found' });

    res.json(result.rows[0]); // send a single project object
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


/**
 * POST /api/projects
 * Protected. Body: { title, project_description, tech_stack, deadline }
 * Owner is inserted to project_members as well.
 */
app.post('/api/projects', verifyToken, async (req, res) => {
  const { title, project_description, tech_stack, deadline } = req.body;
  const created_by = req.user.username;
  const created_by_id = req.user.id;

  try {
    const result = await db.query(
      `INSERT INTO projects (title, project_description, tech_stack, deadline, created_by, created_by_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [title, project_description, tech_stack, deadline, created_by, created_by_id]
    );

    const project = result.rows[0];

    // Insert owner as a member (idempotent)
    try {
      await db.query(
        `INSERT INTO project_members (project_id, user_id, role)
         VALUES ($1, $2, 'owner')
         ON CONFLICT ON CONSTRAINT project_members_project_id_user_id_key
         DO NOTHING`,
        [project.id, created_by_id]
      );
    } catch (pmErr) {
      // If constraint name unknown, use fallback ON CONFLICT DO NOTHING
      try {
        await db.query(
          `INSERT INTO project_members (project_id, user_id, role)
           VALUES ($1, $2, 'owner')
           ON CONFLICT (project_id, user_id) DO NOTHING`,
          [project.id, created_by_id]
        );
      } catch (_) { /* log if you want */ }
    }

    res.status(201).json({ message: 'Project created', project });
  } catch (err) {
    console.error("Error creating project:", err);
    res.status(400).json({ error: 'Failed to create project' });
  }
});

/**
 * POST /api/join-request
 * Protected. Body: { projectId }
 */
app.post('/api/join-request', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { projectId } = req.body;

  if (!projectId) {
    return res.status(400).json({ message: 'Missing projectId in request body' });
  }

  try {
    // Validate project exists and get owner
    const projectRes = await db.query('SELECT id, created_by_id FROM projects WHERE id = $1', [projectId]);
    if (projectRes.rows.length === 0) {
      return res.status(400).json({ message: 'Project not found' });
    }
    const project = projectRes.rows[0];

    // Prevent owner from requesting to join their own project
    if (project.created_by_id && project.created_by_id === userId) {
      return res.status(400).json({ message: 'You cannot request to join your own project' });
    }

    // Try to insert; ON CONFLICT uses the new table-level unique constraint
    try {
      const insertRes = await db.query(
        `INSERT INTO join_requests (user_id, project_id, request_status, requested_at)
         VALUES ($1, $2, 'pending', NOW())
         ON CONFLICT ON CONSTRAINT unique_user_project
         DO NOTHING
         RETURNING id`,
        [userId, projectId]
      );

      const created = insertRes.rowCount === 1;
      const status = created ? 'created' : 'already_exists';

      // Return authoritative stats for the requester (pending outgoing and projects_joined)
      const statsResult = await db.query(
        `SELECT
           COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'pending') AS requests_sent,
           COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'accepted') AS projects_joined
         FROM join_requests`,
        [userId]
      );
      const row = statsResult.rows[0] || { requests_sent: 0, projects_joined: 0 };

      const response = {
        projectId,
        status,
        requests_sent: parseInt(row.requests_sent, 10) || 0,
        projects_joined: parseInt(row.projects_joined, 10) || 0
      };

      const code = created ? 201 : 200;
      return res.status(code).json(response);
    } catch (insertErr) {
      // Fallback if constraint name missing / DB mismatched
      if (insertErr && insertErr.code === '42704') {
        // Fallback insertion
        try {
          await db.query(
            `INSERT INTO join_requests (user_id, project_id, request_status, requested_at)
             VALUES ($1, $2, 'pending', NOW())`,
            [userId, projectId]
          );
          const statsResult = await db.query(
            `SELECT
               COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'pending') AS requests_sent,
               COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'accepted') AS projects_joined
             FROM join_requests`,
            [userId]
          );
          const row = statsResult.rows[0] || { requests_sent: 0, projects_joined: 0 };
          return res.status(201).json({
            projectId,
            status: 'created',
            requests_sent: parseInt(row.requests_sent, 10) || 0,
            projects_joined: parseInt(row.projects_joined, 10) || 0
          });
        } catch (ie) {
          if (ie.code === '23505') {
            // already pending/exists
            const statsResult = await db.query(
              `SELECT
                 COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'pending') AS requests_sent,
                 COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'accepted') AS projects_joined
               FROM join_requests`,
              [userId]
            );
            const row = statsResult.rows[0] || { requests_sent: 0, projects_joined: 0 };
            return res.status(200).json({
              projectId,
              status: 'already_exists',
              requests_sent: parseInt(row.requests_sent, 10) || 0,
              projects_joined: parseInt(row.projects_joined, 10) || 0
            });
          }
          throw ie;
        }
      }
      throw insertErr;
    }
  } catch (err) {
    console.error("Unexpected error in join-request:", err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// -------------------- profile & request-management endpoints --------------------

// GET /api/profile  -> current user (protected)
app.get('/api/profile', verifyToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const userRes = await db.query(`SELECT id, username, email, skills, bio, github_url FROM users WHERE id = $1`, [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ message: 'User not found' });
    const user = userRes.rows[0];

    const statsQuery = `
      SELECT
        (SELECT COUNT(*)::int FROM projects WHERE created_by_id = $1) AS projects_owned,
        (SELECT COUNT(*)::int FROM join_requests WHERE user_id = $1 AND request_status = 'pending') AS requests_sent,
        (SELECT COUNT(*)::int FROM join_requests jr JOIN projects p ON jr.project_id = p.id WHERE p.created_by_id = $1 AND jr.request_status = 'pending') AS pending_incoming,
        (SELECT COUNT(*)::int FROM join_requests WHERE user_id = $1 AND request_status = 'accepted') AS accepted_outgoing,
        (SELECT COUNT(*)::int FROM join_requests jr JOIN projects p ON jr.project_id = p.id WHERE p.created_by_id = $1 AND jr.request_status = 'accepted') AS accepted_incoming
    `;
    const statsRes = await db.query(statsQuery, [userId]);
    const s = statsRes.rows[0] || {};
    const acceptedOutgoing = parseInt(s.accepted_outgoing, 10) || 0;
    const acceptedIncoming = parseInt(s.accepted_incoming, 10) || 0;
    const stats = {
      projects_owned: parseInt(s.projects_owned, 10) || 0,
      requests_sent: parseInt(s.requests_sent, 10) || 0,
      pending_incoming: parseInt(s.pending_incoming, 10) || 0,
      accepted_outgoing: acceptedOutgoing,
      accepted_incoming: acceptedIncoming,
      ongoing: acceptedOutgoing + acceptedIncoming
    };

    const incomingRes = await db.query(
      `SELECT jr.id AS request_id, jr.request_status, jr.requested_at,
              u.id AS requester_id, u.username AS requester_username, u.email AS requester_email,
              p.id AS project_id, p.title AS project_title
       FROM join_requests jr
       JOIN users u ON jr.user_id = u.id
       JOIN projects p ON jr.project_id = p.id
       WHERE p.created_by_id = $1
       ORDER BY jr.requested_at DESC`,
      [userId]
    );

    const outgoingRes = await db.query(
      `SELECT jr.id AS request_id, jr.request_status, jr.requested_at,
              p.id AS project_id, p.title AS project_title,
              owner.id AS owner_id, owner.username AS owner_username, owner.email AS owner_email
       FROM join_requests jr
       JOIN projects p ON jr.project_id = p.id
       JOIN users owner ON p.created_by_id = owner.id
       WHERE jr.user_id = $1
       ORDER BY jr.requested_at DESC`,
      [userId]
    );

    res.json({ user, stats, incoming: incomingRes.rows, outgoing: outgoingRes.rows });
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ message: 'Error fetching profile data' });
  }
});

// ---------------- Public profile endpoints -----------------

// GET /api/users/:id  (public) - returns public profile data and some stats
app.get('/api/users/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ message: 'Invalid user id' });

  try {
    const userRes = await db.query(`SELECT id, username, skills, bio, github_url FROM users WHERE id = $1`, [id]);
    if (userRes.rows.length === 0) return res.status(404).json({ message: 'User not found' });

    const statsQuery = `
      SELECT
        (SELECT COUNT(*)::int FROM projects WHERE created_by_id = $1) AS projects_owned,
        (SELECT COUNT(*)::int FROM join_requests WHERE user_id = $1 AND request_status = 'accepted') AS projects_joined
    `;
    const statsRes = await db.query(statsQuery, [id]);
    const stats = statsRes.rows[0] || { projects_owned: 0, projects_joined: 0 };

    return res.json({ user: userRes.rows[0], stats });
  } catch (err) {
    console.error("Error fetching user profile:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/users/:id/projects/owned  (public) - returns projects with members (accepted members)
app.get('/api/users/:id/projects/owned', async (req, res) => {
  const ownerId = parseInt(req.params.id, 10);
  if (!ownerId) return res.status(400).json({ message: 'Invalid user id' });

  try {
    const projectsRes = await db.query(
      `SELECT p.* FROM projects p WHERE p.created_by_id = $1 ORDER BY p.id DESC`,
      [ownerId]
    );
    const projects = projectsRes.rows;

    // For each project, fetch members from project_members -> users
    const projectIds = projects.map(p => p.id);
    let membersByProject = {};
    if (projectIds.length > 0) {
      const membersRes = await db.query(
        `SELECT pm.project_id, u.id AS user_id, u.username
         FROM project_members pm
         JOIN users u ON pm.user_id = u.id
         WHERE pm.project_id = ANY ($1::int[])
         ORDER BY pm.joined_at ASC`,
        [projectIds]
      );
      membersRes.rows.forEach(r => {
        if (!membersByProject[r.project_id]) membersByProject[r.project_id] = [];
        membersByProject[r.project_id].push({ id: r.user_id, username: r.username });
      });
    }

    const out = projects.map(p => ({ ...p, members: membersByProject[p.id] || [] }));
    return res.json({ projects: out });
  } catch (err) {
    console.error("Error fetching owned projects:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/users/:id/projects/joined (public) - returns projects that the user is a member of
app.get('/api/users/:id/projects/joined', async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!userId) return res.status(400).json({ message: 'Invalid user id' });

  try {
    // join project_members to get projects
    const pjRes = await db.query(
      `SELECT p.*, owner.id AS owner_id, owner.username AS owner_username
       FROM project_members pm
       JOIN projects p ON pm.project_id = p.id
       JOIN users owner ON p.created_by_id = owner.id
       WHERE pm.user_id = $1
       ORDER BY p.id DESC`,
      [userId]
    );
    const projects = pjRes.rows;
    const projectIds = projects.map(p => p.id);

    let membersByProject = {};
    if (projectIds.length > 0) {
      const membersRes = await db.query(
        `SELECT pm.project_id, u.id AS user_id, u.username
         FROM project_members pm
         JOIN users u ON pm.user_id = u.id
         WHERE pm.project_id = ANY ($1::int[])
         ORDER BY pm.joined_at ASC`,
        [projectIds]
      );
      membersRes.rows.forEach(r => {
        if (!membersByProject[r.project_id]) membersByProject[r.project_id] = [];
        membersByProject[r.project_id].push({ id: r.user_id, username: r.username });
      });
    }

    const out = projects.map(p => ({
      ...p,
      owner: { id: p.owner_id, username: p.owner_username },
      members: membersByProject[p.id] || []
    }));
    return res.json({ projects: out });
  } catch (err) {
    console.error("Error fetching joined projects:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/users/:id  -> update profile (skills, bio, github_url). Owner-only.
app.patch('/api/users/:id', verifyToken, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const callerId = req.user.id;
  if (callerId !== userId) return res.status(403).json({ message: 'Not authorized' });

  const { skills, bio, github_url } = req.body;

  try {
    let skillsArray = null;
    if (typeof skills !== 'undefined') {
      if (Array.isArray(skills)) skillsArray = skills.map(s => String(s).trim()).filter(Boolean);
      else if (typeof skills === 'string') skillsArray = skills.split(',').map(s => s.trim()).filter(Boolean);
      else return res.status(400).json({ message: 'Invalid skills format' });

      if (!skillsArray || skillsArray.length === 0) {
        return res.status(400).json({ message: 'Please provide at least one skill' });
      }
    }

    const updateParts = [];
    const params = [];
    let idx = 1;

    if (skillsArray !== null) {
      updateParts.push(`skills = $${idx++}`);
      params.push(JSON.stringify(skillsArray));
    }
    if (typeof bio !== 'undefined') {
      updateParts.push(`bio = $${idx++}`);
      params.push(bio || null);
    }
    if (typeof github_url !== 'undefined') {
      updateParts.push(`github_url = $${idx++}`);
      params.push(github_url || null);
    }

    if (updateParts.length === 0) {
      return res.status(400).json({ message: 'No updates provided' });
    }

    const sql = `UPDATE users SET ${updateParts.join(', ')} WHERE id = $${idx} RETURNING id, username, skills, bio, github_url`;
    params.push(userId);
    const updateRes = await db.query(sql, params);

    return res.json({ user: updateRes.rows[0] });
  } catch (err) {
    console.error("Error updating user profile:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/requests/:id/accept  -> only project owner can accept
// Also inserts into project_members (idempotent)
app.post('/api/requests/:id/accept', verifyToken, async (req, res) => {
  const requestId = parseInt(req.params.id, 10);
  const ownerId = req.user.id;

  try {
    // Only transition pending -> accepted; ensure caller is project owner.
    const updateRes = await db.query(
      `UPDATE join_requests
       SET request_status = 'accepted'
       WHERE id = $1
         AND request_status = 'pending'
         AND EXISTS (
           SELECT 1 FROM projects p
           WHERE p.id = join_requests.project_id
             AND p.created_by_id = $2
         )
       RETURNING id, request_status, user_id AS requester_id, project_id`,
      [requestId, ownerId]
    );

    if (updateRes.rowCount === 0) {
      return res.status(403).json({ message: 'Not authorized, request not found, or already handled' });
    }

    const updated = updateRes.rows[0];
    const requesterId = updated.requester_id;
    const projectId = updated.project_id;

    // Insert into project_members idempotently
    try {
      await db.query(
        `INSERT INTO project_members (project_id, user_id, role, joined_at)
         VALUES ($1, $2, 'member', NOW())
         ON CONFLICT (project_id, user_id) DO NOTHING`,
        [projectId, requesterId]
      );
    } catch (pmErr) {
      // ignore insertion errors (we tried)
      console.error("project_members insert error (ignored):", pmErr && pmErr.message);
    }

    // Compute authoritative counts:
    const ownerStatsRes = await db.query(
      `SELECT
         (SELECT COUNT(*)::int FROM join_requests jr JOIN projects p ON jr.project_id = p.id WHERE p.created_by_id = $1 AND jr.request_status = 'accepted') AS accepted_incoming,
         (SELECT COUNT(*)::int FROM join_requests WHERE user_id = $1 AND request_status = 'accepted') AS accepted_outgoing,
         (SELECT COUNT(*)::int FROM join_requests jr JOIN projects p ON jr.project_id = p.id WHERE p.created_by_id = $1 AND jr.request_status = 'pending') AS pending_incoming
       `,
      [ownerId]
    );

    const requesterStatsRes = await db.query(
      `SELECT
         (SELECT COUNT(*)::int FROM join_requests jr JOIN projects p ON jr.project_id = p.id WHERE p.created_by_id = $1 AND jr.request_status = 'accepted') AS accepted_incoming,
         (SELECT COUNT(*)::int FROM join_requests WHERE user_id = $1 AND request_status = 'accepted') AS accepted_outgoing,
         (SELECT COUNT(*)::int FROM join_requests WHERE user_id = $1 AND request_status = 'pending') AS pending_outgoing
       `,
      [requesterId]
    );

    const o = ownerStatsRes.rows[0];
    const r = requesterStatsRes.rows[0];

    const ownerOngoing = (parseInt(o.accepted_incoming, 10) || 0) + (parseInt(o.accepted_outgoing, 10) || 0);
    const requesterOngoing = (parseInt(r.accepted_incoming, 10) || 0) + (parseInt(r.accepted_outgoing, 10) || 0);

    return res.json({
      success: true,
      request: updated,
      owner_stats: {
        ongoing: ownerOngoing,
        pending_incoming: parseInt(o.pending_incoming, 10) || 0
      },
      requester_stats: {
        ongoing: requesterOngoing,
        requests_sent: parseInt(r.pending_outgoing, 10) || 0
      }
    });
  } catch (err) {
    console.error("Error accepting request:", err);
    res.status(500).json({ message: 'Could not accept request' });
  }
});

// POST /api/requests/:id/reject  -> only project owner can reject
app.post('/api/requests/:id/reject', verifyToken, async (req, res) => {
  const requestId = parseInt(req.params.id, 10);
  const ownerId = req.user.id;

  try {
    const updateRes = await db.query(
      `UPDATE join_requests
       SET request_status = 'rejected'
       WHERE id = $1
         AND request_status = 'pending'
         AND EXISTS (
           SELECT 1 FROM projects p
           WHERE p.id = join_requests.project_id
             AND p.created_by_id = $2
         )
       RETURNING id, request_status, user_id AS requester_id, project_id`,
      [requestId, ownerId]
    );

    if (updateRes.rowCount === 0) {
      return res.status(403).json({ message: 'Not authorized or request not found' });
    }

    const updated = updateRes.rows[0];
    const requesterId = updated.requester_id;

    // Compute owner stats
    const ownerStatsRes = await db.query(
      `SELECT
         (SELECT COUNT(*)::int FROM join_requests jr JOIN projects p ON jr.project_id = p.id WHERE p.created_by_id = $1 AND jr.request_status = 'accepted') AS accepted_incoming,
         (SELECT COUNT(*)::int FROM join_requests WHERE user_id = $1 AND request_status = 'accepted') AS accepted_outgoing,
         (SELECT COUNT(*)::int FROM join_requests jr JOIN projects p ON jr.project_id = p.id WHERE p.created_by_id = $1 AND jr.request_status = 'pending') AS pending_incoming
       `,
      [ownerId]
    );

    const r = ownerStatsRes.rows[0];
    const ownerOngoing = (parseInt(r.accepted_incoming, 10) || 0) + (parseInt(r.accepted_outgoing, 10) || 0);

    return res.json({
      success: true,
      request: updated,
      owner_stats: {
        ongoing: ownerOngoing,
        pending_incoming: parseInt(r.pending_incoming, 10) || 0
      }
    });
  } catch (err) {
    console.error("Error rejecting request:", err);
    res.status(500).json({ message: 'Could not reject request' });
  }
});

// ----------------- NEW: Chat-related REST endpoints -----------------

/**
 * GET /api/my-projects
 * Protected. Returns projects where current user is a member (with member lists)
 */
app.get('/api/my-projects', verifyToken, async (req, res) => {
  const userId = req.user.id;
  try {
  const projectsRes = await db.query(
    `SELECT p.* FROM project_members pm
    JOIN projects p ON pm.project_id = p.id
    WHERE pm.user_id = $1
    ORDER BY COALESCE(p.last_message_at, NOW()) DESC`,
    [userId]
  );

    const projects = projectsRes.rows || [];
    const projectIds = projects.map(p => p.id);

    let membersByProject = {};
    if (projectIds.length > 0) {
      const membersRes = await db.query(
        `SELECT pm.project_id, u.id AS user_id, u.username
         FROM project_members pm
         JOIN users u ON pm.user_id = u.id
         WHERE pm.project_id = ANY ($1::int[])
         ORDER BY pm.joined_at ASC`,
        [projectIds]
      );
      membersRes.rows.forEach(r => {
        if (!membersByProject[r.project_id]) membersByProject[r.project_id] = [];
        membersByProject[r.project_id].push({ id: r.user_id, username: r.username });
      });
    }

    const out = projects.map(p => ({ ...p, members: membersByProject[p.id] || [] }));
    res.json({ projects: out });
  } catch (err) {
    console.error("Error fetching my-projects:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * GET /api/projects/:id/members
 * Protected. Returns members for a project (only for project members).
 */
app.get('/api/projects/:id/members', verifyToken, async (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  const userId = req.user.id;
  if (!projectId) return res.status(400).json({ message: 'Invalid project id' });

  try {
    // Check membership
    const memCheck = await db.query('SELECT 1 FROM project_members WHERE project_id = $1 AND user_id = $2', [projectId, userId]);
    if (memCheck.rowCount === 0) return res.status(403).json({ message: 'Not a member' });

    const membersRes = await db.query(
      `SELECT u.id, u.username, pm.role, pm.joined_at, pm.last_read_at
       FROM project_members pm JOIN users u ON pm.user_id = u.id
       WHERE pm.project_id = $1 ORDER BY pm.joined_at ASC`,
      [projectId]
    );
    res.json({ members: membersRes.rows });
  } catch (err) {
    console.error("Error fetching project members:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * GET /api/projects/:id/messages
 * Protected. Paginated. Query params: limit (default 50), before (ISO date or message id)
 * Returns messages newest-first.
 */
app.get('/api/projects/:id/messages', verifyToken, async (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  const userId = req.user.id;
  if (!projectId) return res.status(400).json({ message: 'Invalid project id' });

  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const before = req.query.before || null; // optional cursor (ISO timestamp)

  try {
    // Verify membership
    const memCheck = await db.query('SELECT 1 FROM project_members WHERE project_id = $1 AND user_id = $2', [projectId, userId]);
    if (memCheck.rowCount === 0) return res.status(403).json({ message: 'Not a member' });

    let messagesRes;
    if (before) {
      // before is ISO timestamp
      messagesRes = await db.query(
        `SELECT m.id, m.project_id, m.sender_id, u.username AS sender_username, m.content, m.metadata, m.created_at, m.edited_at, m.deleted
         FROM messages m
         LEFT JOIN users u ON u.id = m.sender_id
         WHERE m.project_id = $1 AND m.created_at < $2 AND m.deleted = false
         ORDER BY m.created_at DESC
         LIMIT $3`,
        [projectId, before, limit]
      );
    } else {
      messagesRes = await db.query(
        `SELECT m.id, m.project_id, m.sender_id, u.username AS sender_username, m.content, m.metadata, m.created_at, m.edited_at, m.deleted
         FROM messages m
         LEFT JOIN users u ON u.id = m.sender_id
         WHERE m.project_id = $1 AND m.deleted = false
         ORDER BY m.created_at DESC
         LIMIT $2`,
        [projectId, limit]
      );
    }

    res.json({ messages: messagesRes.rows });
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * POST /api/projects/:id/read
 * Mark last_read_at for the current user in this project.
 */
app.post('/api/projects/:id/read', verifyToken, async (req, res) => {
  const projectId = parseInt(req.params.id, 10);
  const userId = req.user.id;
  if (!projectId) return res.status(400).json({ message: 'Invalid project id' });

  try {
    const update = await db.query(
      `UPDATE project_members SET last_read_at = now() WHERE project_id = $1 AND user_id = $2 RETURNING last_read_at`,
      [projectId, userId]
    );
    if (update.rowCount === 0) return res.status(403).json({ message: 'Not a member' });
    return res.json({ last_read_at: update.rows[0].last_read_at });
  } catch (err) {
    console.error("Error marking read:", err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------- SOCKET.IO (real-time chat) -----------------

// Create HTTP server and Socket.IO, attach to same port as express static files
const server = http.createServer(app);

// configure CORS only if needed; by default same-origin will work
const io = new Server(server, {
  // If you run client on a different origin, set cors.origins appropriately:
  cors: {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : true,
    methods: ['GET', 'POST']
  },
  // pingInterval etc can be set for scaling
});

// Socket auth middleware
io.use(async (socket, next) => {
  try {
    // client should send { token } inside socket.handshake.auth
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error: token missing'));

    const decoded = jwt.verify(token, SECRET_KEY);
    socket.user = decoded; // { id, email, username }
    return next();
  } catch (err) {
    console.error('Socket auth error:', err && err.message);
    return next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  const user = socket.user;
  console.log(`Socket connected: user=${user?.id} socket=${socket.id}`);

  // joinProject: user requests to join a project room (server verifies membership)
  socket.on('joinProject', async ({ projectId }, ack) => {
    try {
      projectId = parseInt(projectId, 10);
      if (!projectId) return ack && ack({ ok: false, message: 'Invalid project id' });

      const memRes = await db.query('SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2', [projectId, user.id]);
      if (memRes.rowCount === 0) {
        return ack && ack({ ok: false, message: 'Not a member of project' });
      }

      const room = `project_${projectId}`;
      socket.join(room);

      // Optionally update presence / last_seen here

      return ack && ack({ ok: true, message: 'Joined project room' });
    } catch (err) {
      console.error('joinProject error:', err);
      return ack && ack({ ok: false, message: 'Server error' });
    }
  });

  // leaveProject: leave room
  socket.on('leaveProject', ({ projectId }, ack) => {
    try {
      const room = `project_${projectId}`;
      socket.leave(room);
      return ack && ack({ ok: true });
    } catch (err) {
      console.error('leaveProject error:', err);
      return ack && ack({ ok: false, message: 'Server error' });
    }
  });

  // sendMessage: user sends a message to project (server verifies membership, writes to DB, broadcasts)
  socket.on('sendMessage', async (payload, ack) => {
    try {
      const { projectId, content, metadata } = payload || {};
      if (!projectId || !content || String(content).trim().length === 0) {
        return ack && ack({ ok: false, message: 'Invalid payload. content required.' });
      }

      // basic server-side validation
      const text = String(content).trim();
      if (text.length > 5000) return ack && ack({ ok: false, message: 'Message too long' });

      // verify membership
      const memRes = await db.query('SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2', [projectId, user.id]);
      if (memRes.rowCount === 0) return ack && ack({ ok: false, message: 'Not a member' });

      // Insert message in transaction, update project's last_message_at
      const client = await db.pool.connect();
      try {
        await client.query('BEGIN');

        const insertRes = await client.query(
          `INSERT INTO messages (project_id, sender_id, content, metadata)
           VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
          [projectId, user.id, text, metadata || {}]
        );
        const msgRow = insertRes.rows[0];

        // Update project preview fields (optional)
        await client.query(
          `UPDATE projects SET last_message_at = $1, last_message_id = $2 WHERE id = $3`,
          [msgRow.created_at, msgRow.id, projectId]
        );

        await client.query('COMMIT');

        // Build broadcast payload (include sender username)
        const messagePayload = {
          id: msgRow.id,
          project_id: projectId,
          sender_id: user.id,
          sender_username: user.username,
          content: text,
          metadata: metadata || {},
          created_at: msgRow.created_at
        };

        const room = `project_${projectId}`;
        io.to(room).emit('newMessage', messagePayload);

        // ack to sender
        return ack && ack({ ok: true, message: messagePayload });
      } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error inserting message transaction:', err);
        return ack && ack({ ok: false, message: 'DB error' });
      } finally {
        client.release();
      }
    } catch (err) {
      console.error('sendMessage error:', err);
      return ack && ack({ ok: false, message: 'Server error' });
    }
  });

  // Optional: typing indicator
  socket.on('typing', ({ projectId, isTyping }) => {
    if (!projectId) return;
    const room = `project_${projectId}`;
    socket.to(room).emit('typing', { userId: user.id, username: user.username, isTyping: !!isTyping });
  });

  socket.on('disconnect', (reason) => {
    console.log(`Socket disconnected: ${socket.id} reason=${reason}`);
    // Optionally broadcast presence change
  });
});

// Start server using http server (Socket.IO attached)
server.listen(PORT, () => {
  console.log(`⚡ Server + Socket.IO running on port ${PORT}`);
});
