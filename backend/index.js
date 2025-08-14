// File: backend/index.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const db = require('./db');

const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key'; // put real secret in env for prod

// Static files + parsers
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/**
 * verifyToken middleware
 * Expects header: Authorization: Bearer <token>
 * On success sets req.user = { id, email, username, iat, ... }
 */
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

// Test route
app.get('/', (req, res) => {
  res.send('🚀 CodeCollab API is running');
});

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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚡ Server running on port ${PORT}`);
});
