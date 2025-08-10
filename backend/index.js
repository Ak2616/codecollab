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

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: 'User created successfully', user: result.rows[0] });
  } catch (err) {
    console.error("Signup DB Error:", err.message);
    if (err.code === '23505') {
      return res.status(400).json({ message: 'Email already exists' });
    }
    res.status(500).json({ message: 'Error creating user' });
  }
});

// Login route (now returns JWT)
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
    console.error("Login DB Error:", err.message);
    res.status(500).json({ message: 'Server error' });
  }
});

// Serve home.html (still available if needed)
app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/home.html'));
});

/**
 * GET /api/projects
 * Protected. Returns:
 * { projects: [...], stats: { requests_sent, pending_requests } }
 * Projects are filtered to exclude projects created by the current user.
 * Each project includes `requested: boolean` indicating whether current user has a pending request.
 */
app.get('/api/projects', verifyToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const projectsQuery = `
      SELECT p.*,
             (jr.id IS NOT NULL) AS requested
      FROM projects p
      LEFT JOIN join_requests jr
        ON jr.project_id = p.id
        AND jr.user_id = $1
        AND jr.request_status = 'pending'
      WHERE p.created_by_id IS NULL OR p.created_by_id <> $1
      ORDER BY p.id DESC
    `;
    const projectsResult = await db.query(projectsQuery, [userId]);

    const statsQuery = `
      SELECT
        COUNT(*) FILTER (WHERE user_id = $1) AS requests_sent,
        COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'pending') AS pending_requests
      FROM join_requests
    `;
    const statsResult = await db.query(statsQuery, [userId]);

    const statsRow = statsResult.rows[0] || { requests_sent: 0, pending_requests: 0 };

    // ensure ints
    const stats = {
      requests_sent: parseInt(statsRow.requests_sent, 10) || 0,
      pending_requests: parseInt(statsRow.pending_requests, 10) || 0
    };

    res.json({ projects: projectsResult.rows, stats });
  } catch (err) {
    console.error("Error fetching projects:", err);
    res.status(500).json({ message: 'Error fetching projects' });
  }
});

/**
 * POST /api/projects
 * Protected. Uses token-derived user as creator (server-side).
 * Body: { title, project_description, tech_stack, deadline }
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

    res.status(201).json({ message: 'Project created', project: result.rows[0] });
  } catch (err) {
    console.error("Error creating project:", err);
    res.status(400).json({ error: 'Failed to create project' });
  }
});

/**
 * POST /api/join-request
 * Protected. Body: { projectId }
 * Server derives userId from token.
 * Returns authoritative counts and status.
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

    let status = 'created';
    try {
      await db.query(
        `INSERT INTO join_requests (user_id, project_id, request_status, requested_at)
         VALUES ($1, $2, 'pending', NOW())`,
        [userId, projectId]
      );
    } catch (err) {
      // Unique constraint violation for existing pending request
      if (err.code === '23505') { // unique_violation
        status = 'already_pending';
      } else if (err.code === '23503') { // foreign key violation (shouldn't happen due to pre-check, but safe)
        return res.status(400).json({ message: 'Invalid project or user' });
      } else {
        console.error("Error inserting join_request:", err);
        return res.status(500).json({ message: 'Failed to send join request' });
      }
    }

    // Compute updated stats
    const statsResult = await db.query(
      `SELECT
         COUNT(*) FILTER (WHERE user_id = $1) AS requests_sent,
         COUNT(*) FILTER (WHERE user_id = $1 AND request_status = 'pending') AS pending_requests
       FROM join_requests`,
      [userId]
    );
    const row = statsResult.rows[0] || { requests_sent: 0, pending_requests: 0 };
    const response = {
      projectId,
      status,
      requests_sent: parseInt(row.requests_sent, 10) || 0,
      pending_requests: parseInt(row.pending_requests, 10) || 0
    };

    const code = status === 'created' ? 201 : 200;
    return res.status(code).json(response);
  } catch (err) {
    console.error("Unexpected error in join-request:", err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚡ Server running on port ${PORT}`);
});
