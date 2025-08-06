// File: backend/index.js

const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const db = require('./db');

const SECRET_KEY = 'your-secret-key'; // 🔒 Store in env for production

// Middleware to serve static files
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// JWT verification middleware
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access denied. Token missing.' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token.' });
  }
}

// Test route
app.get('/', (req, res) => {
  res.send('🚀 CodeCollab API is running');
});

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log("📩 Received signup data:", { username, email });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *',
      [username, email, hashedPassword]
    );

    console.log("✅ User created:", result.rows[0]);
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error("❌ Signup DB Error:", err.message);

    if (err.code === '23505') {
      return res.status(400).json({ message: 'Email already exists' });
    }

    res.status(500).json({ message: 'Error creating user' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log("🔐 Login attempt:", { email });

  try {
    const result = await db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      console.warn("❌ Email not found");
      return res.status(401).send('Invalid email or password');
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      console.warn("❌ Incorrect password");
      return res.status(401).send('Invalid email or password');
    }

    // Generate JWT (optional — useful for APIs)
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '2h' });

    console.log("✅ Login successful:", user.email);

    // Send JSON response with username
    res.json({ username: user.username });

  } catch (err) {
    console.error("❌ Login DB Error:", err.message);
    res.status(500).send('Server error');
  }
});


// Serve home.html
app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/home.html'));
});

// API route to fetch all projects
app.get('/api/projects', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM projects');
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching projects:", err.message);
    res.status(500).json({ message: "Error fetching projects" });
  }
});

app.post('/api/projects', async (req, res) => {
  const { title, project_description, tech_stack, deadline, created_by } = req.body;

  try {
    const result = await db.query(
      `INSERT INTO projects (title, project_description, tech_stack, deadline, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [title, project_description, tech_stack, deadline, created_by]
    );

    res.status(201).json({ message: 'Project created', project: result.rows[0] });
  } catch (err) {
    console.error("❌ Error creating project:", err.message);
    res.status(400).json({ error: 'Failed to create project' });
  }
});


// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`⚡ Server running on port ${PORT}`);
});
