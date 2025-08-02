// File: backend/index.js

const express = require('express');
const path = require('path');
const app = express();
const db = require('./db');

// Middleware to serve static files
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Test route
app.get('/', (req, res) => {
  res.send('🚀 CodeCollab API is running');
});

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  console.log("📩 Received form data:", { username, email, password });

  try {
    const result = await db.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *',
      [username, email, password]
    );

    console.log("✅ User inserted:", result.rows[0]);
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error("❌ DB Error:", err.message);

    if (err.code === '23505') {
      return res.status(400).json({ message: 'Email already exists' });
    }

    res.status(500).json({ message: 'Error creating user' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log("🔐 Login attempt:", { email, password });

  try {
    const result = await db.query(
      'SELECT * FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );

    if (result.rows.length > 0) {
      console.log("✅ Login success:", result.rows[0]);
      res.redirect('/home');
    } else {
      console.warn("❌ Invalid credentials");
      res.status(401).send('<h3>Invalid email or password</h3>');
    }
  } catch (err) {
    console.error("❌ DB Error:", err.message);
    res.status(500).send('<h3>Server error</h3>');
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

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`⚡ Server running on port ${PORT}`);
});
