// File: backend/db/index.js
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.PGUSER || 'postgres',
  host: process.env.PGHOST || 'localhost',
  database: process.env.PGDATABASE || 'codecollab',
  password: process.env.PGPASSWORD || 'postgres',
  port: parseInt(process.env.PGPORT, 10) || 5432,
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL'))
  .catch((err) => console.error('❌ PostgreSQL connection error:', err));

module.exports = {
  pool, // export pool for transactions / client usage
  query: (text, params) => pool.query(text, params),
};
