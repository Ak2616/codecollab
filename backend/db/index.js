// File: backend/db/index.js

const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'codecollab',
  password: 'postgres',
  port: 5432,
});

pool.connect()
  .then(() => {
    console.log('✅ Connected to PostgreSQL');
  })
  .catch((err) => {
    console.error('❌ PostgreSQL connection error:', err);
  });

// Export a query function to maintain clean abstraction
module.exports = {
  query: (text, params) => pool.query(text, params),
};
