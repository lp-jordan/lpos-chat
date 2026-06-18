'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function query(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

async function init() {
  await query(`
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      room_id TEXT REFERENCES rooms(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      deleted BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS muted_users (
      room_id TEXT REFERENCES rooms(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      PRIMARY KEY (room_id, user_id)
    );
  `);
  // Q&A mode flag on rooms
  await query(`ALTER TABLE rooms ADD COLUMN IF NOT EXISTS qa_active BOOLEAN DEFAULT FALSE;`);
  // Slow mode interval in seconds (0 = off)
  await query(`ALTER TABLE rooms ADD COLUMN IF NOT EXISTS slow_seconds INTEGER NOT NULL DEFAULT 0;`);
  // Submitted questions (pending / approved / denied)
  await query(`
    CREATE TABLE IF NOT EXISTS questions (
      id SERIAL PRIMARY KEY,
      room_id TEXT REFERENCES rooms(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      votes INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  // One vote per user per question
  await query(`
    CREATE TABLE IF NOT EXISTS question_votes (
      question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      PRIMARY KEY (question_id, user_id)
    );
  `);
  console.log('[db] Tables ready.');
}

module.exports = { query, init };
