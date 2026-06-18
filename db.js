'use strict';

const { Pool } = require('pg');
const auth = require('./auth');

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
  // Pinned announcement text (null/empty = none)
  await query(`ALTER TABLE rooms ADD COLUMN IF NOT EXISTS pinned_text TEXT;`);
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
  // ── Auth / authz tables (Phase A) ──
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'moderator',   -- 'owner' | 'admin' | 'moderator'
      disabled BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS room_moderators (
      room_id TEXT REFERENCES rooms(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (room_id, user_id)
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS moderator_links (
      token TEXT PRIMARY KEY,
      room_id TEXT REFERENCES rooms(id) ON DELETE CASCADE,
      label TEXT,
      expires_at TIMESTAMPTZ,
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Seed the first owner if no users exist yet.
  const userCount = await query('SELECT COUNT(*)::int AS n FROM users');
  if (userCount.rows[0].n === 0) {
    const email = process.env.ADMIN_EMAIL || 'owner@lpos.local';
    const passwordHash = auth.hashPassword(process.env.ADMIN_PASSWORD || 'changeme');
    await query(
      `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'owner')`,
      [email, passwordHash]
    );
    console.log('[db] Seeded owner account: ' + email);
  }

  console.log('[db] Tables ready.');
}

module.exports = { query, init };
