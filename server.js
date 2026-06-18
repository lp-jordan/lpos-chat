'use strict';

require('dotenv').config({ path: __dirname + '/.env' });

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const auth = require('./auth');

const PORT = process.env.PORT || 3001;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), { etag: false, lastModified: false, maxAge: 0, cacheControl: false }));

// ─── Auth resolution ─────────────────────────────────────────────────────────

function extractToken(req) {
  return req.headers['x-admin-token'] || req.query.token || null;
}

// Resolve a session OR moderator-link token. Returns null when invalid.
//   session: { kind:'session', userId, email, role }
//   link:    { kind:'link', role:'moderator', roomId, linkToken }
async function resolveAuth(tokenStr) {
  if (!tokenStr || typeof tokenStr !== 'string') return null;
  try {
    const s = await db.query(
      `SELECT s.token, u.id AS user_id, u.email, u.role, u.disabled
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token = $1 AND s.expires_at > NOW()`,
      [tokenStr]
    );
    if (s.rows.length > 0) {
      const row = s.rows[0];
      if (row.disabled) return null;
      return { kind: 'session', userId: row.user_id, email: row.email, role: row.role };
    }
    const l = await db.query(
      `SELECT token, room_id FROM moderator_links
       WHERE token = $1 AND revoked = FALSE
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [tokenStr]
    );
    if (l.rows.length > 0) {
      return { kind: 'link', role: 'moderator', roomId: l.rows[0].room_id, linkToken: l.rows[0].token };
    }
  } catch (err) {
    console.error('[auth] resolveAuth error', err);
  }
  return null;
}

async function requireAuth(req, res, next) {
  const a = await resolveAuth(extractToken(req));
  if (!a) return res.status(401).json({ error: 'Unauthorized' });
  req.auth = a;
  next();
}

function requireAdminRole(req, res, next) {
  const a = req.auth;
  if (a && a.kind === 'session' && (a.role === 'owner' || a.role === 'admin')) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

async function canModerateRoom(req, roomId) {
  const a = req.auth;
  if (!a) return false;
  if (a.kind === 'session' && (a.role === 'owner' || a.role === 'admin')) return true;
  if (a.kind === 'link') return a.roomId === roomId;
  if (a.kind === 'session') {
    try {
      const r = await db.query(
        'SELECT 1 FROM room_moderators WHERE room_id = $1 AND user_id = $2',
        [roomId, a.userId]
      );
      return r.rows.length > 0;
    } catch (err) {
      console.error('[auth] canModerateRoom error', err);
      return false;
    }
  }
  return false;
}

async function requireRoomModerator(req, res, next) {
  const roomId = req.params.id;
  if (await canModerateRoom(req, roomId)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

// ─── HTTP routes ─────────────────────────────────────────────────────────────

app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  try {
    const r = await db.query(
      'SELECT id, email, role, password_hash, disabled FROM users WHERE email = $1',
      [String(email).trim().toLowerCase()]
    );
    const user = r.rows[0];
    if (!user || user.disabled || !auth.verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = auth.randomToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    await db.query(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)',
      [token, user.id, expiresAt]
    );
    res.json({ token, role: user.role, email: user.email, expiresAt: expiresAt.toISOString() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/admin/logout', requireAuth, async (req, res) => {
  try {
    if (req.auth.kind === 'session') {
      await db.query('DELETE FROM sessions WHERE token = $1', [extractToken(req)]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  const a = req.auth;
  res.json({
    kind: a.kind,
    email: a.kind === 'session' ? a.email : null,
    role: a.role,
    roomId: a.kind === 'link' ? a.roomId : null,
  });
});

// ─── User management (owner/admin only) ──────────────────────────────────────

const VALID_ROLES = ['owner', 'admin', 'moderator'];

app.get('/api/users', requireAuth, requireAdminRole, async (req, res) => {
  try {
    const r = await db.query(
      'SELECT id, email, role, disabled, created_at FROM users ORDER BY created_at ASC'
    );
    res.json(r.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/users', requireAuth, requireAdminRole, async (req, res) => {
  let { email, password, role } = req.body || {};
  email = (email == null ? '' : String(email)).trim().toLowerCase();
  role = VALID_ROLES.includes(role) ? role : 'moderator';
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  try {
    const exists = await db.query('SELECT 1 FROM users WHERE email = $1', [email]);
    if (exists.rows.length > 0) return res.status(409).json({ error: 'Email already in use' });
    const r = await db.query(
      `INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)
       RETURNING id, email, role, disabled, created_at`,
      [email, auth.hashPassword(password), role]
    );
    res.json(r.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Count of enabled owners (used for last-owner guards)
async function enabledOwnerCount() {
  const r = await db.query(
    `SELECT COUNT(*)::int AS n FROM users WHERE role = 'owner' AND disabled = FALSE`
  );
  return r.rows[0].n;
}

app.patch('/api/users/:id', requireAuth, requireAdminRole, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  const { role, disabled, password } = req.body || {};
  try {
    const cur = await db.query('SELECT id, role, disabled FROM users WHERE id = $1', [id]);
    if (cur.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const user = cur.rows[0];

    // Guard: do not let the last enabled owner be demoted or disabled.
    const losingOwner =
      (user.role === 'owner' && !user.disabled) &&
      ((role && role !== 'owner') || disabled === true);
    if (losingOwner && (await enabledOwnerCount()) <= 1) {
      return res.status(400).json({ error: 'Cannot remove the last owner' });
    }

    const sets = [];
    const params = [];
    if (role !== undefined) {
      if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
      params.push(role); sets.push(`role = $${params.length}`);
    }
    if (disabled !== undefined) {
      params.push(!!disabled); sets.push(`disabled = $${params.length}`);
    }
    if (password !== undefined && password) {
      params.push(auth.hashPassword(password)); sets.push(`password_hash = $${params.length}`);
    }
    if (sets.length === 0) return res.json({ ok: true });
    params.push(id);
    const r = await db.query(
      `UPDATE users SET ${sets.join(', ')} WHERE id = $${params.length}
       RETURNING id, email, role, disabled, created_at`,
      params
    );
    res.json(r.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/users/:id', requireAuth, requireAdminRole, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  try {
    const cur = await db.query('SELECT role, disabled FROM users WHERE id = $1', [id]);
    if (cur.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const user = cur.rows[0];
    if (user.role === 'owner' && !user.disabled && (await enabledOwnerCount()) <= 1) {
      return res.status(400).json({ error: 'Cannot remove the last owner' });
    }
    await db.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// ─── Room moderator assignment (owner/admin only) ────────────────────────────

app.get('/api/rooms/:id/moderators', requireAuth, requireAdminRole, async (req, res) => {
  try {
    const r = await db.query(
      `SELECT u.id, u.email, u.role, u.disabled
       FROM room_moderators rm JOIN users u ON u.id = rm.user_id
       WHERE rm.room_id = $1 ORDER BY u.email ASC`,
      [req.params.id]
    );
    res.json(r.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/rooms/:id/moderators', requireAuth, requireAdminRole, async (req, res) => {
  const userId = parseInt(req.body && req.body.userId, 10);
  if (!userId) return res.status(400).json({ error: 'userId required' });
  try {
    await db.query(
      'INSERT INTO room_moderators (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.params.id, userId]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/rooms/:id/moderators/:userId', requireAuth, requireAdminRole, async (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  if (!userId) return res.status(400).json({ error: 'Invalid userId' });
  try {
    await db.query(
      'DELETE FROM room_moderators WHERE room_id = $1 AND user_id = $2',
      [req.params.id, userId]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// ─── Moderator links (owner/admin only) ──────────────────────────────────────

app.get('/api/rooms/:id/links', requireAuth, requireAdminRole, async (req, res) => {
  try {
    const r = await db.query(
      `SELECT token, label, expires_at, revoked, created_at
       FROM moderator_links WHERE room_id = $1 ORDER BY created_at DESC`,
      [req.params.id]
    );
    res.json(r.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/rooms/:id/links', requireAuth, requireAdminRole, async (req, res) => {
  const { label } = req.body || {};
  let expiresInHours = parseFloat(req.body && req.body.expiresInHours);
  const expiresAt =
    !isNaN(expiresInHours) && expiresInHours > 0
      ? new Date(Date.now() + expiresInHours * 3600 * 1000)
      : null;
  try {
    const room = await db.query('SELECT id FROM rooms WHERE id = $1', [req.params.id]);
    if (room.rows.length === 0) return res.status(404).json({ error: 'Room not found' });
    const token = auth.randomToken();
    const r = await db.query(
      `INSERT INTO moderator_links (token, room_id, label, expires_at)
       VALUES ($1, $2, $3, $4)
       RETURNING token, label, expires_at, revoked, created_at`,
      [token, req.params.id, (label == null ? null : String(label).trim() || null), expiresAt]
    );
    res.json(r.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/links/:token/revoke', requireAuth, requireAdminRole, async (req, res) => {
  try {
    const r = await db.query(
      'UPDATE moderator_links SET revoked = TRUE WHERE token = $1 RETURNING token',
      [req.params.token]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/rooms', requireAuth, requireAdminRole, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM rooms ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/rooms', requireAuth, requireAdminRole, async (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Name is required' });
  }
  const id = crypto.randomUUID().substring(0, 8);
  try {
    await db.query('INSERT INTO rooms (id, name) VALUES ($1, $2)', [id, name.trim()]);
    res.json({ id, name: name.trim() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/rooms/:id', requireAuth, requireAdminRole, async (req, res) => {
  try {
    await db.query('DELETE FROM rooms WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/rooms/:id/messages', requireAuth, requireRoomModerator, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM messages
       WHERE room_id = $1 AND deleted = FALSE
       ORDER BY created_at DESC
       LIMIT 200`,
      [req.params.id]
    );
    res.json(result.rows.reverse());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.delete('/api/messages/:id', requireAuth, async (req, res) => {
  try {
    const lookup = await db.query('SELECT room_id FROM messages WHERE id = $1', [req.params.id]);
    if (lookup.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    if (!(await canModerateRoom(req, lookup.rows[0].room_id))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const result = await db.query(
      'UPDATE messages SET deleted = TRUE WHERE id = $1 RETURNING room_id',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    const roomId = result.rows[0].room_id;
    broadcastToRoom(roomId, { type: 'delete', messageId: parseInt(req.params.id, 10) });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/rooms/:id/mute', requireAuth, requireRoomModerator, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  try {
    await db.query(
      'INSERT INTO muted_users (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.params.id, userId]
    );
    broadcastToRoom(req.params.id, { type: 'muted', userId });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/rooms/:id/unmute', requireAuth, requireRoomModerator, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  try {
    await db.query(
      'DELETE FROM muted_users WHERE room_id = $1 AND user_id = $2',
      [req.params.id, userId]
    );
    broadcastToRoom(req.params.id, { type: 'unmuted', userId });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/rooms/:id/users', requireAuth, requireRoomModerator, async (req, res) => {
  const roomId = req.params.id;
  const clients = rooms.get(roomId);
  if (!clients) return res.json([]);

  let mutedSet = new Set();
  try {
    const result = await db.query('SELECT user_id FROM muted_users WHERE room_id = $1', [roomId]);
    mutedSet = new Set(result.rows.map((r) => r.user_id));
  } catch (err) {
    console.error('[users] mute lookup error', err);
  }

  // De-dupe by userId (a user may have multiple tabs/connections); exclude admin/mod consoles
  const seen = new Map();
  for (const client of clients) {
    if (client.isAdmin) continue;
    if (!seen.has(client.userId)) {
      seen.set(client.userId, {
        userId: client.userId,
        username: client.username,
        muted: mutedSet.has(client.userId),
        verified: isVerified(roomId, client.userId),
      });
    }
  }
  res.json([...seen.values()]);
});

// Verify / unverify a user for this session (grants a "verified" badge on their messages)
app.post('/api/rooms/:id/verify', requireAuth, requireRoomModerator, (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  if (!verifiedUsers.has(req.params.id)) verifiedUsers.set(req.params.id, new Set());
  verifiedUsers.get(req.params.id).add(userId);
  broadcastToRoom(req.params.id, { type: 'verified', userId, verified: true });
  res.json({ ok: true });
});

app.post('/api/rooms/:id/unverify', requireAuth, requireRoomModerator, (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  const s = verifiedUsers.get(req.params.id);
  if (s) s.delete(userId);
  broadcastToRoom(req.params.id, { type: 'verified', userId, verified: false });
  res.json({ ok: true });
});

// Ban / unban (harder than mute: blocks rejoin and disconnects live sockets)
app.post('/api/rooms/:id/ban', requireAuth, requireRoomModerator, async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  try {
    await db.query(
      'INSERT INTO banned_users (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.params.id, userId]
    );
    kickUser(req.params.id, userId);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/rooms/:id/unban', requireAuth, requireRoomModerator, async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  try {
    await db.query('DELETE FROM banned_users WHERE room_id = $1 AND user_id = $2', [req.params.id, userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/rooms/:id/banned', requireAuth, requireRoomModerator, async (req, res) => {
  try {
    const r = await db.query(
      'SELECT user_id FROM banned_users WHERE room_id = $1 ORDER BY user_id',
      [req.params.id]
    );
    res.json(r.rows.map((x) => x.user_id));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

const noCache = { etag: false, lastModified: false, cacheControl: false, headers: { 'Cache-Control': 'no-store' } };

// ─── Q&A routes (admin) ──────────────────────────────────────────────────────

// Toggle Q&A mode on/off for a room
app.post('/api/rooms/:id/qa', requireAuth, requireRoomModerator, async (req, res) => {
  const active = !!req.body.active;
  try {
    const r = await db.query(
      'UPDATE rooms SET qa_active = $1 WHERE id = $2 RETURNING id',
      [active, req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Room not found' });
    broadcastToRoom(req.params.id, { type: 'qa_mode', active });
    res.json({ ok: true, active });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Set or clear the pinned announcement
app.post('/api/rooms/:id/pin', requireAuth, requireRoomModerator, async (req, res) => {
  const text = (req.body.text == null ? '' : String(req.body.text)).trim().substring(0, 280);
  const value = text || null;
  try {
    const r = await db.query(
      'UPDATE rooms SET pinned_text = $1 WHERE id = $2 RETURNING id',
      [value, req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Room not found' });
    broadcastToRoom(req.params.id, { type: 'pinned', text: value });
    res.json({ ok: true, text: value });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Clear / reset a room: wipe messages, questions, votes, mutes (room itself stays)
app.post('/api/rooms/:id/clear', requireAuth, requireAdminRole, async (req, res) => {
  const roomId = req.params.id;
  try {
    await db.query('DELETE FROM messages WHERE room_id = $1', [roomId]);
    await db.query('DELETE FROM questions WHERE room_id = $1', [roomId]); // cascades question_votes
    await db.query('DELETE FROM muted_users WHERE room_id = $1', [roomId]);
    broadcastToRoom(roomId, { type: 'cleared' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Download a room transcript as CSV
app.get('/api/rooms/:id/transcript', requireAuth, requireRoomModerator, async (req, res) => {
  const roomId = req.params.id;
  try {
    const room = await db.query('SELECT name FROM rooms WHERE id = $1', [roomId]);
    if (room.rows.length === 0) return res.status(404).json({ error: 'Room not found' });
    const msgs = await db.query(
      `SELECT created_at, username, content FROM messages
       WHERE room_id = $1 AND deleted = FALSE
       ORDER BY created_at ASC`,
      [roomId]
    );
    const csvEscape = (v) => `"${String(v).replace(/"/g, '""')}"`;
    const rows = [['timestamp', 'username', 'message'].join(',')];
    for (const m of msgs.rows) {
      rows.push([csvEscape(new Date(m.created_at).toISOString()), csvEscape(m.username), csvEscape(m.content)].join(','));
    }
    const safeName = (room.rows[0].name || 'room').replace(/[^a-z0-9]+/gi, '-').toLowerCase();
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="transcript-${safeName}-${roomId}.csv"`);
    res.send(rows.join('\n'));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Set slow mode interval (seconds; 0 = off)
app.post('/api/rooms/:id/slowmode', requireAuth, requireRoomModerator, async (req, res) => {
  let seconds = parseInt(req.body.seconds, 10);
  if (isNaN(seconds) || seconds < 0) seconds = 0;
  if (seconds > 300) seconds = 300;
  try {
    const r = await db.query(
      'UPDATE rooms SET slow_seconds = $1 WHERE id = $2 RETURNING id',
      [seconds, req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Room not found' });
    roomSlow.set(req.params.id, seconds);
    broadcastToRoom(req.params.id, { type: 'slow_mode_config', seconds });
    res.json({ ok: true, seconds });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// All non-denied questions for moderation (pending + approved)
app.get('/api/rooms/:id/questions', requireAuth, requireRoomModerator, async (req, res) => {
  try {
    const r = await db.query(
      `SELECT id, user_id, username, content, status, votes, created_at
       FROM questions
       WHERE room_id = $1 AND status <> 'denied'
       ORDER BY created_at ASC`,
      [req.params.id]
    );
    res.json(r.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Approve a pending question
app.post('/api/questions/:id/approve', requireAuth, async (req, res) => {
  try {
    const look = await db.query('SELECT room_id FROM questions WHERE id = $1', [req.params.id]);
    if (look.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    if (!(await canModerateRoom(req, look.rows[0].room_id))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const r = await db.query(
      `UPDATE questions SET status = 'approved' WHERE id = $1
       RETURNING id, room_id, user_id, username, content, votes, created_at`,
      [req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const q = r.rows[0];
    broadcastToRoom(q.room_id, {
      type: 'question_approved',
      question: { id: q.id, username: q.username, content: q.content, votes: q.votes, user_id: q.user_id },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Deny (reject) a pending question — never shown publicly, no broadcast needed
app.post('/api/questions/:id/deny', requireAuth, async (req, res) => {
  try {
    const look = await db.query('SELECT room_id FROM questions WHERE id = $1', [req.params.id]);
    if (look.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    if (!(await canModerateRoom(req, look.rows[0].room_id))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const r = await db.query(
      `UPDATE questions SET status = 'denied' WHERE id = $1 RETURNING room_id`,
      [req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Remove an already-approved question — drops it live for everyone
app.post('/api/questions/:id/remove', requireAuth, async (req, res) => {
  try {
    const look = await db.query('SELECT room_id FROM questions WHERE id = $1', [req.params.id]);
    if (look.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    if (!(await canModerateRoom(req, look.rows[0].room_id))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const r = await db.query(
      `UPDATE questions SET status = 'removed' WHERE id = $1 RETURNING room_id`,
      [req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    broadcastToRoom(r.rows[0].room_id, { type: 'question_removed', id: parseInt(req.params.id, 10) });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Widget page
app.get('/room/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'widget.html'), noCache);
});

// Admin SPA
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'), noCache);
});
app.get('/admin/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'), noCache);
});

// Scoped moderator page (same SPA; client detects mod mode from URL)
app.get('/mod/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'), noCache);
});

// ─── In-memory rooms map ─────────────────────────────────────────────────────
// Map<roomId, Set<{ ws, userId, username }>>

const rooms = new Map();

// Per-session "verified" grants: roomId -> Set(userId). In-memory (per-session by design).
const verifiedUsers = new Map();
function isVerified(roomId, userId) {
  const s = verifiedUsers.get(roomId);
  return !!(s && s.has(userId));
}

// Forcibly disconnect a user's live connections in a room (used on ban)
function kickUser(roomId, userId) {
  const clients = rooms.get(roomId);
  if (!clients) return;
  for (const client of clients) {
    if (client.userId === userId && client.ws.readyState === WebSocket.OPEN) {
      try { client.ws.send(JSON.stringify({ type: 'banned', userId })); } catch (e) {}
      try { client.ws.close(); } catch (e) {}
    }
  }
}

async function isBanned(roomId, userId) {
  try {
    const r = await db.query(
      'SELECT 1 FROM banned_users WHERE room_id = $1 AND user_id = $2',
      [roomId, userId]
    );
    return r.rows.length > 0;
  } catch (err) {
    console.error('[ban] check error', err);
    return false;
  }
}

// ─── Rate limiting ───────────────────────────────────────────────────────────
// Always-on flood protection: max FLOOD_MAX sends per FLOOD_WINDOW_MS per user.
const FLOOD_WINDOW_MS = 4000;
const FLOOD_MAX = 6;
const floodLog = new Map();   // "roomId|userId" -> [timestamps]
const lastSentAt = new Map(); // "roomId|userId" -> timestamp (for slow mode)
const roomSlow = new Map();   // roomId -> slow_seconds (cached; updated on join + admin set)

// Returns { ok: true } or { ok: false, reason: 'slow'|'flood', retryAfter: seconds }
function rateCheck(roomId, userId) {
  const key = roomId + '|' + userId;
  const now = Date.now();
  const slowSeconds = roomSlow.get(roomId) || 0;

  if (slowSeconds > 0) {
    const last = lastSentAt.get(key) || 0;
    const elapsed = now - last;
    const need = slowSeconds * 1000;
    if (elapsed < need) {
      return { ok: false, reason: 'slow', retryAfter: Math.ceil((need - elapsed) / 1000) };
    }
  }

  const recent = (floodLog.get(key) || []).filter((t) => now - t < FLOOD_WINDOW_MS);
  if (recent.length >= FLOOD_MAX) {
    return { ok: false, reason: 'flood', retryAfter: Math.ceil((FLOOD_WINDOW_MS - (now - recent[0])) / 1000) };
  }
  return { ok: true };
}

function rateRecord(roomId, userId) {
  const key = roomId + '|' + userId;
  const now = Date.now();
  const recent = (floodLog.get(key) || []).filter((t) => now - t < FLOOD_WINDOW_MS);
  recent.push(now);
  floodLog.set(key, recent);
  lastSentAt.set(key, now);
}

function broadcastToRoom(roomId, data, excludeWs = null) {
  const clients = rooms.get(roomId);
  if (!clients) return;
  const payload = JSON.stringify(data);
  for (const client of clients) {
    if (client.ws !== excludeWs && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(payload);
    }
  }
}

// Broadcast presence count (distinct non-admin userIds) to a room
function broadcastPresence(roomId) {
  const clients = rooms.get(roomId);
  if (!clients) return;
  const ids = new Set();
  for (const client of clients) {
    if (!client.isAdmin) ids.add(client.userId);
  }
  broadcastToRoom(roomId, { type: 'presence', count: ids.size });
}

// Broadcast only to admin connections (userId === 'admin') in a room
function broadcastToAdmins(roomId, data) {
  const clients = rooms.get(roomId);
  if (!clients) return;
  const payload = JSON.stringify(data);
  for (const client of clients) {
    if (client.isAdmin && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(payload);
    }
  }
}

// Approved questions for a room, newest-votes first
async function approvedQuestions(roomId) {
  const r = await db.query(
    `SELECT id, user_id, username, content, votes, created_at
     FROM questions
     WHERE room_id = $1 AND status = 'approved'
     ORDER BY votes DESC, created_at ASC`,
    [roomId]
  );
  return r.rows;
}

// ─── WebSocket server ─────────────────────────────────────────────────────────

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  let currentRoomId = null;
  let currentUserId = null;
  let currentUsername = null;
  let clientRef = null;

  ws.on('message', async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (msg.type === 'join') {
      const { roomId, userId, username } = msg;
      if (!roomId || !userId || !username) return;

      // Validate room exists
      let roomRow;
      try {
        const result = await db.query('SELECT id, qa_active, slow_seconds, pinned_text FROM rooms WHERE id = $1', [roomId]);
        roomRow = result.rows[0];
      } catch (err) {
        console.error('[ws] join db error', err);
        return;
      }
      if (!roomRow) {
        ws.send(JSON.stringify({ type: 'error', message: 'Room not found' }));
        return;
      }

      // Banned users cannot join (unless they hold a valid admin/mod auth token)
      if (!msg.auth && await isBanned(roomId, userId)) {
        ws.send(JSON.stringify({ type: 'banned', userId }));
        return;
      }

      // Determine admin/moderator privilege from the supplied auth token (not userId).
      let isAdmin = false;
      if (msg.auth) {
        const a = await resolveAuth(msg.auth);
        if (a) {
          if (a.kind === 'session' && (a.role === 'owner' || a.role === 'admin')) {
            isAdmin = true;
          } else if (a.kind === 'link' && a.roomId === roomId) {
            isAdmin = true;
          } else if (a.kind === 'session' && a.role === 'moderator') {
            try {
              const rm = await db.query(
                'SELECT 1 FROM room_moderators WHERE room_id = $1 AND user_id = $2',
                [roomId, a.userId]
              );
              if (rm.rows.length > 0) isAdmin = true;
            } catch (err) {
              console.error('[ws] mod check error', err);
            }
          }
        }
      }

      currentRoomId = roomId;
      currentUserId = userId;
      currentUsername = username;
      clientRef = { ws, userId, username, isAdmin };
      roomSlow.set(roomId, roomRow.slow_seconds || 0);

      if (!rooms.has(roomId)) rooms.set(roomId, new Set());
      rooms.get(roomId).add(clientRef);

      // Send history (last 100 non-deleted)
      try {
        const hist = await db.query(
          `SELECT * FROM messages
           WHERE room_id = $1 AND deleted = FALSE
           ORDER BY created_at DESC
           LIMIT 100`,
          [roomId]
        );
        ws.send(JSON.stringify({ type: 'history', messages: hist.rows.reverse() }));
      } catch (err) {
        console.error('[ws] history error', err);
      }

      // Send current Q&A state (mode + approved questions + which this user voted for)
      try {
        const approved = await approvedQuestions(roomId);
        let votedIds = [];
        if (approved.length > 0) {
          const v = await db.query(
            `SELECT question_id FROM question_votes
             WHERE user_id = $1 AND question_id = ANY($2::int[])`,
            [userId, approved.map((q) => q.id)]
          );
          votedIds = v.rows.map((r) => r.question_id);
        }
        ws.send(JSON.stringify({
          type: 'qa_state',
          active: !!roomRow.qa_active,
          questions: approved,
          votedIds,
        }));
        ws.send(JSON.stringify({ type: 'slow_mode_config', seconds: roomRow.slow_seconds || 0 }));
        if (roomRow.pinned_text) ws.send(JSON.stringify({ type: 'pinned', text: roomRow.pinned_text }));
      } catch (err) {
        console.error('[ws] qa_state error', err);
      }

      // Presence (count distinct userIds, not raw connections)
      broadcastPresence(roomId);

    } else if (msg.type === 'question') {
      if (!currentRoomId || !currentUserId) return;
      // Only accept questions while Q&A mode is active
      try {
        const rm = await db.query('SELECT qa_active FROM rooms WHERE id = $1', [currentRoomId]);
        if (!rm.rows[0] || !rm.rows[0].qa_active) return;
        const muteCheck = await db.query(
          'SELECT 1 FROM muted_users WHERE room_id = $1 AND user_id = $2',
          [currentRoomId, currentUserId]
        );
        if (muteCheck.rows.length > 0) return;
      } catch (err) {
        console.error('[ws] question guard error', err);
        return;
      }
      const content = String(msg.content || '').trim().substring(0, 500);
      if (!content) return;

      const rcq = rateCheck(currentRoomId, currentUserId);
      if (!rcq.ok) {
        ws.send(JSON.stringify({ type: 'rate_limited', reason: rcq.reason, retryAfter: rcq.retryAfter }));
        return;
      }
      rateRecord(currentRoomId, currentUserId);

      try {
        const ins = await db.query(
          `INSERT INTO questions (room_id, user_id, username, content)
           VALUES ($1, $2, $3, $4)
           RETURNING id, user_id, username, content, status, votes, created_at`,
          [currentRoomId, currentUserId, currentUsername, content]
        );
        const q = ins.rows[0];
        // Notify admins of the new pending question
        broadcastToAdmins(currentRoomId, { type: 'question_new', question: q });
        // Acknowledge to the submitter
        ws.send(JSON.stringify({ type: 'question_submitted', id: q.id }));
      } catch (err) {
        console.error('[ws] insert question error', err);
      }

    } else if (msg.type === 'vote') {
      if (!currentRoomId || !currentUserId) return;
      const questionId = parseInt(msg.questionId, 10);
      if (!questionId) return;
      try {
        const ins = await db.query(
          `INSERT INTO question_votes (question_id, user_id) VALUES ($1, $2)
           ON CONFLICT DO NOTHING RETURNING question_id`,
          [questionId, currentUserId]
        );
        if (ins.rows.length === 0) return; // already voted
        const upd = await db.query(
          `UPDATE questions SET votes = votes + 1 WHERE id = $1 AND status = 'approved'
           RETURNING votes`,
          [questionId]
        );
        if (upd.rows.length === 0) return;
        broadcastToRoom(currentRoomId, {
          type: 'question_vote',
          id: questionId,
          votes: upd.rows[0].votes,
        });
      } catch (err) {
        console.error('[ws] vote error', err);
      }

    } else if (msg.type === 'unvote') {
      if (!currentRoomId || !currentUserId) return;
      const questionId = parseInt(msg.questionId, 10);
      if (!questionId) return;
      try {
        const del = await db.query(
          `DELETE FROM question_votes WHERE question_id = $1 AND user_id = $2 RETURNING question_id`,
          [questionId, currentUserId]
        );
        if (del.rows.length === 0) return; // wasn't voted
        const upd = await db.query(
          `UPDATE questions SET votes = GREATEST(votes - 1, 0) WHERE id = $1 AND status = 'approved'
           RETURNING votes`,
          [questionId]
        );
        if (upd.rows.length === 0) return;
        broadcastToRoom(currentRoomId, {
          type: 'question_vote',
          id: questionId,
          votes: upd.rows[0].votes,
        });
      } catch (err) {
        console.error('[ws] unvote error', err);
      }

    } else if (msg.type === 'message') {
      if (!currentRoomId || !currentUserId) return;

      // Host post: an authenticated admin/mod posting as Host — bypasses mute + rate limit.
      const asHost = clientRef && clientRef.isAdmin && msg.asHost;

      if (!asHost) {
        // Check muted
        try {
          const muteCheck = await db.query(
            'SELECT 1 FROM muted_users WHERE room_id = $1 AND user_id = $2',
            [currentRoomId, currentUserId]
          );
          if (muteCheck.rows.length > 0) return;
        } catch (err) {
          console.error('[ws] mute check error', err);
          return;
        }
      }

      const content = String(msg.content || '').trim().substring(0, 500);
      if (!content) return;

      if (!asHost) {
        // Rate limit (slow mode + flood protection)
        const rc = rateCheck(currentRoomId, currentUserId);
        if (!rc.ok) {
          ws.send(JSON.stringify({ type: 'rate_limited', reason: rc.reason, retryAfter: rc.retryAfter }));
          return;
        }
        rateRecord(currentRoomId, currentUserId);
      }

      const badge = asHost ? 'host' : (isVerified(currentRoomId, currentUserId) ? 'verified' : null);
      const displayName = asHost
        ? (String(msg.hostName || '').trim().substring(0, 40) || 'Host')
        : currentUsername;

      try {
        const ins = await db.query(
          `INSERT INTO messages (room_id, user_id, username, content, badge)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, room_id, user_id, username, content, badge, created_at`,
          [currentRoomId, currentUserId, displayName, content, badge]
        );
        const row = ins.rows[0];
        broadcastToRoom(currentRoomId, {
          type: 'message',
          id: row.id,
          roomId: row.room_id,
          userId: row.user_id,
          username: row.username,
          content: row.content,
          badge: row.badge,
          createdAt: row.created_at,
        });
      } catch (err) {
        console.error('[ws] insert message error', err);
      }
    }
  });

  ws.on('close', () => {
    if (currentRoomId && clientRef) {
      const clients = rooms.get(currentRoomId);
      if (clients) {
        clients.delete(clientRef);
        if (clients.size === 0) {
          rooms.delete(currentRoomId);
        } else {
          broadcastPresence(currentRoomId);
        }
      }
    }
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

db.init().then(() => {
  server.listen(PORT, () => {
    console.log(`[server] lpos-chat listening on port ${PORT}`);
  });
}).catch((err) => {
  console.error('[server] Failed to init DB:', err);
  process.exit(1);
});
