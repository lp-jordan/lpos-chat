'use strict';

require('dotenv').config({ path: __dirname + '/.env' });

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const PORT = process.env.PORT || 3001;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-this-secret-token';

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), { etag: false, lastModified: false, maxAge: 0, cacheControl: false }));

// ─── Auth middleware ─────────────────────────────────────────────────────────

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── HTTP routes ─────────────────────────────────────────────────────────────

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  res.json({ token: ADMIN_TOKEN });
});

app.get('/api/rooms', requireAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM rooms ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/rooms', requireAdmin, async (req, res) => {
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

app.delete('/api/rooms/:id', requireAdmin, async (req, res) => {
  try {
    await db.query('DELETE FROM rooms WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/rooms/:id/messages', requireAdmin, async (req, res) => {
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

app.delete('/api/messages/:id', requireAdmin, async (req, res) => {
  try {
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

app.post('/api/rooms/:id/mute', requireAdmin, async (req, res) => {
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

app.post('/api/rooms/:id/unmute', requireAdmin, async (req, res) => {
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

app.get('/api/rooms/:id/users', requireAdmin, async (req, res) => {
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

  // De-dupe by userId (a user may have multiple tabs/connections)
  const seen = new Map();
  for (const client of clients) {
    if (!seen.has(client.userId)) {
      seen.set(client.userId, {
        userId: client.userId,
        username: client.username,
        muted: mutedSet.has(client.userId),
      });
    }
  }
  res.json([...seen.values()]);
});

const noCache = { etag: false, lastModified: false, cacheControl: false, headers: { 'Cache-Control': 'no-store' } };

// ─── Q&A routes (admin) ──────────────────────────────────────────────────────

// Toggle Q&A mode on/off for a room
app.post('/api/rooms/:id/qa', requireAdmin, async (req, res) => {
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

// Set slow mode interval (seconds; 0 = off)
app.post('/api/rooms/:id/slowmode', requireAdmin, async (req, res) => {
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
app.get('/api/rooms/:id/questions', requireAdmin, async (req, res) => {
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
app.post('/api/questions/:id/approve', requireAdmin, async (req, res) => {
  try {
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
app.post('/api/questions/:id/deny', requireAdmin, async (req, res) => {
  try {
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
app.post('/api/questions/:id/remove', requireAdmin, async (req, res) => {
  try {
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

// ─── In-memory rooms map ─────────────────────────────────────────────────────
// Map<roomId, Set<{ ws, userId, username }>>

const rooms = new Map();

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
    if (client.userId !== 'admin') ids.add(client.userId);
  }
  broadcastToRoom(roomId, { type: 'presence', count: ids.size });
}

// Broadcast only to admin connections (userId === 'admin') in a room
function broadcastToAdmins(roomId, data) {
  const clients = rooms.get(roomId);
  if (!clients) return;
  const payload = JSON.stringify(data);
  for (const client of clients) {
    if (client.userId === 'admin' && client.ws.readyState === WebSocket.OPEN) {
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
        const result = await db.query('SELECT id, qa_active, slow_seconds FROM rooms WHERE id = $1', [roomId]);
        roomRow = result.rows[0];
      } catch (err) {
        console.error('[ws] join db error', err);
        return;
      }
      if (!roomRow) {
        ws.send(JSON.stringify({ type: 'error', message: 'Room not found' }));
        return;
      }

      currentRoomId = roomId;
      currentUserId = userId;
      currentUsername = username;
      clientRef = { ws, userId, username };
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

      const content = String(msg.content || '').trim().substring(0, 500);
      if (!content) return;

      // Rate limit (slow mode + flood protection)
      const rc = rateCheck(currentRoomId, currentUserId);
      if (!rc.ok) {
        ws.send(JSON.stringify({ type: 'rate_limited', reason: rc.reason, retryAfter: rc.retryAfter }));
        return;
      }
      rateRecord(currentRoomId, currentUserId);

      try {
        const ins = await db.query(
          `INSERT INTO messages (room_id, user_id, username, content)
           VALUES ($1, $2, $3, $4)
           RETURNING id, room_id, user_id, username, content, created_at`,
          [currentRoomId, currentUserId, currentUsername, content]
        );
        const row = ins.rows[0];
        broadcastToRoom(currentRoomId, {
          type: 'message',
          id: row.id,
          roomId: row.room_id,
          userId: row.user_id,
          username: row.username,
          content: row.content,
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
