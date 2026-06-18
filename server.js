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
app.use(express.static(path.join(__dirname, 'public')));

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
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/rooms/:id/users', requireAdmin, (req, res) => {
  const roomId = req.params.id;
  const clients = rooms.get(roomId);
  if (!clients) return res.json([]);
  const users = [];
  for (const client of clients) {
    users.push({ userId: client.userId, username: client.username });
  }
  res.json(users);
});

// Widget page
app.get('/room/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'widget.html'));
});

// Admin SPA
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/admin/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── In-memory rooms map ─────────────────────────────────────────────────────
// Map<roomId, Set<{ ws, userId, username }>>

const rooms = new Map();

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
        const result = await db.query('SELECT id FROM rooms WHERE id = $1', [roomId]);
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

      // Broadcast presence
      broadcastToRoom(roomId, { type: 'presence', count: rooms.get(roomId).size });

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
          broadcastToRoom(currentRoomId, { type: 'presence', count: clients.size });
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
