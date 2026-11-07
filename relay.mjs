// Binoculars private Nostr relay.
// - Only allowlisted keys can connect (NIP-42 auth).
// - A user can read only events they wrote, or events tagged to them (#p).
// - Stores events in SQLite. Handles replaceable / addressable events and NIP-09 deletions.
import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { WebSocketServer } from 'ws';
import { verifyEvent } from 'nostr-tools/pure';
import { decode } from 'nostr-tools/nip19';

const PORT = Number(process.env.PORT || 7777);
const DATA_DIR = process.env.DATA_DIR || './data';
const RELAY_URL = process.env.RELAY_URL || `ws://localhost:${PORT}`;
const ALLOWLIST_FILE = process.env.ALLOWLIST_FILE || `${DATA_DIR}/allowlist.txt`;
const MAX_EVENT_BYTES = 256 * 1024;
const MAX_LIMIT = 5000;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- allowlist ----------
let admins = new Set(); // keys in allowlist.txt
let allowed = new Set(); // admins + members added by admins through the app
const MEMBERS_KIND = 30000;
const MEMBERS_D = 'binoculars-members';
function toHex(s) {
  s = s.trim();
  if (!s || s.startsWith('#')) return null;
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  try {
    const d = decode(s);
    if (d.type === 'npub') return d.data;
  } catch {}
  return null;
}
function loadAllowlist() {
  if (!fs.existsSync(ALLOWLIST_FILE)) fs.writeFileSync(ALLOWLIST_FILE, '# One npub or hex public key per line\n');
  const next = new Set();
  for (const line of fs.readFileSync(ALLOWLIST_FILE, 'utf8').split('\n')) {
    const hex = toHex(line.split(/\s/)[0] || '');
    if (hex) next.add(hex);
  }
  admins = next;
  recomputeAllowed();
  console.log(`admins: ${admins.size} key(s), members: ${allowed.size}`);
}
fs.watchFile(ALLOWLIST_FILE, { interval: 2000 }, loadAllowlist);

// ---------- storage ----------
const db = new DatabaseSync(`${DATA_DIR}/events.db`);
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, kind INTEGER NOT NULL,
    created_at INTEGER NOT NULL, d TEXT, raw TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS ev_author ON events(pubkey, kind, created_at);
  CREATE INDEX IF NOT EXISTS ev_kind ON events(kind, created_at);
  CREATE TABLE IF NOT EXISTS tags (id TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL);
  CREATE INDEX IF NOT EXISTS tag_lookup ON tags(name, value);
  CREATE INDEX IF NOT EXISTS tag_id ON tags(id);
`);
const q = {
  insert: db.prepare('INSERT OR IGNORE INTO events (id, pubkey, kind, created_at, d, raw) VALUES (?, ?, ?, ?, ?, ?)'),
  insertTag: db.prepare('INSERT INTO tags (id, name, value) VALUES (?, ?, ?)'),
  del: db.prepare('DELETE FROM events WHERE id = ?'),
  delTags: db.prepare('DELETE FROM tags WHERE id = ?'),
  getById: db.prepare('SELECT pubkey FROM events WHERE id = ?'),
  replaceable: db.prepare('SELECT id, created_at FROM events WHERE pubkey = ? AND kind = ? AND d IS ?'),
  membersLists: db.prepare('SELECT raw FROM events WHERE kind = ? AND d = ?'),
};

function recomputeAllowed() {
  const next = new Set(admins);
  if (typeof q !== 'undefined') {
    for (const row of q.membersLists.all(MEMBERS_KIND, MEMBERS_D)) {
      const e = JSON.parse(row.raw);
      if (!admins.has(e.pubkey)) continue;
      for (const t of e.tags) if (t[0] === 'p' && /^[0-9a-f]{64}$/.test(t[1] || '')) next.add(t[1]);
    }
  }
  allowed = next;
}
loadAllowlist();

const isReplaceable = (k) => k === 0 || k === 3 || (k >= 10000 && k < 20000);
const isAddressable = (k) => k >= 30000 && k < 40000;
const isEphemeral = (k) => k >= 20000 && k < 30000;
const dTagOf = (e) => e.tags.find((t) => t[0] === 'd')?.[1] ?? '';

function removeEvent(id) {
  q.del.run(id);
  q.delTags.run(id);
}

/** Returns [ok, message]. */
function store(e) {
  if (isEphemeral(e.kind)) return [true, ''];
  if (q.getById.get(e.id)) return [true, 'duplicate: already have this event'];
  let d = null;
  if (isReplaceable(e.kind) || isAddressable(e.kind)) {
    d = isAddressable(e.kind) ? dTagOf(e) : null;
    for (const old of q.replaceable.all(e.pubkey, e.kind, d)) {
      if (old.created_at > e.created_at || (old.created_at === e.created_at && old.id < e.id)) {
        return [true, 'duplicate: have a newer version'];
      }
      removeEvent(old.id);
    }
  }
  if (e.kind === 5) {
    for (const t of e.tags) {
      if (t[0] === 'e') {
        const row = q.getById.get(t[1]);
        if (row && row.pubkey === e.pubkey) removeEvent(t[1]);
      } else if (t[0] === 'a') {
        const [kind, pk, ...rest] = t[1].split(':');
        const dd = rest.join(':');
        if (pk === e.pubkey) {
          for (const old of q.replaceable.all(pk, Number(kind), isAddressable(Number(kind)) ? dd : null)) {
            if (old.created_at <= e.created_at) removeEvent(old.id);
          }
        }
      }
    }
  }
  q.insert.run(e.id, e.pubkey, e.kind, e.created_at, d, JSON.stringify(e));
  for (const t of e.tags) if (typeof t[0] === 'string' && t[0].length === 1 && typeof t[1] === 'string') q.insertTag.run(e.id, t[0], t[1]);
  return [true, ''];
}

// ---------- access rule ----------
// A user may read an event if they wrote it or it is addressed to them with a p tag.
function canRead(e, pk) {
  if (e.pubkey === pk) return true;
  return e.tags.some((t) => t[0] === 'p' && t[1] === pk);
}

function query(filter, pk) {
  const where = [];
  const params = [];
  const list = (col, vals) => {
    where.push(`${col} IN (${vals.map(() => '?').join(',')})`);
    params.push(...vals);
  };
  if (Array.isArray(filter.ids)) list('e.id', filter.ids.slice(0, 1000));
  if (Array.isArray(filter.authors)) list('e.pubkey', filter.authors.slice(0, 1000));
  if (Array.isArray(filter.kinds)) list('e.kind', filter.kinds.slice(0, 100).map(Number));
  if (filter.since) (where.push('e.created_at >= ?'), params.push(Number(filter.since)));
  if (filter.until) (where.push('e.created_at <= ?'), params.push(Number(filter.until)));
  for (const [key, vals] of Object.entries(filter)) {
    if (/^#[a-zA-Z]$/.test(key) && Array.isArray(vals) && vals.length) {
      where.push(`e.id IN (SELECT id FROM tags WHERE name = ? AND value IN (${vals.map(() => '?').join(',')}))`);
      params.push(key.slice(1), ...vals.slice(0, 1000));
    }
  }
  // Access rule pushed into SQL: own events, or tagged to me.
  where.push(`(e.pubkey = ? OR e.id IN (SELECT id FROM tags WHERE name = 'p' AND value = ?))`);
  params.push(pk, pk);
  const limit = Math.min(Number(filter.limit) || MAX_LIMIT, MAX_LIMIT);
  const sql = `SELECT raw FROM events e WHERE ${where.join(' AND ')} ORDER BY e.created_at DESC LIMIT ${limit}`;
  return db.prepare(sql).all(...params).map((r) => JSON.parse(r.raw));
}

function matches(f, e) {
  if (f.ids && !f.ids.includes(e.id)) return false;
  if (f.authors && !f.authors.includes(e.pubkey)) return false;
  if (f.kinds && !f.kinds.includes(e.kind)) return false;
  if (f.since && e.created_at < f.since) return false;
  if (f.until && e.created_at > f.until) return false;
  for (const [key, vals] of Object.entries(f)) {
    if (/^#[a-zA-Z]$/.test(key) && Array.isArray(vals)) {
      if (!e.tags.some((t) => t[0] === key.slice(1) && vals.includes(t[1]))) return false;
    }
  }
  return true;
}

// ---------- server ----------
const info = {
  name: 'Binoculars private relay',
  description: 'Private relay for Property Management Binoculars. Members only.',
  supported_nips: [1, 9, 11, 33, 40, 42, 59],
  software: 'binoculars-relay',
  version: '0.2.0',
  limitation: { auth_required: true, restricted_writes: true, max_message_length: MAX_EVENT_BYTES },
};

// ---------- encrypted file storage (Blossom-style) ----------
// Files arrive already encrypted by the app. Upload needs a signed kind-24242 auth event from a member.
const BLOB_DIR = `${DATA_DIR}/blobs`;
const MAX_BLOB_BYTES = 30 * 1024 * 1024;
fs.mkdirSync(BLOB_DIR, { recursive: true });

function blobAuth(req, action) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Nostr ')) return 'missing auth';
  let e;
  try {
    e = JSON.parse(Buffer.from(h.slice(6), 'base64').toString('utf8'));
  } catch {
    return 'bad auth';
  }
  if (!e || e.kind !== 24242 || !verifyEvent(e)) return 'bad auth event';
  if (!e.tags.some((t) => t[0] === 't' && t[1] === action)) return 'wrong action';
  const exp = Number(e.tags.find((t) => t[0] === 'expiration')?.[1] || 0);
  if (!exp || exp < Date.now() / 1000) return 'auth expired';
  if (!allowed.has(e.pubkey)) return 'not a member';
  return null;
}

function handleBlob(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-SHA-256');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, PUT, OPTIONS');
  if (req.method === 'OPTIONS') return res.writeHead(204).end();

  if (req.method === 'PUT' && req.url === '/upload') {
    const err = blobAuth(req, 'upload');
    if (err) return res.writeHead(401, { 'X-Reason': err }).end(err);
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BLOB_BYTES) {
        res.writeHead(413).end('file too large');
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      if (res.writableEnded) return;
      const buf = Buffer.concat(chunks);
      const sha = crypto.createHash('sha256').update(buf).digest('hex');
      fs.writeFileSync(`${BLOB_DIR}/${sha}`, buf);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ sha256: sha, size: buf.length, url: `${publicHttpUrl()}/${sha}`, uploaded: Math.floor(Date.now() / 1000) }));
    });
    return true;
  }

  const m = req.url.match(/^\/([0-9a-f]{64})(\.[a-z0-9]+)?$/);
  if (m && (req.method === 'GET' || req.method === 'HEAD')) {
    const file = `${BLOB_DIR}/${m[1]}`;
    if (!fs.existsSync(file)) return res.writeHead(404).end('not found');
    const stat = fs.statSync(file);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': stat.size, 'Cache-Control': 'public, max-age=31536000, immutable' });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
    return true;
  }
  return false;
}

function publicHttpUrl() {
  return RELAY_URL.replace(/^ws/, 'http').replace(/\/+$/, '');
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') return res.end('ok');
  if (req.method === 'PUT' || req.method === 'OPTIONS' || /^\/[0-9a-f]{64}/.test(req.url)) {
    if (handleBlob(req, res) !== false) return;
  }
  res.setHeader('Access-Control-Allow-Origin', '*');
  if ((req.headers.accept || '').includes('application/nostr+json')) {
    res.setHeader('Content-Type', 'application/nostr+json');
    return res.end(JSON.stringify(info));
  }
  res.end('Binoculars private relay. Connect with a Nostr client over WebSocket.');
});

const wss = new WebSocketServer({ server, maxPayload: MAX_EVENT_BYTES });
const clients = new Set();

wss.on('connection', (ws) => {
  const client = { ws, pubkey: null, challenge: crypto.randomBytes(16).toString('hex'), subs: new Map() };
  clients.add(client);
  const send = (msg) => ws.readyState === 1 && ws.send(JSON.stringify(msg));
  send(['AUTH', client.challenge]);

  ws.on('message', (buf) => {
    let msg;
    try {
      msg = JSON.parse(buf.toString());
    } catch {
      return send(['NOTICE', 'invalid: bad JSON']);
    }
    if (!Array.isArray(msg)) return send(['NOTICE', 'invalid: not an array']);
    const [type, ...rest] = msg;

    if (type === 'AUTH') {
      const e = rest[0];
      const ok =
        e && e.kind === 22242 && verifyEvent(e) &&
        Math.abs(Date.now() / 1000 - e.created_at) < 600 &&
        e.tags.some((t) => t[0] === 'challenge' && t[1] === client.challenge) &&
        e.tags.some((t) => t[0] === 'relay' && normalize(t[1]) === normalize(RELAY_URL));
      if (!ok) return send(['OK', e?.id ?? '', false, 'auth-required: invalid auth event']);
      if (!allowed.has(e.pubkey)) return send(['OK', e.id, false, 'restricted: this key is not a member of this relay']);
      client.pubkey = e.pubkey;
      return send(['OK', e.id, true, '']);
    }

    if (type === 'EVENT') {
      const e = rest[0];
      if (!e || typeof e.id !== 'string') return send(['NOTICE', 'invalid: missing event']);
      if (!client.pubkey) return send(['OK', e.id, false, 'auth-required: sign in first']);
      if (!allowed.has(client.pubkey)) return send(['OK', e.id, false, 'restricted: membership ended']);
      if (!verifyEvent(e)) return send(['OK', e.id, false, 'invalid: bad signature or id']);
      // Members may publish their own events, or gift-wrapped messages (kind 1059, random signer) for others.
      if (e.pubkey !== client.pubkey && e.kind !== 1059) return send(['OK', e.id, false, 'restricted: you can only publish your own events']);
      const exp = e.tags.find((t) => t[0] === 'expiration')?.[1];
      if (exp && Number(exp) < Date.now() / 1000) return send(['OK', e.id, false, 'invalid: event has expired']);
      let result;
      try {
        result = store(e);
      } catch (err) {
        console.error(err);
        return send(['OK', e.id, false, 'error: could not save']);
      }
      send(['OK', e.id, ...result]);
      if (e.kind === MEMBERS_KIND && dTagOf(e) === MEMBERS_D) recomputeAllowed();
      if (!result[1]) broadcast(e);
      return;
    }

    if (type === 'REQ') {
      const [subId, ...filters] = rest;
      if (typeof subId !== 'string') return send(['NOTICE', 'invalid: subscription id']);
      if (!client.pubkey) return send(['CLOSED', subId, 'auth-required: sign in first']);
      client.subs.set(subId, filters);
      const seen = new Set();
      for (const f of filters) {
        for (const e of query(f || {}, client.pubkey)) {
          if (!seen.has(e.id)) (seen.add(e.id), send(['EVENT', subId, e]));
        }
      }
      return send(['EOSE', subId]);
    }

    if (type === 'CLOSE') {
      client.subs.delete(rest[0]);
      return;
    }
    send(['NOTICE', `invalid: unknown message type ${type}`]);
  });

  ws.on('close', () => clients.delete(client));
  ws.on('error', () => clients.delete(client));
});

function broadcast(e) {
  for (const c of clients) {
    if (!c.pubkey || !canRead(e, c.pubkey)) continue;
    for (const [subId, filters] of c.subs) {
      if (filters.some((f) => matches(f || {}, e))) {
        c.ws.readyState === 1 && c.ws.send(JSON.stringify(['EVENT', subId, e]));
        break;
      }
    }
  }
}

function normalize(u) {
  try {
    const x = new URL(u);
    return `${x.host}${x.pathname.replace(/\/+$/, '')}`.toLowerCase();
  } catch {
    return String(u).toLowerCase();
  }
}

server.listen(PORT, () => console.log(`relay listening on :${PORT} as ${RELAY_URL}`));
