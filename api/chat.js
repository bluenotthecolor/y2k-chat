// The Lobby, Vercel edition.
//
// Vercel can't keep WebSocket connections open and its disk is wiped between
// requests, so this is the same chat room rebuilt for serverless:
//   - the page sends/receives over plain HTTP (it polls for new messages)
//   - everything is stored in Redis, so a refresh (or a redeploy) loses nothing
//
// One endpoint: POST /api/chat with a JSON body { type, token, ... }.
// It answers with { events: [...] } using the same event shapes the WebSocket
// server sends (welcome, msg, deleted, sys, admin, ...), so the page logic is shared.
"use strict";

const crypto = require("crypto");
const db = require("../lib/redis");

const P = "lobby:";
const K = {
  seq: P + "seq", // ONE counter: message ids and event numbers
  msgs: P + "messages", // sorted set: score = id, member = message JSON
  events: P + "events", // sorted set: score = seq, member = event JSON (newest MAX_EVENTS)
  users: P + "users", // hash: sha256(token) -> anon number
  anonseq: P + "anonseq",
  presence: P + "presence", // sorted set: sha256(token) -> last seen (ms)
  banned: P + "banned", // set of anon numbers
};

const MAX_LEN = 280;
const PAGE_SIZE = 50;
const MAX_STORED = 50000; // messages kept in Redis
const MIN_GAP_MS = 800; // per-anon rate limit
const REPLY_SNIPPET = 80;
const MAX_EVENTS = 300; // recent events kept for polling clients
const OVERLAP = 3; // re-read the last few events on each poll (clients de-duplicate)
const PRESENCE_MS = 60000; // "online" = seen in the last minute
const MAX_LOGIN_FAILS = 8; // per IP per 10 minutes

const TOKEN_RE = /^[a-f0-9]{32}$/;

// Owner key. On Vercel there is no disk to save a generated one on, so you must set
// ADMIN_KEY in the project's environment variables. Without it, owner mode is off.
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const sha = (s) => crypto.createHash("sha256").update(s).digest();
const shaHex = (s) => crypto.createHash("sha256").update(s).digest("hex");
const ADMIN_HASH = ADMIN_KEY ? sha(ADMIN_KEY) : null;

function keyMatches(k) {
  if (!ADMIN_HASH || typeof k !== "string" || k.length > 200) return false;
  return crypto.timingSafeEqual(sha(k), ADMIN_HASH);
}

// true only for the right key; wrong guesses are counted per IP and eventually refused
async function checkAdmin(key, ip) {
  if (typeof key !== "string" || !key || !ADMIN_HASH) return false;
  const lf = P + "lf:" + shaHex(ip);
  const fails = Number(await db.cmd(["GET", lf])) || 0;
  if (fails >= MAX_LOGIN_FAILS) return false;
  if (keyMatches(key)) return true;
  await db.pipeline([
    ["INCR", lf],
    ["EXPIRE", lf, 600],
  ]);
  return false;
}

const pad = (n) => "anon-" + String(n).padStart(4, "0");
const sys = (text) => ({ type: "sys", text });
const parse = (s) => {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
};

// ---------- anonymous identities (token -> anon number) ----------
const anonCache = new Map(); // per warm instance; the mapping never changes
async function getAnon(h) {
  if (anonCache.has(h)) return anonCache.get(h);
  let n = await db.cmd(["HGET", K.users, h]);
  if (n === null || n === undefined) {
    const fresh = await db.cmd(["INCR", K.anonseq]);
    const won = await db.cmd(["HSETNX", K.users, h, fresh]);
    n = Number(won) === 1 ? fresh : await db.cmd(["HGET", K.users, h]);
  }
  n = Number(n);
  if (anonCache.size > 5000) anonCache.clear();
  anonCache.set(h, n);
  return n;
}

// a broadcast event every polling client will pick up
async function pushEvent(ev) {
  const seq = Number(await db.cmd(["INCR", K.seq]));
  const e = { ...ev, seq };
  await db.pipeline([
    ["ZADD", K.events, seq, JSON.stringify(e)],
    ["ZREMRANGEBYRANK", K.events, 0, -(MAX_EVENTS + 1)],
  ]);
  return e;
}

// ---------- actions ----------
async function hello(token, h) {
  const anon = await getAnon(h);
  const now = Date.now();
  // the event counter is read FIRST so nothing posted while we load can be missed
  const r = await db.pipeline([
    ["GET", K.seq],
    ["ZREVRANGEBYSCORE", K.msgs, "+inf", "-inf", "LIMIT", 0, PAGE_SIZE + 1],
    ["HLEN", K.users],
    ["ZADD", K.presence, now, h],
    ["ZREMRANGEBYSCORE", K.presence, "-inf", now - PRESENCE_MS],
    ["ZCARD", K.presence],
  ]);
  const rows = (r[1] || []).map(parse).filter(Boolean); // newest first
  const hasMore = rows.length > PAGE_SIZE;
  const history = rows.slice(0, PAGE_SIZE).reverse();
  const visits = Number(r[2]) || 0;
  return {
    events: [
      {
        type: "welcome",
        you: anon,
        token,
        history,
        hasMore,
        visits,
        eventSeq: Number(r[0]) || 0,
      },
    ],
    online: Number(r[5]) || 0,
    visitors: visits,
  };
}

async function poll(body, h) {
  const since = Math.max(0, Math.floor(Number(body.since)) || 0);
  const now = Date.now();
  const cmds = [["GET", K.seq]];
  if (body.ping) {
    cmds.push(
      ["ZADD", K.presence, now, h],
      ["ZREMRANGEBYSCORE", K.presence, "-inf", now - PRESENCE_MS],
      ["ZCARD", K.presence],
      ["HLEN", K.users],
    );
  }
  const r = await db.pipeline(cmds);
  const seq = Number(r[0]) || 0;
  const out = { events: [], seq };
  if (body.ping) {
    out.online = Number(r[3]) || 0;
    out.visitors = Number(r[4]) || 0;
  }
  // far behind (or the database was reset): tell the page to reload from scratch
  if (seq < since || seq - since > MAX_EVENTS - 50) {
    out.resync = true;
    return out;
  }
  if (seq > since) {
    const rows = await db.cmd([
      "ZRANGEBYSCORE",
      K.events,
      "(" + Math.max(0, since - OVERLAP),
      "+inf",
      "LIMIT",
      0,
      200,
    ]);
    out.events = (rows || []).map(parse).filter(Boolean);
  }
  return out;
}

async function history(body) {
  const before = Number(body.before);
  if (!Number.isFinite(before)) return { events: [] };
  const rows = await db.cmd([
    "ZREVRANGEBYSCORE",
    K.msgs,
    "(" + before,
    "-inf",
    "LIMIT",
    0,
    PAGE_SIZE + 1,
  ]);
  const list = (rows || []).map(parse).filter(Boolean);
  return {
    events: [
      {
        type: "history",
        messages: list.slice(0, PAGE_SIZE).reverse(),
        hasMore: list.length > PAGE_SIZE,
      },
    ],
  };
}

async function sendMessage(body, h, ip) {
  const anon = await getAnon(h);
  const isAdmin = await checkAdmin(body.key, ip);
  const raw = typeof body.text === "string" ? body.text : "";

  // owner commands start with "/" - nobody else can run them
  if (isAdmin && /^\/[a-z]/i.test(raw)) {
    return { events: await runCommand(raw.trim(), anon) };
  }

  const text = raw.replace(/\s+/g, " ").trim().slice(0, MAX_LEN);
  if (!text) return { events: [] };

  const now = Date.now();
  const cmds = [
    ["SISMEMBER", K.banned, anon],
    ["SET", P + "rl:" + anon, "1", "PX", MIN_GAP_MS, "NX"], // rate limit
  ];
  const replyId =
    body.replyTo !== undefined && body.replyTo !== null
      ? Math.floor(Number(body.replyTo))
      : NaN;
  if (Number.isFinite(replyId) && replyId > 0) {
    cmds.push(["ZRANGEBYSCORE", K.msgs, replyId, replyId]);
  }
  const r = await db.pipeline(cmds);
  if (Number(r[0]) === 1) return { events: [sys("you are banned from this chat")] };
  if (r[1] === null) return { events: [{ type: "slow" }] };

  // reply: keep a short snapshot of the original so it still reads fine later
  let reply = null;
  if (r[2] && r[2][0]) {
    const orig = parse(r[2][0]);
    if (orig) {
      reply = {
        id: orig.id,
        anon: orig.anon,
        text: String(orig.text).slice(0, REPLY_SNIPPET),
      };
    }
  }

  const id = Number(await db.cmd(["INCR", K.seq]));
  const message = { id, anon, text, ts: now };
  if (reply) message.reply = reply;
  const event = { type: "msg", ...message, seq: id }; // message id doubles as event number
  await db.pipeline([
    ["ZADD", K.msgs, id, JSON.stringify(message)],
    ["ZADD", K.events, id, JSON.stringify(event)],
    ["ZREMRANGEBYRANK", K.events, 0, -(MAX_EVENTS + 1)],
    ["ZREMRANGEBYRANK", K.msgs, 0, -(MAX_STORED + 1)],
  ]);
  return { events: [event] };
}

async function deleteOne(body, ip) {
  if (!(await checkAdmin(body.key, ip))) return { events: [] };
  const id = Number(body.id);
  if (!Number.isInteger(id)) return { events: [] };
  const removed = await db.cmd(["ZREMRANGEBYSCORE", K.msgs, id, id]);
  if (Number(removed) < 1) return { events: [] };
  return { events: [await pushEvent({ type: "deleted", id })] };
}

const HELP = [
  "/clear            wipe the whole chat for everyone",
  "/clear <n>        delete the last n messages",
  "/ban <anon#>      ban an anon (e.g. /ban 12)",
  "/unban <anon#>    lift a ban",
  "/bans             list banned anons",
  "/announce <text>  post a notice to everyone",
  "/stats            messages / online / visitors",
  "/logout           leave owner mode",
];

async function runCommand(line, anon) {
  const [cmdRaw, ...rest] = line.split(/\s+/);
  const cmd = cmdRaw.slice(1).toLowerCase();
  const arg = rest.join(" ").trim();

  if (cmd === "help") return HELP.map(sys);

  if (cmd === "clear") {
    if (arg === "") {
      await db.cmd(["DEL", K.msgs]);
      return [await pushEvent({ type: "cleared" })];
    }
    const n = parseInt(arg, 10);
    if (!Number.isInteger(n) || n < 1 || n > 1000)
      return [sys("usage: /clear  or  /clear <1-1000>")];
    const members = await db.cmd(["ZRANGE", K.msgs, -n, -1]);
    const ids = (members || []).map(parse).filter(Boolean).map((m) => m.id);
    if (!ids.length) return [sys("deleted 0 message(s)")];
    await db.cmd(["ZREMRANGEBYRANK", K.msgs, -n, -1]);
    return [
      await pushEvent({ type: "deletedMany", ids }),
      sys(`deleted ${ids.length} message(s)`),
    ];
  }

  if (cmd === "ban" || cmd === "unban") {
    const n = parseInt(arg.replace(/^anon-/i, ""), 10);
    if (!Number.isInteger(n)) return [sys(`usage: /${cmd} <anon number>`)];
    if (cmd === "ban") {
      if (n === anon) return [sys("you can't ban yourself")];
      await db.cmd(["SADD", K.banned, n]);
    } else {
      await db.cmd(["SREM", K.banned, n]);
    }
    return [sys(`${cmd === "ban" ? "banned" : "unbanned"} ${pad(n)}`)];
  }

  if (cmd === "bans") {
    const list = ((await db.cmd(["SMEMBERS", K.banned])) || [])
      .map(Number)
      .sort((a, b) => a - b);
    return [sys(list.length ? "banned: " + list.map(pad).join(", ") : "nobody is banned")];
  }

  if (cmd === "announce") {
    if (!arg) return [sys("usage: /announce <text>")];
    return [await pushEvent({ type: "sys", text: "ANNOUNCEMENT: " + arg.slice(0, 200) })];
  }

  if (cmd === "stats") {
    const now = Date.now();
    const r = await db.pipeline([
      ["ZCARD", K.msgs],
      ["ZREMRANGEBYSCORE", K.presence, "-inf", now - PRESENCE_MS],
      ["ZCARD", K.presence],
      ["HLEN", K.users],
      ["SCARD", K.banned],
    ]);
    return [sys(`${r[0]} messages saved, ${r[2]} online, ${r[3]} visitors, ${r[4]} banned`)];
  }

  if (cmd === "logout") return [{ type: "admin", on: false }];

  return [sys("unknown command - try /help")];
}

// ---------- entry point ----------
async function handle(body, ip) {
  const type = body.type;

  let token = body.token;
  if (type === "hello") {
    if (!TOKEN_RE.test(token)) token = crypto.randomBytes(16).toString("hex");
  } else if (!TOKEN_RE.test(token)) {
    return { events: [], resync: true };
  }
  const h = shaHex(token);

  switch (type) {
    case "hello":
      return hello(token, h);
    case "poll":
      return poll(body, h);
    case "history":
      return history(body);
    case "msg":
      return sendMessage(body, h, ip);
    case "delete":
      return deleteOne(body, ip);
    case "login": {
      const ok = await checkAdmin(body.key, ip);
      return { events: [{ type: "admin", on: ok }] };
    }
    case "bye":
      await db.cmd(["ZREM", K.presence, h]);
      return { events: [] };
    default:
      return { events: [] };
  }
}

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(obj));
}

function clientIp(req) {
  const xf = req.headers["x-vercel-forwarded-for"] || req.headers["x-forwarded-for"] || "";
  return (
    String(xf).split(",")[0].trim() ||
    (req.socket && req.socket.remoteAddress) ||
    "unknown"
  );
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") return send(res, 405, { error: "POST only" });

  let body = req.body;
  if (Buffer.isBuffer(body)) body = body.toString("utf8");
  if (typeof body === "string") {
    try {
      body = JSON.parse(body); // sendBeacon posts text/plain
    } catch {
      body = null;
    }
  }
  if (!body || typeof body !== "object") return send(res, 400, { error: "bad request" });

  // lets the page find out which kind of server it is talking to
  if (body.type === "probe") return send(res, 200, { lobby: 1, db: db.configured() });

  if (!db.configured()) {
    return send(res, 503, {
      error: "database not connected - add an Upstash Redis store to this project",
    });
  }

  try {
    send(res, 200, await handle(body, clientIp(req)));
  } catch (e) {
    console.error("chat api error:", e && e.message);
    send(res, 500, { error: "server error" });
  }
};
