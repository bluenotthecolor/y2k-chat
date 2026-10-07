const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, "public");
const DATA_FILE =
  process.env.DATA_FILE || path.join(__dirname, "messages.jsonl");
const USERS_FILE =
  process.env.USERS_FILE || path.join(__dirname, "users.jsonl");

// Owner-only commands. Set ADMIN_KEY to a long secret. In the chat type: /login <key>
// If you don't set it, a random one is made once and saved in admin.key next to server.js.
const ADMIN_KEY_FILE = path.join(__dirname, "admin.key");
const BANS_FILE = process.env.BANS_FILE || path.join(__dirname, "bans.jsonl");
function getAdminKey() {
  if (process.env.ADMIN_KEY) return process.env.ADMIN_KEY;
  try {
    const k = fs.readFileSync(ADMIN_KEY_FILE, "utf8").trim();
    if (k) return k;
  } catch {}
  const k = crypto.randomBytes(16).toString("hex");
  try {
    fs.writeFileSync(ADMIN_KEY_FILE, k + "\n", { mode: 0o600 });
  } catch (e) {
    console.error("could not save admin.key:", e.message);
  }
  return k;
}
const ADMIN_KEY = getAdminKey();
const ADMIN_KEY_HASH = crypto.createHash("sha256").update(ADMIN_KEY).digest();
function isAdminKey(k) {
  if (typeof k !== "string" || k.length > 200) return false;
  const h = crypto.createHash("sha256").update(k).digest();
  return crypto.timingSafeEqual(h, ADMIN_KEY_HASH);
}

const MAX_LEN = 280;
const PAGE_SIZE = 50; // messages sent per page (first load + each "load older")
const MAX_STORED = 50000; // how many messages are kept in memory (file keeps everything)
const MIN_GAP_MS = 800; // per-connection rate limit
const REPLY_SNIPPET = 80; // characters of the original message kept inside a reply

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css",
  ".js": "text/javascript",
  ".png": "image/png",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
};

// ---------- saved messages ----------
let messages = []; // oldest -> newest, each: { id, anon, text, ts, gif?, reply? }
let nextMsgId = 1;

function loadMessages() {
  if (!fs.existsSync(DATA_FILE)) return;
  const lines = fs.readFileSync(DATA_FILE, "utf8").split("\n");
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const m = JSON.parse(line);
      if (m && m.cleared) messages = [];
      else if (m && typeof m.del === "number")
        messages = messages.filter((x) => x.id !== m.del);
      else if (typeof m.id === "number" && typeof m.text === "string") {
        delete m.gif; // gifs were removed
        if (m.text) messages.push(m);
      }
    } catch {
      // skip a damaged line instead of crashing
    }
  }
  if (messages.length > MAX_STORED) messages = messages.slice(-MAX_STORED);
  if (messages.length) nextMsgId = messages[messages.length - 1].id + 1;
  console.log(`loaded ${messages.length} saved messages from ${DATA_FILE}`);
}
loadMessages();

// appended synchronously so /clear can safely wipe the file without racing a write
function saveMessage(m) {
  try {
    fs.appendFileSync(DATA_FILE, JSON.stringify(m) + "\n");
  } catch (e) {
    console.error("could not save message:", e.message);
  }
}

function deleteMessage(id) {
  const i = lowerBound(id);
  if (i >= messages.length || messages[i].id !== id) return false;
  messages.splice(i, 1);
  saveMessage({ del: id }); // tombstone, applied again on the next start
  return true;
}

function clearMessages() {
  messages = [];
  try {
    fs.writeFileSync(DATA_FILE, "");
  } catch (e) {
    console.error("could not clear messages file:", e.message);
  }
}

// ---------- bans (by anon number) ----------
const banned = new Set();
function loadBans() {
  if (!fs.existsSync(BANS_FILE)) return;
  for (const n of fs.readFileSync(BANS_FILE, "utf8").split("\n")) {
    const v = parseInt(n, 10);
    if (Number.isInteger(v)) banned.add(v);
  }
}
loadBans();
function saveBans() {
  try {
    fs.writeFileSync(
      BANS_FILE,
      [...banned].join("\n") + (banned.size ? "\n" : ""),
    );
  } catch (e) {
    console.error("could not save bans:", e.message);
  }
}

// messages are sorted by id: index of the first message with id >= target
function lowerBound(target) {
  let lo = 0,
    hi = messages.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (messages[mid].id < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function findById(id) {
  const i = lowerBound(id);
  return i < messages.length && messages[i].id === id ? messages[i] : null;
}

// last PAGE_SIZE messages with id < beforeId (or the newest ones if beforeId is null)
function getPage(beforeId) {
  const end = beforeId === null ? messages.length : lowerBound(beforeId);
  const start = Math.max(0, end - PAGE_SIZE);
  return { page: messages.slice(start, end), hasMore: start > 0 };
}

// ---------- anonymous identities ----------
// Each browser keeps a secret token. The server remembers token -> number, so the
// same browser is always the same anon (anon-0001, anon-0002, ...) after a refresh
// or a server restart. Only a hash of the token is stored.
// The number of known tokens is also the real visitor count: one browser = one visitor.
const userByHash = new Map(); // sha256(token) -> number
let nextAnonNumber = 1;

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return;
  for (const line of fs.readFileSync(USERS_FILE, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const u = JSON.parse(line);
      if (typeof u.h === "string" && Number.isInteger(u.n)) {
        userByHash.set(u.h, u.n);
        if (u.n >= nextAnonNumber) nextAnonNumber = u.n + 1;
      }
    } catch {
      // skip a damaged line
    }
  }
  console.log(`loaded ${userByHash.size} known anons from ${USERS_FILE}`);
}
loadUsers();

const userStream = fs.createWriteStream(USERS_FILE, { flags: "a" });
userStream.on("error", (e) => console.error("could not save user:", e.message));

function getAnonNumber(token) {
  const h = hashToken(token);
  let n = userByHash.get(h);
  if (n === undefined) {
    n = nextAnonNumber++;
    userByHash.set(h, n);
    userStream.write(JSON.stringify({ h, n }) + "\n");
  }
  return n;
}

const TOKEN_RE = /^[a-f0-9]{32}$/;

// ---------- http ----------
const server = http.createServer((req, res) => {
  let urlPath = req.url.split("?")[0];
  if (urlPath === "/") urlPath = "/index.html";
  if (urlPath === "/favicon.ico") {
    res.writeHead(204);
    return res.end();
  }
  let filePath;
  try {
    filePath = path.normalize(path.join(PUBLIC, decodeURIComponent(urlPath)));
  } catch {
    res.writeHead(400);
    return res.end("bad request");
  }
  if (!filePath.startsWith(PUBLIC)) {
    res.writeHead(403);
    return res.end("nope");
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end("404 - page not found (very 1999 of us)");
    }
    const ext = path.extname(filePath);
    const headers = { "Content-Type": MIME[ext] || "application/octet-stream" };
    if (ext === ".gif") headers["Cache-Control"] = "public, max-age=86400";
    res.writeHead(200, headers);
    res.end(data);
  });
});

// ---------- websocket ----------
const wss = new WebSocketServer({ server, maxPayload: 4096 });

function broadcast(obj) {
  const msg = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(msg);
  }
}

function sendOnlineCount() {
  broadcast({
    type: "online",
    count: wss.clients.size,
    visitors: userByHash.size,
  });
}

function sys(ws, text) {
  if (ws.readyState === 1) ws.send(JSON.stringify({ type: "sys", text }));
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

function runCommand(ws, line) {
  const [cmdRaw, ...rest] = line.split(/\s+/);
  const cmd = cmdRaw.slice(1).toLowerCase();
  const arg = rest.join(" ").trim();

  if (cmd === "help") {
    HELP.forEach((l) => sys(ws, l));
  } else if (cmd === "clear") {
    if (arg === "") {
      clearMessages();
      broadcast({ type: "cleared" });
    } else {
      const n = parseInt(arg, 10);
      if (!Number.isInteger(n) || n < 1 || n > 1000)
        return sys(ws, "usage: /clear  or  /clear <1-1000>");
      const ids = messages.slice(-n).map((m) => m.id);
      ids.forEach((id) => {
        deleteMessage(id);
        broadcast({ type: "deleted", id });
      });
      sys(ws, `deleted ${ids.length} message(s)`);
    }
  } else if (cmd === "ban" || cmd === "unban") {
    const n = parseInt(arg.replace(/^anon-/i, ""), 10);
    if (!Number.isInteger(n)) return sys(ws, `usage: /${cmd} <anon number>`);
    if (cmd === "ban") {
      if (n === ws.anonId) return sys(ws, "you can't ban yourself");
      banned.add(n);
    } else banned.delete(n);
    saveBans();
    sys(
      ws,
      `${cmd === "ban" ? "banned" : "unbanned"} anon-${String(n).padStart(4, "0")}`,
    );
  } else if (cmd === "bans") {
    sys(
      ws,
      banned.size
        ? "banned: " +
            [...banned]
              .map((n) => "anon-" + String(n).padStart(4, "0"))
              .join(", ")
        : "nobody is banned",
    );
  } else if (cmd === "announce") {
    if (!arg) return sys(ws, "usage: /announce <text>");
    broadcast({ type: "sys", text: "ANNOUNCEMENT: " + arg.slice(0, 200) });
  } else if (cmd === "stats") {
    sys(
      ws,
      `${messages.length} messages saved, ${wss.clients.size} online, ${userByHash.size} visitors, ${banned.size} banned`,
    );
  } else if (cmd === "logout") {
    ws.isAdmin = false;
    ws.send(JSON.stringify({ type: "admin", on: false }));
  } else {
    sys(ws, "unknown command - try /help");
  }
}

wss.on("connection", (ws, req) => {
  // returning browsers send their token; new browsers get one from us
  let token = null;
  try {
    token = new URL(req.url, "http://localhost").searchParams.get("t");
  } catch {}
  if (!token || !TOKEN_RE.test(token))
    token = crypto.randomBytes(16).toString("hex");

  ws.anonId = getAnonNumber(token);
  ws.lastMsgAt = 0;
  ws.lastHistoryAt = 0;
  ws.isAdmin = false;
  ws.loginFails = 0;

  const { page, hasMore } = getPage(null);
  ws.send(
    JSON.stringify({
      type: "welcome",
      you: ws.anonId,
      token,
      history: page,
      hasMore,
      visits: userByHash.size,
    }),
  );
  sendOnlineCount();

  ws.on("message", async (raw) => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!data || typeof data !== "object") return;

    // client scrolled to the top and wants older messages
    if (data.type === "history") {
      const before = Number(data.before);
      if (!Number.isFinite(before)) return;
      const now = Date.now();
      if (now - ws.lastHistoryAt < 300) return;
      ws.lastHistoryAt = now;
      const { page, hasMore } = getPage(before);
      ws.send(JSON.stringify({ type: "history", messages: page, hasMore }));
      return;
    }

    // owner login: the key is checked here and never broadcast
    if (data.type === "login") {
      if (ws.loginFails >= 5) return;
      if (isAdminKey(data.key)) {
        ws.isAdmin = true;
        ws.send(JSON.stringify({ type: "admin", on: true }));
      } else {
        ws.loginFails++;
        ws.isAdmin = false;
        ws.send(JSON.stringify({ type: "admin", on: false }));
        if (ws.loginFails >= 5) ws.close();
      }
      return;
    }
    if (data.type === "logout") {
      ws.isAdmin = false;
      ws.send(JSON.stringify({ type: "admin", on: false }));
      return;
    }

    // owner deletes a single message with its [del] button
    if (data.type === "delete") {
      if (!ws.isAdmin) return;
      const id = Number(data.id);
      if (deleteMessage(id)) broadcast({ type: "deleted", id });
      return;
    }

    if (data.type !== "msg") return;

    if (banned.has(ws.anonId)) {
      return ws.send(
        JSON.stringify({ type: "sys", text: "you are banned from this chat" }),
      );
    }

    // owner commands start with "/" - nobody else can run them
    if (
      ws.isAdmin &&
      typeof data.text === "string" &&
      /^\/[a-z]/i.test(data.text)
    ) {
      return runCommand(ws, data.text.trim());
    }

    const text =
      typeof data.text === "string"
        ? data.text.replace(/\s+/g, " ").trim().slice(0, MAX_LEN)
        : "";
    if (!text) return;

    const now = Date.now();
    if (now - ws.lastMsgAt < MIN_GAP_MS) {
      return ws.send(JSON.stringify({ type: "slow" }));
    }
    ws.lastMsgAt = now;

    // reply: keep a short snapshot of the original so it still reads fine later
    let reply = null;
    if (data.replyTo !== undefined && data.replyTo !== null) {
      const orig = findById(Number(data.replyTo));
      if (orig) {
        reply = {
          id: orig.id,
          anon: orig.anon,
          text: orig.text.slice(0, REPLY_SNIPPET),
        };
      }
    }

    const message = { id: nextMsgId++, anon: ws.anonId, text, ts: now };
    if (reply) message.reply = reply;

    messages.push(message);
    if (messages.length > MAX_STORED) messages.shift();
    saveMessage(message);
    broadcast({ type: "msg", ...message });
  });

  ws.on("close", sendOnlineCount);
});

server.listen(PORT, () => {
  console.log(`y2k chat running on http://localhost:${PORT}`);
  console.log(
    process.env.ADMIN_KEY
      ? "owner key: from ADMIN_KEY"
      : `owner key: ${ADMIN_KEY} (saved in admin.key) - in the chat type /login <key>`,
  );
});
