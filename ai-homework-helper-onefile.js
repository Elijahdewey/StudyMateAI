const http = require("node:http");
const crypto = require("node:crypto");
const { URL } = require("node:url");
const { DatabaseSync } = require("node:sqlite");

const PORT = Number(process.env.PORT || 8080);
const DB_PATH = process.env.AHH_DB_PATH || "./ai-homework-helper.sqlite3";
const SESSION_COOKIE = "ahh_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

const APPROVER_EMAIL = (process.env.AHH_APPROVER_EMAIL || "admin@oklahomachristianschool.edu").trim();
const ADMIN_EMAIL = (process.env.AHH_ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.AHH_ADMIN_PASSWORD || "";
const AUTO_APPROVE_EMAILS = (process.env.AHH_AUTO_APPROVE_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const AUTO_APPROVE_DOMAINS = (process.env.AHH_AUTO_APPROVE_DOMAINS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function isEmail(s) {
  if (typeof s !== "string") return false;
  const email = s.trim();
  if (email.length < 5 || email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString("base64")}$${key.toString("base64")}`;
}

function verifyPassword(password, stored) {
  try {
    const [alg, saltB64, keyB64] = String(stored || "").split("$");
    if (alg !== "scrypt" || !saltB64 || !keyB64) return false;
    const salt = Buffer.from(saltB64, "base64");
    const expected = Buffer.from(keyB64, "base64");
    const actual = crypto.scryptSync(String(password), salt, expected.length);
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

function setCookie(res, name, value, { maxAgeSec, httpOnly = true, sameSite = "Lax", secure = false, path = "/" } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`];
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");
  if (typeof maxAgeSec === "number") parts.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly`);
}

function isSecureRequest(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0].trim();
  return proto === "https";
}

function send(res, status, body, contentType) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  res.statusCode = status;
  res.setHeader("Content-Type", contentType);
  res.setHeader("Content-Length", String(buf.length));
  res.end(buf);
}

function sendJson(res, status, obj) {
  send(res, status, JSON.stringify(obj), "application/json; charset=utf-8");
}

function sendHtml(res, html) {
  send(res, 200, html, "text/html; charset=utf-8");
}

function jsonError(res, status, error) {
  sendJson(res, status, { error });
}

async function readJson(req, { limitBytes = 64 * 1024 } = {}) {
  const chunks = [];
  let total = 0;
  for await (const c of req) {
    total += c.length;
    if (total > limitBytes) throw new Error("Payload too large.");
    chunks.push(c);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("Invalid JSON.");
  }
}

function transaction(db, fn) {
  db.exec("BEGIN");
  try {
    const out = fn();
    db.exec("COMMIT");
    return out;
  } catch (e) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore
    }
    throw e;
  }
}

function initDb(db) {
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS Users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      approved_at INTEGER,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS Sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS AccessRequests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      user_id INTEGER,
      status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      decided_at INTEGER,
      decided_by INTEGER,
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE SET NULL,
      FOREIGN KEY (decided_by) REFERENCES Users(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON Sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_requests_status ON AccessRequests(status);
    CREATE INDEX IF NOT EXISTS idx_requests_email ON AccessRequests(email);
  `);
}

function cleanupExpiredSessions(db) {
  db.prepare("DELETE FROM Sessions WHERE expires_at <= ?").run(nowSec());
}

function createSession(db, userId) {
  const token = base64url(crypto.randomBytes(32));
  const tokenHash = sha256Hex(token);
  const expiresAt = nowSec() + SESSION_TTL_SECONDS;
  db.prepare("INSERT INTO Sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)").run(userId, tokenHash, expiresAt);
  return { token, expiresAt };
}

function emailIsAutoApproved(email) {
  const e = String(email || "").trim().toLowerCase();
  if (!isEmail(e)) return false;
  if (AUTO_APPROVE_EMAILS.includes(e)) return true;
  const domain = e.split("@")[1] || "";
  if (domain && AUTO_APPROVE_DOMAINS.includes(domain)) return true;
  return false;
}

function ensureAdminUser(db) {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) return;
  const exists = db.prepare("SELECT id FROM Users WHERE role = 'admin' LIMIT 1").get();
  if (exists) return;
  try {
    db.prepare("INSERT INTO Users (email, password, role, approved_at) VALUES (?, ?, 'admin', ?)").run(
      ADMIN_EMAIL,
      hashPassword(ADMIN_PASSWORD),
      nowSec(),
    );
    console.log(`Created admin user: ${ADMIN_EMAIL}`);
  } catch {
    // ignore
  }
}

function authUser(db, req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const tokenHash = sha256Hex(token);
  const row = db
    .prepare(
      `
      SELECT Sessions.user_id, Sessions.expires_at, Users.email, Users.role, Users.approved_at
      FROM Sessions
      JOIN Users ON Users.id = Sessions.user_id
      WHERE Sessions.token_hash = ?
    `,
    )
    .get(tokenHash);
  if (!row) return null;
  if (Number(row.expires_at) <= nowSec()) {
    db.prepare("DELETE FROM Sessions WHERE token_hash = ?").run(tokenHash);
    return null;
  }
  return {
    user: { id: row.user_id, email: row.email, role: row.role, approved_at: row.approved_at },
    sessionTokenHash: tokenHash,
  };
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const ICON_SVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="10" y1="8" x2="54" y2="56" gradientUnits="userSpaceOnUse">
      <stop stop-color="#38BDF8" />
      <stop offset="1" stop-color="#22C55E" />
    </linearGradient>
    <filter id="soft" x="-20%" y="-20%" width="140%" height="140%" color-interpolation-filters="sRGB">
      <feDropShadow dx="0" dy="6" stdDeviation="6" flood-color="#0B1220" flood-opacity="0.25" />
    </filter>
  </defs>
  <rect x="6" y="6" width="52" height="52" rx="14" fill="url(#bg)" filter="url(#soft)" />
  <path d="M32 16c-7.2 0-13 5.6-13 12.6 0 4.2 2.3 7.6 5.2 10.4 1.2 1.1 1.8 2.5 1.8 4V45c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2v-1.6c0-1.5.6-2.9 1.8-4 2.9-2.8 5.2-6.2 5.2-10.4C45 21.6 39.2 16 32 16Z"
    stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
  <path d="M26.5 30c0-2.2 1.8-4 4-4M37.5 30c0-2.2-1.8-4-4-4M28 34c1.2 1.2 2.6 1.8 4 1.8s2.8-.6 4-1.8"
    stroke="white" stroke-opacity="0.95" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />
  <path d="M26 48h12M27.5 52h9" stroke="white" stroke-width="3" stroke-linecap="round" />
  <path d="M18 24h5M41 24h5M22 20v4M42 20v4"
    stroke="white" stroke-opacity="0.95" stroke-width="2.5" stroke-linecap="round" />
  <circle cx="18" cy="24" r="2.2" fill="white" />
  <circle cx="46" cy="24" r="2.2" fill="white" />
  <circle cx="22" cy="20" r="2.0" fill="white" />
  <circle cx="42" cy="20" r="2.0" fill="white" />
</svg>`;

function homeworkHtml() {
  const approver = escapeHtml(APPROVER_EMAIL || "admin@example.com");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI Homework Helper</title>
  <link rel="icon" type="image/svg+xml" href="/ai-homework-helper-icon.svg" />
  <style>
    *{box-sizing:border-box;}
    body{margin:0;font-family:Arial,sans-serif;background:linear-gradient(180deg,#020617,#0f172a);color:white;display:flex;flex-direction:column;height:100vh;}
    header{text-align:center;padding:15px;font-size:22px;font-weight:bold;color:#38bdf8;text-shadow:0 0 10px #38bdf8;display:flex;align-items:center;justify-content:center;gap:10px;}
    .appIcon{width:22px;height:22px;flex:0 0 auto;filter:drop-shadow(0 0 10px rgba(56,189,248,.35));}
    #chat{flex:1;overflow-y:auto;padding:15px;display:flex;flex-direction:column;gap:10px;}
    .card{border:1px solid rgba(56,189,248,.35);background:rgba(30,41,59,.72);border-radius:16px;padding:14px;box-shadow:0 12px 30px rgba(2,6,23,.35);}
    .cardTitle{font-weight:800;font-size:16px;margin:0 0 6px;}
    .muted{color:rgba(226,232,240,.82);font-size:13px;line-height:1.35;}
    .pillRow{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;}
    .pill{border:1px solid rgba(56,189,248,.4);background:rgba(15,23,42,.85);color:white;padding:10px 12px;border-radius:999px;font-weight:700;cursor:pointer;}
    .pill.primary{border-color:rgba(34,197,94,.45);background:rgba(34,197,94,.95);color:#020617;}
    .tabs{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px;}
    .tab{border:1px solid rgba(56,189,248,.25);background:rgba(2,6,23,.35);color:rgba(226,232,240,.95);padding:10px 12px;border-radius:12px;font-weight:800;cursor:pointer;}
    .tab.active{border-color:rgba(56,189,248,.55);background:rgba(56,189,248,.14);}
    .authForm{margin-top:10px;display:grid;gap:10px;}
    .authForm input{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(56,189,248,.35);background:rgba(15,23,42,.9);color:white;outline:none;}
    .authForm input:focus{border-color:rgba(34,197,94,.55);box-shadow:0 0 0 4px rgba(34,197,94,.15);}
    .authError{display:none;border:1px solid rgba(248,113,113,.35);background:rgba(248,113,113,.12);color:#fecaca;border-radius:12px;padding:10px 12px;font-weight:700;font-size:13px;}
    .authError.show{display:block;}
    .disabled{opacity:.6;pointer-events:none;}
    .message{padding:12px;border-radius:12px;max-width:80%;font-size:15px;}
    .user{align-self:flex-end;background:#22c55e;color:black;}
    .ai{align-self:flex-start;background:#1e293b;border:1px solid #38bdf8;}
    .image{max-width:200px;border-radius:10px;margin-top:5px;}
    #inputArea{display:flex;padding:10px;background:#020617;border-top:1px solid #38bdf8;gap:6px;}
    #input{flex:1;padding:14px;font-size:16px;border:none;border-radius:10px;background:#0f172a;color:white;outline:none;}
    #input:disabled{opacity:.7;}
    button{padding:14px;font-size:16px;border:none;border-radius:10px;background:#38bdf8;font-weight:bold;cursor:pointer;}
    button:active{transform:scale(.95);}
    #fileInput{display:none;}
  </style>
</head>
<body>
  <header><img class="appIcon" src="/ai-homework-helper-icon.svg" alt="" /><span>AI Homework Helper</span></header>

  <div id="chat">
    <div id="accessGate" class="card">
      <div class="cardTitle">Request Permission</div>
      <div class="muted">
        Hi! To use AI Homework Helper, please request permission to access the assistant. Once approved, you’ll be able to
        ask questions, upload photos of problems, and receive step-by-step help.
      </div>

      <div class="pillRow">
        <button id="requestAccessBtn" class="pill primary" type="button">Request Access</button>
        <button id="shareAccessBtn" class="pill" type="button">Share Request</button>
        <button id="logoutBtn" class="pill" type="button" style="display:none">Logout</button>
      </div>

      <div class="tabs" aria-label="Authentication tabs">
        <button id="tabLogin" class="tab active" type="button">Login</button>
        <button id="tabCreate" class="tab" type="button">Create Account</button>
      </div>

      <form id="authForm" class="authForm">
        <input id="authEmail" type="email" inputmode="email" autocomplete="email" placeholder="Email" required />
        <input id="authPassword" type="password" autocomplete="current-password" placeholder="Password (8+ chars)" minlength="8" required />
        <div id="authError" class="authError" role="alert" aria-live="polite"></div>
        <button id="authSubmitBtn" type="submit">Login</button>
      </form>

      <div id="approvalStatus" class="muted" style="margin-top:10px;display:none"></div>
    </div>
  </div>

  <div id="inputArea">
    <button onclick="openCamera()">📷</button>
    <input id="input" placeholder="Ask a homework question..." disabled />
    <button onclick="send()">Ask</button>
    <input type="file" id="fileInput" accept="image/*" capture="environment" onchange="uploadImage(event)">
  </div>

  <script>
    const APPROVER_EMAIL = ${JSON.stringify(approver)};

    async function api(path, { method = "GET", body } = {}) {
      const res = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        credentials: "include",
      });
      const isJson = (res.headers.get("content-type") || "").includes("application/json");
      const data = isJson ? await res.json().catch(() => null) : null;
      if (!res.ok) throw new Error(data?.error || "Request failed (" + res.status + ")");
      return data;
    }

    function addMessage(text, type) {
      let msg = document.createElement("div");
      msg.className = "message " + type;
      msg.textContent = text;
      document.getElementById("chat").appendChild(msg);
      scrollChat();
    }

    function addImage(src) {
      let container = document.createElement("div");
      container.className = "message user";
      let img = document.createElement("img");
      img.src = src;
      img.className = "image";
      container.appendChild(img);
      document.getElementById("chat").appendChild(container);
      scrollChat();
      setTimeout(() => {
        addMessage("AI: I can see the image. Connect this to an AI vision API to analyze the homework.", "ai");
      }, 1000);
    }

    function scrollChat() {
      let chat = document.getElementById("chat");
      chat.scrollTop = chat.scrollHeight;
    }

    let appState = { me: null, approved: false, mode: "login" };

    function setAuthError(msg) {
      const el = document.getElementById("authError");
      if (!msg) { el.textContent = ""; el.classList.remove("show"); return; }
      el.textContent = msg; el.classList.add("show");
    }

    function setApprovalStatus(msg) {
      const el = document.getElementById("approvalStatus");
      if (!msg) { el.textContent = ""; el.style.display = "none"; return; }
      el.textContent = msg; el.style.display = "block";
    }

    function updateGateUI() {
      const input = document.getElementById("input");
      const gate = document.getElementById("accessGate");
      const logoutBtn = document.getElementById("logoutBtn");
      const authForm = document.getElementById("authForm");
      const tabs = document.querySelector(".tabs");

      if (appState.me && appState.approved) {
        input.disabled = false;
        gate.classList.add("disabled");
        gate.style.display = "none";
        return;
      }

      gate.style.display = "block";
      gate.classList.remove("disabled");
      input.disabled = true;

      if (appState.me && !appState.approved) {
        logoutBtn.style.display = "inline-block";
        authForm.style.display = "none";
        tabs.style.display = "none";
        setApprovalStatus(
          "Signed in as " + appState.me.email + ". Your access request is pending approval. You can also tap “Request Access” to email a request."
        );
      } else {
        logoutBtn.style.display = "none";
        authForm.style.display = "grid";
        tabs.style.display = "grid";
        setApprovalStatus("");
      }
    }

    async function refreshMe() {
      try {
        const me = await api("/api/me");
        appState.me = me;
        appState.approved = !!me.approved;
      } catch {
        appState.me = null;
        appState.approved = false;
      }
      updateGateUI();
    }

    function buildRequestText(email) {
      return (
        "May I please have permission to use the AI Homework Helper application? " +
        "I would like to ask questions and get assistance with my homework through this tool. " +
        (email ? ("My email is: " + email + ". ") : "") +
        "Thank you!"
      );
    }

    async function requestAccessViaEmail() {
      const email = (document.getElementById("authEmail").value || "").trim();
      try { await api("/api/access/request", { method: "POST", body: { email } }); } catch {}
      const subject = encodeURIComponent("AI Homework Helper Access Request");
      const body = encodeURIComponent(buildRequestText(email));
      window.location.href = "mailto:" + encodeURIComponent(APPROVER_EMAIL) + "?subject=" + subject + "&body=" + body;
    }

    async function shareAccessRequest() {
      const email = (document.getElementById("authEmail").value || "").trim();
      const text = buildRequestText(email);
      try { await api("/api/access/request", { method: "POST", body: { email } }); } catch {}

      if (navigator.share) {
        try { await navigator.share({ title: "Request Access", text }); return; } catch {}
      }
      try {
        await navigator.clipboard.writeText(text);
        addMessage("AI: Access request copied to clipboard. Paste it into an email or message to request approval.", "ai");
      } catch {
        addMessage("AI: Please copy and send this request to an approver:\\n\\n" + text, "ai");
      }
    }

    function setMode(mode) {
      appState.mode = mode;
      document.getElementById("tabLogin").classList.toggle("active", mode === "login");
      document.getElementById("tabCreate").classList.toggle("active", mode === "create");
      document.getElementById("authSubmitBtn").textContent = mode === "login" ? "Login" : "Create Account";
      document.getElementById("authPassword").setAttribute("autocomplete", mode === "login" ? "current-password" : "new-password");
      setAuthError("");
    }

    document.getElementById("tabLogin").addEventListener("click", () => setMode("login"));
    document.getElementById("tabCreate").addEventListener("click", () => setMode("create"));
    document.getElementById("requestAccessBtn").addEventListener("click", requestAccessViaEmail);
    document.getElementById("shareAccessBtn").addEventListener("click", shareAccessRequest);

    document.getElementById("logoutBtn").addEventListener("click", async () => {
      try { await api("/api/auth/logout", { method: "POST" }); } catch {}
      await refreshMe();
    });

    document.getElementById("authForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      setAuthError("");
      const email = (document.getElementById("authEmail").value || "").trim();
      const password = document.getElementById("authPassword").value || "";
      try {
        if (appState.mode === "login") await api("/api/auth/login", { method: "POST", body: { email, password } });
        else await api("/api/auth/signup", { method: "POST", body: { email, password } });
        await refreshMe();
        if (!appState.approved) addMessage("AI: You’re signed in, but access is pending approval. Tap “Request Access” to send a request.", "ai");
        else addMessage("AI: Access approved. Ask your question whenever you're ready.", "ai");
      } catch (err) {
        setAuthError(err?.message || "Something went wrong.");
      }
    });

    async function send() {
      let input = document.getElementById("input");
      if (input.value.trim() == "") return;
      if (!appState.approved) {
        addMessage("AI: Please request access first (tap “Request Access”), then try again once approved.", "ai");
        return;
      }
      let question = input.value;
      addMessage("You: " + question, "user");
      input.value = "";
      addMessage("AI: Thinking...", "ai");
      try {
        const data = await api("/api/chat", { method: "POST", body: { message: question } });
        let msgs = document.querySelectorAll(".ai");
        msgs[msgs.length - 1].textContent = "AI: " + (data?.reply || "Try breaking the problem into smaller steps.");
      } catch {
        setTimeout(() => {
          let msgs = document.querySelectorAll(".ai");
          msgs[msgs.length - 1].textContent = "AI: (Server error) Try breaking the problem into smaller steps.";
        }, 600);
      }
    }

    function openCamera(){ document.getElementById("fileInput").click(); }
    function uploadImage(event){
      let file = event.target.files[0];
      if(!file) return;
      let reader = new FileReader();
      reader.onload = function(e){ addImage(e.target.result); }
      reader.readAsDataURL(file);
    }
    document.getElementById("input").addEventListener("keypress", function(e){ if(e.key==="Enter") send(); });
    refreshMe();
  </script>
</body>
</html>`;
}

function adminHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>AI Homework Helper • Admin</title>
  <style>
    *{box-sizing:border-box;}
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b1220;color:#e2e8f0;}
    header{position:sticky;top:0;z-index:5;padding:14px 16px;background:rgba(11,18,32,.75);border-bottom:1px solid rgba(148,163,184,.18);backdrop-filter:blur(12px);display:flex;align-items:center;justify-content:space-between;gap:10px;}
    h1{margin:0;font-size:16px;letter-spacing:-.02em;}
    .wrap{width:min(980px,100%);margin:0 auto;padding:16px;display:grid;gap:12px;}
    .card{border:1px solid rgba(56,189,248,.25);background:rgba(15,23,42,.75);border-radius:16px;padding:14px;}
    .muted{color:rgba(226,232,240,.75);font-size:13px;}
    .row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;}
    table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:14px;}
    th,td{text-align:left;padding:10px 10px;border-bottom:1px solid rgba(148,163,184,.14);font-size:13px;}
    th{color:rgba(226,232,240,.8);font-weight:800;background:rgba(2,6,23,.35);}
    .btn{border:1px solid rgba(148,163,184,.2);background:rgba(2,6,23,.25);color:#e2e8f0;border-radius:12px;padding:10px 12px;font-weight:800;cursor:pointer;}
    .btn.approve{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.92);color:#020617;}
    .btn.deny{border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.18);}
    .badge{display:inline-block;padding:4px 8px;border-radius:999px;font-weight:800;font-size:12px;border:1px solid rgba(148,163,184,.2);}
    .badge.pending{border-color:rgba(56,189,248,.35);}
    .badge.approved{border-color:rgba(34,197,94,.35);}
    .badge.denied{border-color:rgba(248,113,113,.35);}
    .err{display:none;margin-top:10px;border:1px solid rgba(248,113,113,.35);background:rgba(248,113,113,.12);border-radius:12px;padding:10px 12px;font-weight:800;font-size:13px;}
    .err.show{display:block;}
    input{flex:1;min-width:220px;padding:10px 12px;border-radius:12px;border:1px solid rgba(148,163,184,.2);background:rgba(2,6,23,.25);color:#e2e8f0;}
  </style>
</head>
<body>
  <header>
    <h1>AI Homework Helper • Admin</h1>
    <button id="logoutBtn" class="btn" type="button">Logout</button>
  </header>

  <div class="wrap">
    <div class="card">
      <div class="row">
        <div>
          <div style="font-weight:900">Access Requests</div>
          <div class="muted">Approve or deny student access. Admin login required.</div>
        </div>
        <button id="refreshBtn" class="btn" type="button">Refresh</button>
      </div>
      <div id="err" class="err" role="alert" aria-live="polite"></div>
      <form id="loginForm" style="display:none;margin-top:12px;gap:8px" class="row">
        <input id="email" type="email" placeholder="Admin email" required />
        <input id="password" type="password" placeholder="Password" required />
        <button class="btn approve" type="submit">Login</button>
      </form>
    </div>

    <div class="card">
      <table aria-label="Access requests table">
        <thead>
          <tr>
            <th>Email</th><th>Status</th><th>Created</th><th>Decision</th><th style="width:220px">Actions</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </div>

  <script>
    async function api(path, { method = "GET", body } = {}) {
      const res = await fetch(path, { method, headers: body ? { "Content-Type": "application/json" } : undefined, body: body ? JSON.stringify(body) : undefined, credentials: "include" });
      const isJson = (res.headers.get("content-type") || "").includes("application/json");
      const data = isJson ? await res.json().catch(() => null) : null;
      if (!res.ok) throw new Error(data?.error || "Request failed (" + res.status + ")");
      return data;
    }
    function showErr(msg){
      const el = document.getElementById("err");
      if(!msg){ el.textContent=""; el.classList.remove("show"); return; }
      el.textContent=msg; el.classList.add("show");
    }
    function fmt(ts){ if(!ts) return "—"; try { return new Date(ts*1000).toLocaleString(); } catch { return String(ts); } }

    async function load(){
      showErr("");
      const body = document.getElementById("rows");
      body.innerHTML="";
      try{
        const data = await api("/api/admin/requests");
        document.getElementById("loginForm").style.display="none";
        for(const r of (data.requests||[])){
          const tr = document.createElement("tr");
          const statusClass = r.status || "pending";
          tr.innerHTML = \`
            <td>\${r.email}</td>
            <td><span class="badge \${statusClass}">\${statusClass}</span></td>
            <td>\${fmt(r.created_at)}</td>
            <td>\${r.decided_at ? fmt(r.decided_at) : "—"}</td>
            <td>
              <button class="btn approve" data-act="approve" data-id="\${r.id}">Approve</button>
              <button class="btn deny" data-act="deny" data-id="\${r.id}">Deny</button>
            </td>\`;
          body.appendChild(tr);
        }
      } catch(e){
        showErr(e?.message || "Could not load requests. Are you logged in as admin?");
        document.getElementById("loginForm").style.display="flex";
      }
    }

    document.getElementById("rows").addEventListener("click", async (e) => {
      const btn = e.target?.closest?.("button");
      if(!btn) return;
      const act = btn.dataset.act;
      const id = btn.dataset.id;
      if(!act || !id) return;
      showErr("");
      try{ await api("/api/admin/requests/" + encodeURIComponent(id) + "/" + act, { method:"POST" }); await load(); }
      catch(err){ showErr(err?.message || "Action failed."); }
    });

    document.getElementById("refreshBtn").addEventListener("click", load);
    document.getElementById("logoutBtn").addEventListener("click", async () => {
      try { await api("/api/auth/logout", { method:"POST" }); } catch {}
      window.location.href = "/homework";
    });

    document.getElementById("loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      showErr("");
      try{
        await api("/api/auth/login", { method:"POST", body:{ email: document.getElementById("email").value, password: document.getElementById("password").value }});
        await load();
      } catch(err){ showErr(err?.message || "Login failed."); }
    });

    load();
  </script>
</body>
</html>`;
}

const db = new DatabaseSync(DB_PATH);
initDb(db);
cleanupExpiredSessions(db);
ensureAdminUser(db);

function securityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
}

function linkAccessRequest({ email, userId, status = "pending", decidedBy = null } = {}) {
  const decidedAt = status === "pending" ? null : nowSec();
  return db
    .prepare("INSERT INTO AccessRequests (email, user_id, status, decided_at, decided_by) VALUES (?, ?, ?, ?, ?)")
    .run(email, userId || null, status, decidedAt, decidedBy).lastInsertRowid;
}

function decideRequest({ id, status, decidedBy }) {
  const reqRow = db.prepare("SELECT id, email, user_id FROM AccessRequests WHERE id = ?").get(id);
  if (!reqRow) return { ok: false, error: "Request not found." };

  try {
    transaction(db, () => {
      db.prepare("UPDATE AccessRequests SET status = ?, decided_at = ?, decided_by = ? WHERE id = ?").run(
        status,
        nowSec(),
        decidedBy,
        id,
      );
      if (status === "approved") {
        const userId = reqRow.user_id || db.prepare("SELECT id FROM Users WHERE email = ?").get(reqRow.email)?.id;
        if (userId) db.prepare("UPDATE Users SET approved_at = ? WHERE id = ?").run(nowSec(), userId);
      }
    });
    return { ok: true };
  } catch {
    return { ok: false, error: "Could not update request." };
  }
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const path = url.pathname;

  if (req.method === "GET" && (path === "/" || path === "/homework.html")) {
    res.statusCode = 302;
    res.setHeader("Location", "/homework");
    return res.end();
  }

  if (req.method === "GET" && path === "/homework") return sendHtml(res, homeworkHtml());
  if (req.method === "GET" && path === "/admin") return sendHtml(res, adminHtml());
  if (req.method === "GET" && path === "/ai-homework-helper-icon.svg") return send(res, 200, ICON_SVG, "image/svg+xml");

  if (path.startsWith("/api/")) {
    try {
      if (req.method === "POST" && path === "/api/auth/signup") {
        const body = await readJson(req);
        const emailRaw = body?.email;
        const password = body?.password;
        if (!isEmail(emailRaw)) return jsonError(res, 400, "Enter a valid email.");
        if (typeof password !== "string" || password.length < 8) return jsonError(res, 400, "Password must be 8+ characters.");

        const email = emailRaw.trim().toLowerCase();
        const auto = emailIsAutoApproved(email);
        const existingApproved = db
          .prepare("SELECT 1 FROM AccessRequests WHERE email = ? AND status = 'approved' LIMIT 1")
          .get(email);
        const approvedAt = auto || existingApproved ? nowSec() : null;

        let userId;
        try {
          const info = db
            .prepare("INSERT INTO Users (email, password, role, approved_at) VALUES (?, ?, 'user', ?)")
            .run(email, hashPassword(password), approvedAt);
          userId = Number(info.lastInsertRowid);
        } catch (e) {
          if (String(e?.message || "").includes("UNIQUE")) return jsonError(res, 409, "That email is already in use.");
          return jsonError(res, 500, "Could not create account.");
        }

        try {
          linkAccessRequest({ email, userId, status: approvedAt ? "approved" : "pending" });
        } catch {
          // ignore
        }

        const { token } = createSession(db, userId);
        setCookie(res, SESSION_COOKIE, token, {
          maxAgeSec: SESSION_TTL_SECONDS,
          httpOnly: true,
          sameSite: "Lax",
          secure: isSecureRequest(req),
          path: "/",
        });
        return sendJson(res, 200, { ok: true, approved: !!approvedAt });
      }

      if (req.method === "POST" && path === "/api/auth/login") {
        const body = await readJson(req);
        const emailRaw = body?.email;
        const password = body?.password;
        if (!isEmail(emailRaw)) return jsonError(res, 400, "Enter a valid email.");
        if (typeof password !== "string" || password.length < 1) return jsonError(res, 400, "Enter your password.");

        const email = emailRaw.trim().toLowerCase();
        const user = db.prepare("SELECT id, email, password, role, approved_at FROM Users WHERE email = ?").get(email);
        if (!user) return jsonError(res, 401, "Invalid email or password.");
        if (!verifyPassword(password, user.password)) return jsonError(res, 401, "Invalid email or password.");

        const { token } = createSession(db, user.id);
        setCookie(res, SESSION_COOKIE, token, {
          maxAgeSec: SESSION_TTL_SECONDS,
          httpOnly: true,
          sameSite: "Lax",
          secure: isSecureRequest(req),
          path: "/",
        });
        return sendJson(res, 200, { ok: true, approved: !!user.approved_at, role: user.role });
      }

      const auth = authUser(db, req);

      if (req.method === "POST" && path === "/api/auth/logout") {
        if (auth) db.prepare("DELETE FROM Sessions WHERE token_hash = ?").run(auth.sessionTokenHash);
        clearCookie(res, SESSION_COOKIE);
        return sendJson(res, 200, { ok: true });
      }

      if (req.method === "GET" && path === "/api/me") {
        if (!auth) return jsonError(res, 401, "Not logged in.");
        return sendJson(res, 200, {
          id: auth.user.id,
          email: auth.user.email,
          role: auth.user.role,
          approved: !!auth.user.approved_at,
        });
      }

      if (req.method === "POST" && path === "/api/access/request") {
        const body = await readJson(req);
        const emailRaw = body?.email;
        if (!isEmail(emailRaw)) return jsonError(res, 400, "Enter a valid email (or log in first).");
        const email = emailRaw.trim().toLowerCase();

        const user = db.prepare("SELECT id, approved_at FROM Users WHERE email = ?").get(email);
        const already = db
          .prepare("SELECT id FROM AccessRequests WHERE email = ? AND status = 'pending' ORDER BY id DESC LIMIT 1")
          .get(email);
        if (already) return sendJson(res, 200, { ok: true, status: "pending" });
        if (user?.approved_at) return sendJson(res, 200, { ok: true, status: "approved" });

        try {
          linkAccessRequest({ email, userId: user?.id || null, status: "pending" });
        } catch {
          return jsonError(res, 500, "Could not create request.");
        }
        return sendJson(res, 200, { ok: true, status: "pending" });
      }

      if (path.startsWith("/api/admin/")) {
        if (!auth) return jsonError(res, 401, "Not logged in.");
        if (auth.user.role !== "admin") return jsonError(res, 403, "Admin access required.");

        if (req.method === "GET" && path === "/api/admin/requests") {
          const requests = db
            .prepare("SELECT id, email, status, created_at, decided_at FROM AccessRequests ORDER BY created_at DESC LIMIT 250")
            .all();
          return sendJson(res, 200, { requests });
        }

        const m = path.match(/^\/api\/admin\/requests\/(\d+)\/(approve|deny)$/);
        if (req.method === "POST" && m) {
          const id = Number(m[1]);
          const act = m[2];
          const result = decideRequest({ id, status: act === "approve" ? "approved" : "denied", decidedBy: auth.user.id });
          if (!result.ok) return jsonError(res, 400, result.error);
          return sendJson(res, 200, { ok: true });
        }
      }

      if (req.method === "POST" && path === "/api/chat") {
        if (!auth) return jsonError(res, 401, "Not logged in.");
        if (!auth.user.approved_at && auth.user.role !== "admin") return jsonError(res, 403, "Access not approved yet.");
        const body = await readJson(req, { limitBytes: 128 * 1024 });
        const msg = (body?.message || "").toString().slice(0, 2000);
        if (!msg.trim()) return jsonError(res, 400, "Message required.");
        return sendJson(res, 200, {
          reply:
            "Thanks! I can help. First, tell me what class this is for and paste the exact question. Then we’ll solve it step by step.",
        });
      }

      return jsonError(res, 404, "Not found.");
    } catch (e) {
      return jsonError(res, 400, e?.message || "Bad request.");
    }
  }

  return send(res, 404, "Not found", "text/plain; charset=utf-8");
});

server.listen(PORT, () => {
  console.log(`One-file AI Homework Helper running on http://localhost:${PORT}/homework`);
  console.log(`Admin: http://localhost:${PORT}/admin`);
  console.log(`DB: ${DB_PATH}`);
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.log("Admin not configured. Set AHH_ADMIN_EMAIL and AHH_ADMIN_PASSWORD to enable admin approvals.");
  }
});

