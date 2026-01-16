// server.js
// TutoPay demo backend — escrow logic + catalogue + buyer→seller requests with replies + live GPS

const express = require("express");
const cors = require("cors");
const { v4: uuid } = require("uuid");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 4000;




let dbReady = false;
let dbInitError = null;
// ===== Railway / uptime health endpoints =====
// Railway health checks cannot send custom headers, so these MUST stay public.
// (They do not expose any sensitive data.)
app.get("/", (req, res) => res.status(200).send("ok"));

// --- Railway/production startup gate ---
// Start listening immediately so Railway healthchecks can reach /health,
// then finish DB init in the background.
app.use((req, res, next) => {
  // Always allow liveness endpoints + root + preflight while DB is coming up
  if (req.method === 'OPTIONS') return next();
  const p = req.path || '';
  if (p === '/' || p === '/health' || p === '/ready') return next();
  if (dbReady) return next();
  // If DB init already failed, surface it (helps debugging)
  const msg = dbInitError ? 'DB init failed' : 'Server starting';
  return res.status(503).json({ ok: false, status: msg });
});

app.all('/health', (req, res) => {
  // Liveness: always 200 if the HTTP server is up.
  // Includes DB readiness info for humans (Railway healthcheck should point here).
  res.status(200).json({
    ok: true,
    dbReady,
    dbError: dbInitError ? (dbInitError.message || String(dbInitError)) : null,
    time: new Date().toISOString(),
  });
});
// ===== Payments mode =====
// demo: no external calls (instant success)
// mtn_sandbox / airtel_sandbox: prepared hooks (requires env vars + Node 18+ fetch)
const PAYMENTS_MODE = (process.env.PAYMENTS_MODE || "demo").toLowerCase();

// ===== Airtel Money (sandbox) integration helpers =====
// Uses Airtel Africa Open API (UAT base URL) — Collection / USSD Push.
// Docs/examples: https://openapiuat.airtel.africa with POST /auth/oauth2/token and POST /merchant/v1/payments/
const AIRTEL_BASE_URL =
  process.env.AIRTEL_BASE_URL ||
  (PAYMENTS_MODE === "airtel_sandbox"
    ? "https://openapiuat.airtel.africa"
    : "https://openapi.airtel.africa");

const AIRTEL_CLIENT_ID = process.env.AIRTEL_CLIENT_ID || "";
const AIRTEL_CLIENT_SECRET = process.env.AIRTEL_CLIENT_SECRET || "";
const AIRTEL_COUNTRY = String(process.env.AIRTEL_COUNTRY || "ZM").toUpperCase();   // ISO alpha-2 (e.g., ZM)
const AIRTEL_CURRENCY = String(process.env.AIRTEL_CURRENCY || "ZMW").toUpperCase(); // ISO currency (e.g., ZMW)

let airtelTokenCache = { token: null, expiresAt: 0 };

function airtelMsisdnFromPhone(phone) {
  // Airtel expects MSISDN without country code for many markets (e.g., "0977..." -> "977...").
  // If your sandbox expects a different format, tweak this function only.
  const digits = String(phone || "").replace(/\D/g, "");
  if (!digits) return "";
  if (digits.startsWith("0")) return digits.slice(1);
  if (digits.startsWith("260")) return digits.slice(3);
  if (digits.startsWith("00")) return digits.replace(/^00/, "");
  return digits;
}

async function airtelGetAccessToken() {
  const now = Date.now();
  if (airtelTokenCache.token && airtelTokenCache.expiresAt > now) {
    return airtelTokenCache.token;
  }

  if (!AIRTEL_CLIENT_ID || !AIRTEL_CLIENT_SECRET) {
    throw new Error("Missing AIRTEL_CLIENT_ID / AIRTEL_CLIENT_SECRET");
  }

  const url = `${AIRTEL_BASE_URL}/auth/oauth2/token`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "*/*" },
    body: JSON.stringify({
      client_id: AIRTEL_CLIENT_ID,
      client_secret: AIRTEL_CLIENT_SECRET,
      grant_type: "client_credentials",
    }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    const msg = data && (data.error_description || data.error || data.message);
    throw new Error(`Airtel token error (${res.status}): ${msg || "unknown"}`);
  }

  const expiresInSec = Number(data.expires_in || 0);
  // Refresh 60s early to avoid edge expiry
  airtelTokenCache = {
    token: data.access_token,
    expiresAt: now + Math.max(0, expiresInSec * 1000 - 60_000),
  };
  return airtelTokenCache.token;
}

async function airtelInitiateCollection({ msisdn, amount, transactionId, reference }) {
  const token = await airtelGetAccessToken();
  const url = `${AIRTEL_BASE_URL}/merchant/v1/payments/`;

  const payload = {
    reference: reference || "TutoPay",
    subscriber: {
      country: AIRTEL_COUNTRY,
      currency: AIRTEL_CURRENCY,
      msisdn: msisdn, // phone without country code in many sandboxes
    },
    transaction: {
      amount: String(amount),
      country: AIRTEL_COUNTRY,
      currency: AIRTEL_CURRENCY,
      id: String(transactionId),
    },
  };

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      "X-Country": AIRTEL_COUNTRY,
      "X-Currency": AIRTEL_CURRENCY,
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data && (data.message || data.error || data.error_description);
    throw new Error(`Airtel initiate error (${res.status}): ${msg || "unknown"}`);
  }
  return data;
}

async function airtelCheckCollectionStatus(transactionId) {
  const token = await airtelGetAccessToken();
  const url = `${AIRTEL_BASE_URL}/standard/v1/payments/${encodeURIComponent(String(transactionId))}`;

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "*/*",
      "X-Country": AIRTEL_COUNTRY,
      "X-Currency": AIRTEL_CURRENCY,
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data && (data.message || data.error || data.error_description);
    throw new Error(`Airtel status error (${res.status}): ${msg || "unknown"}`);
  }
  return data;
}


// Allow bigger JSON bodies (base64 images from frontend)
const allowedOrigins = [
  "https://tutopay.online",
  "https://www.tutopay.online",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

const corsOptions = {
  origin: function (origin, cb) {
    // Allow non-browser tools (no Origin header) like curl/Postman
    if (!origin) return cb(null, true);
    if (allowedOrigins.includes(origin)) return cb(null, true);
    // Allow Railway preview domains too
    if (/\.up\.railway\.app$/.test(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS: ' + origin));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Idempotency-Key'],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: "50mb" }));  // ⬅️ change 5mb → 50mb

// (optional, but good for safety if you use urlencoded anywhere)
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Serve the frontend and uploaded dispute docs
app.use(express.static("public"));

// ===== MTN MoMo Sandbox helpers (Collections + Disbursement) =====
const MOMO_BASE_URL = process.env.MOMO_BASE_URL || "https://sandbox.momodeveloper.mtn.com";
const MOMO_CURRENCY = process.env.MOMO_CURRENCY || "ZMW";
const PUBLIC_API_BASE = process.env.PUBLIC_API_BASE || process.env.API_PUBLIC_BASE || "https://api.tutopay.online";
const MOMO_CALLBACK_URL = process.env.MOMO_CALLBACK_URL || `${PUBLIC_API_BASE}/momo/callback`;

// Expect these env vars on Railway (Settings -> Variables):
// MTN_COLLECTION_SUB_KEY, MTN_COLLECTION_APIUSER, MTN_COLLECTION_APIKEY
// MTN_DISBURSEMENT_SUB_KEY, MTN_DISBURSEMENT_APIUSER, MTN_DISBURSEMENT_APIKEY
function momoAssertEnv(keys) {
  const missing = keys.filter((k) => !process.env[k]);
  if (missing.length) {
    const err = new Error(`Missing env vars: ${missing.join(", ")}`);
    err.statusCode = 500;
    throw err;
  }
}
function momoBasicAuth(apiUser, apiKey) {
  const token = Buffer.from(`${apiUser}:${apiKey}`).toString("base64");
  return `Basic ${token}`;
}

async function momoGetToken(product) {
  // product: "collection" | "disbursement"
  if (product === "collection") {
    momoAssertEnv(["MTN_COLLECTION_SUB_KEY", "MTN_COLLECTION_APIUSER", "MTN_COLLECTION_APIKEY"]);
    const auth = momoBasicAuth(process.env.MTN_COLLECTION_APIUSER, process.env.MTN_COLLECTION_APIKEY);
    const r = await axios.post(
      `${MOMO_BASE_URL}/collection/token/`,
      null,
      { headers: { Authorization: auth, "Ocp-Apim-Subscription-Key": process.env.MTN_COLLECTION_SUB_KEY } }
    );
    return r?.data?.access_token;
  }
  momoAssertEnv(["MTN_DISBURSEMENT_SUB_KEY", "MTN_DISBURSEMENT_APIUSER", "MTN_DISBURSEMENT_APIKEY"]);
  const auth = momoBasicAuth(process.env.MTN_DISBURSEMENT_APIUSER, process.env.MTN_DISBURSEMENT_APIKEY);
  const r = await axios.post(
    `${MOMO_BASE_URL}/disbursement/token/`,
    null,
    { headers: { Authorization: auth, "Ocp-Apim-Subscription-Key": process.env.MTN_DISBURSEMENT_SUB_KEY } }
  );
  return r?.data?.access_token;
}

async function momoRequestToPay({ amount, msisdn, externalId, payerMessage, payeeNote, callbackUrl }) {
  const accessToken = await momoGetToken("collection");
  if (!accessToken) throw new Error("Failed to get MoMo access token (collection)");

  const referenceId = uuidv4(); // X-Reference-Id for MoMo
  const body = {
    amount: String(amount),
    currency: MOMO_CURRENCY,
    externalId: String(externalId || referenceId),
    payer: { partyIdType: "MSISDN", partyId: String(msisdn) },
    payerMessage: payerMessage || "TutoPay escrow deposit",
    payeeNote: payeeNote || "Escrow deposit",
  };

  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "X-Reference-Id": referenceId,
    "X-Target-Environment": "sandbox",
    "Ocp-Apim-Subscription-Key": process.env.MTN_COLLECTION_SUB_KEY,
    "Content-Type": "application/json",
  };
  if (callbackUrl) headers["X-Callback-Url"] = callbackUrl;

  await axios.post(`${MOMO_BASE_URL}/collection/v1_0/requesttopay`, body, { headers });
  return { referenceId };
}

async function momoGetRequestToPayStatus(referenceId) {
  const accessToken = await momoGetToken("collection");
  if (!accessToken) throw new Error("Failed to get MoMo access token (collection)");

  const r = await axios.get(`${MOMO_BASE_URL}/collection/v1_0/requesttopay/${encodeURIComponent(referenceId)}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Target-Environment": "sandbox",
      "Ocp-Apim-Subscription-Key": process.env.MTN_COLLECTION_SUB_KEY,
    },
  });
  return r?.data;
}

// Simple callback receiver (MoMo will call this if you set X-Callback-Url)
app.post("/momo/callback", (req, res) => {
  try {
    console.log("MoMo callback:", JSON.stringify({ headers: req.headers, body: req.body }));
  } catch {}
  res.status(200).json({ ok: true });
});

// ===== Dispute document uploads (Multer) =====
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const disputeUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
      cb(
        null,
        "dispute-" + unique + (file.originalname ? path.extname(file.originalname) : "")
      );
    },
  }),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10 MB
  },
});

// Expose uploaded dispute docs (e.g. for admin review)
app.use("/uploads", express.static(uploadDir));

// ===== Item image helpers (convert base64 data URLs to real files in /uploads) =====
function extFromMime(mime) {
  if (!mime) return "png";
  if (mime.includes("jpeg")) return "jpg";
  if (mime.includes("png")) return "png";
  if (mime.includes("webp")) return "webp";
  if (mime.includes("gif")) return "gif";
  return "png";
}

function saveDataUrlToUploads(dataUrl, prefix = "item") {
  if (typeof dataUrl !== "string") return "";
  if (!dataUrl.startsWith("data:")) return dataUrl; // already a normal URL/path
  const m = dataUrl.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.*)$/);
  if (!m) return "";
  const mime = m[1];
  const b64 = m[2];
  const buf = Buffer.from(b64, "base64");
  const ext = extFromMime(mime);
  const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const filename = `${prefix}-${unique}.${ext}`;
  const fp = path.join(uploadDir, filename);
  fs.writeFileSync(fp, buf);
  return `/uploads/${filename}`;
}

function migrateItemImagesInPlace(item) {
  if (!item || typeof item !== "object") return item;

  // Ensure every item has a stable id for future lookups
  if (!item.id) item.id = uuid();

  const urls = Array.isArray(item.imageUrls)
    ? item.imageUrls.slice()
    : (item.imageUrl ? [item.imageUrl] : []);

  // Convert any base64 blobs into uploaded files
  const cache = new Map();
  const convert = (u) => {
    if (typeof u !== "string") return "";
    if (!u.startsWith("data:")) return u;
    if (cache.has(u)) return cache.get(u);
    const saved = saveDataUrlToUploads(u, "item");
    cache.set(u, saved);
    return saved;
  };

  const converted = urls.map(convert).filter(Boolean);

  // Keep item.imageUrl aligned with first image for compatibility
  if (converted.length) {
    item.imageUrls = converted;
    item.imageUrl = converted[0];
  } else {
    item.imageUrls = [];
    item.imageUrl = "";
  }

  return item;
}


// -------- In-memory "database" --------
const items = [
  {
    id: uuid(),
    code: "1000",
    title: "Laptop, Lenovo (Used)",
    price: 5000,
    sellerPhone: "0977623456",
    holdHours: 24,
    imageUrl: "",
    availability: "available",
    condition: "used",
  },
  {
    id: uuid(),
    code: "1001",
    title: "Laptop, Lenovo (New)",
    price: 11500,
    sellerPhone: "0977100999",
    holdHours: 24,
    imageUrl: "",
    availability: "available",
    condition: "new",
  },
];

// -------- KYC TIERS & LIMITS (demo values) --------
const KYC_LIMITS = {
  basic: {
    maxPerTx: 2000,     // e.g. KYC level 1: max 2,000 ZMW per transaction
    maxDaily: 5000,     // e.g. KYC level 1: 5,000 ZMW total per day
  },
  enhanced: {
    maxPerTx: 10000,    // level 2: 10,000 ZMW per transaction
    maxDaily: 50000,    // level 2: 50,000 ZMW per day
  },
  full: {
    maxPerTx: 50000,    // level 3: 50,000 ZMW per transaction
    maxDaily: 250000,   // level 3: 250,000 ZMW per day
  },
};

const transactions = [];
const requests = [];
// -------- Audit log (in-memory) --------
// Each entry: { id, timestamp, ip, userPhone, userRole, eventType, details }
const auditLog = [];

// ===== PostgreSQL persistence (Railway) =====
// If DATABASE_URL exists and pg is installed, we persist users/items/transactions/requests/audit logs.
// If not, the app continues using in-memory arrays (demo mode).
const HAS_DATABASE_URL = !!process.env.DATABASE_URL;
let _pgPool = null;
let _dbReady = false;

function dbEnabled() {
  return !!(_dbReady && _pgPool);
}

async function dbInit() {
  if (!HAS_DATABASE_URL) {
    console.log("[DB] DATABASE_URL not set — using in-memory storage.");
    return;
  }

  let Pool;
  try {
    ({ Pool } = require("pg"));
  } catch (e) {
    console.warn("[DB] pg module not installed. Run: npm i pg. Using in-memory storage for now.");
    return;
  }

  try {
    _pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }, // Railway Postgres often requires SSL
      max: 5,
    });

    // Quick ping
    await _pgPool.query("SELECT 1 as ok");
    await dbEnsureSchema();
    await dbLoadIntoMemory();
    _dbReady = true;
    console.log("[DB] Connected + schema ready.");
  } catch (e) {
    console.error("[DB] Failed to init Postgres. Using in-memory storage.", e.message);
    _pgPool = null;
    _dbReady = false;
  }
}

async function dbEnsureSchema() {
  if (!_pgPool) return;
  // JSONB “document” tables — minimal change to existing logic
  await _pgPool.query(`
    CREATE TABLE IF NOT EXISTS tutopay_users (
      phone TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tutopay_items (
      id TEXT PRIMARY KEY,
      code TEXT UNIQUE,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tutopay_transactions (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tutopay_requests (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tutopay_audit (
      id TEXT PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      data JSONB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tutopay_idempotency (
      key TEXT PRIMARY KEY,
      request_hash TEXT,
      status_code INT,
      response JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS tutopay_items_code_idx ON tutopay_items(code);
    CREATE INDEX IF NOT EXISTS tutopay_audit_ts_idx ON tutopay_audit(ts);
    CREATE INDEX IF NOT EXISTS tutopay_idem_expires_idx ON tutopay_idempotency(expires_at);
  `);
}

async function dbLoadIntoMemory() {
  if (!_pgPool) return;

  // Users
  try {
    const u = await _pgPool.query("SELECT data FROM tutopay_users");
    if (u.rows && u.rows.length) {
      users.length = 0;
      for (const r of u.rows) users.push(r.data);
    }
  } catch (e) {}

  // Items (seed if empty)
  try {
    const it = await _pgPool.query("SELECT data FROM tutopay_items ORDER BY updated_at ASC");
    if (it.rows && it.rows.length) {
      const loaded = it.rows.map(r => r.data);
      items.length = 0;
      for (const obj of loaded) items.push(obj);
      // Keep nextItemNumber in sync with max code
      const maxCode = loaded
        .map(i => parseInt(String(i.code || i.id || ""), 10))
        .filter(n => Number.isFinite(n))
        .reduce((a,b)=>Math.max(a,b), 0);
      if (maxCode && maxCode >= nextItemNumber) nextItemNumber = maxCode + 1;
    } else {
      // Seed demo items on first run
      for (const item of items) await dbUpsertItem(item);
    }
  } catch (e) {}

  // Transactions
  try {
    const tx = await _pgPool.query("SELECT data FROM tutopay_transactions ORDER BY updated_at ASC");
    if (tx.rows && tx.rows.length) {
      transactions.length = 0;
      for (const r of tx.rows) transactions.push(r.data);
    }
  } catch (e) {}

  // Requests
  try {
    const rq = await _pgPool.query("SELECT data FROM tutopay_requests ORDER BY updated_at ASC");
    if (rq.rows && rq.rows.length) {
      requests.length = 0;
      for (const r of rq.rows) requests.push(r.data);
    }
  } catch (e) {}

  // Audit (keep last 2000 for memory)
  try {
    const a = await _pgPool.query("SELECT data FROM tutopay_audit ORDER BY ts DESC LIMIT 2000");
    if (a.rows && a.rows.length) {
      auditLog.length = 0;
      for (const r of a.rows.reverse()) auditLog.push(r.data);
    }
  } catch (e) {}

  // Idempotency cache (optional)
  try {
    const idem = await _pgPool.query("SELECT key, request_hash, status_code, response, EXTRACT(EPOCH FROM expires_at)*1000 AS expires_ms FROM tutopay_idempotency WHERE expires_at > NOW()");
    for (const r of idem.rows || []) {
      idempotencyStore.set(r.key, {
        requestHash: r.request_hash,
        statusCode: r.status_code,
        body: r.response,
        createdAt: Date.now(),
        expiresAt: Number(r.expires_ms) || Date.now(),
      });
    }
  } catch (e) {}
}

async function dbUpsertUser(user) {
  if (!dbEnabled()) return;
  const phone = String(user.phone || "").trim();
  if (!phone) return;
  await _pgPool.query(
    `INSERT INTO tutopay_users(phone, data, updated_at)
     VALUES ($1, $2::jsonb, NOW())
     ON CONFLICT (phone) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,
    [phone, JSON.stringify(user)]
  );
}

async function dbUpsertItem(item) {
  if (!dbEnabled()) return;
  const id = String(item.id || "").trim();
  const code = item.code ? String(item.code).trim() : null;
  if (!id) return;
  await _pgPool.query(
    `INSERT INTO tutopay_items(id, code, data, updated_at)
     VALUES ($1, $2, $3::jsonb, NOW())
     ON CONFLICT (id) DO UPDATE SET code=EXCLUDED.code, data=EXCLUDED.data, updated_at=NOW()`,
    [id, code, JSON.stringify(item)]
  );
}

async function dbDeleteItem(id) {
  if (!dbEnabled()) return;
  await _pgPool.query("DELETE FROM tutopay_items WHERE id=$1", [String(id)]);
}

async function dbUpsertTransaction(tx) {
  if (!dbEnabled()) return;
  const id = String(tx.id || "").trim();
  if (!id) return;
  await _pgPool.query(
    `INSERT INTO tutopay_transactions(id, data, updated_at)
     VALUES ($1, $2::jsonb, NOW())
     ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,
    [id, JSON.stringify(tx)]
  );
}

async function dbUpsertRequest(rq) {
  if (!dbEnabled()) return;
  const id = String(rq.id || "").trim();
  if (!id) return;
  await _pgPool.query(
    `INSERT INTO tutopay_requests(id, data, updated_at)
     VALUES ($1, $2::jsonb, NOW())
     ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,
    [id, JSON.stringify(rq)]
  );
}

async function dbInsertAudit(entry) {
  if (!dbEnabled()) return;
  const id = String(entry.id || uuid()).trim();
  const ts = entry.timestamp ? new Date(entry.timestamp) : new Date();
  await _pgPool.query(
    `INSERT INTO tutopay_audit(id, ts, data) VALUES ($1, $2, $3::jsonb)
     ON CONFLICT (id) DO NOTHING`,
    [id, ts, JSON.stringify(entry)]
  );
}

async function dbIdemGet(key) {
  if (!dbEnabled()) return null;
  const r = await _pgPool.query("SELECT request_hash, status_code, response FROM tutopay_idempotency WHERE key=$1 AND expires_at > NOW()", [key]);
  return r.rows && r.rows[0] ? r.rows[0] : null;
}

async function dbIdemSet(key, requestHash, statusCode, response, ttlMs) {
  if (!dbEnabled()) return;
  const expiresAt = new Date(Date.now() + (ttlMs || 30*60*1000));
  await _pgPool.query(
    `INSERT INTO tutopay_idempotency(key, request_hash, status_code, response, expires_at)
     VALUES ($1, $2, $3, $4::jsonb, $5)
     ON CONFLICT (key) DO UPDATE SET request_hash=EXCLUDED.request_hash, status_code=EXCLUDED.status_code, response=EXCLUDED.response, expires_at=EXCLUDED.expires_at`,
    [key, requestHash, statusCode || 200, JSON.stringify(response), expiresAt]
  );
}



function logAudit(req, eventType, details = {}) {
  const entry = {
    id: uuid(),
    timestamp: nowIso(),
    ip: req.ip,
    userPhone: null,
    userRole: null,
    eventType,
    details,
  };

  // If authenticated, use req.user
  if (req.user) {
    entry.userPhone = req.user.phone;
    entry.userRole = req.user.role;
  } else if (req.body && req.body.phone) {
    // for unauthenticated events like login
    entry.userPhone = String(req.body.phone).trim();
  }

  auditLog.push(entry);
  // persist audit log
  if (dbEnabled()) { dbInsertAudit(entry).catch(() => {}); }

  // keep only last 1000 entries in memory
  if (auditLog.length > 1000) {
    auditLog.shift();
  }
}

/**
 * Simple demo OTP store
 * Map of otpId -> { code, userPhone, purpose, txId, expiresAt, used }
 */
const otps = new Map();
const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes

function generateOtpCode() {
  // 6-digit numeric
  return String(Math.floor(100000 + Math.random() * 900000));
}

// -------- Simple in-memory users & sessions (demo only) --------
const users = []; // { id, phone, role, pinHash, kycLevel }
const sessions = new Map(); // token -> { id, phone, role, kycLevel }

function hashPin(pin) {
  return crypto.createHash("sha256").update(String(pin)).digest("hex");
}

function findUserByPhone(phone) {
  return users.find((u) => u.phone === phone);
}

// Seed a couple of demo users (optional)
users.push({
  id: uuid(),
  phone: "0977123456",
  role: "buyer",
  pinHash: hashPin("1111"),
  kycLevel: "basic",
});

users.push({
  id: uuid(),
  phone: "0977234567",
  role: "seller",
  pinHash: hashPin("2222"),
  kycLevel: "basic",
});

users.push({
  id: uuid(),
  phone: "0977345678",
  role: "admin",
  pinHash: hashPin("3333"),
  kycLevel: "admin",
});

// Auth middleware
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  const token = parts.length === 2 && parts[0] === "Bearer" ? parts[1] : null;

  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  req.user = sessions.get(token); // { id, phone, role, kycLevel }
  next();
}

// ===== Idempotency middleware (prevents duplicates on retries/double-taps) =====
const IDEM_TTL_MS = 30 * 60 * 1000; // 30 minutes
const idempotencyStore = new Map(); // key -> { requestHash, statusCode, body, createdAt }

function _hashBody(body) {
  try {
    const str = typeof body === "string" ? body : JSON.stringify(body || {});
    return crypto.createHash("sha256").update(str).digest("hex");
  } catch (e) {
    return "na";
  }
}

function _cleanupIdempotency() {
  const now = Date.now();
  for (const [k, v] of idempotencyStore.entries()) {
    if (!v || now - v.createdAt > IDEM_TTL_MS) idempotencyStore.delete(k);
  }
}

async function idempotencyMiddleware(req, res, next) {
  const key = req.get("Idempotency-Key");
  if (!key) return next();

  _cleanupIdempotency();
  const userPart = req.user && req.user.phone ? req.user.phone : "anon";
  const storeKey = `${userPart}:${req.method}:${req.originalUrl}:${key}`;
  const requestHash = _hashBody(req.body);

  // Check Postgres idempotency cache (persists across redeploys)
  if (dbEnabled()) {
    try {
      const dbExisting = await dbIdemGet(storeKey);
      if (dbExisting) {
        if (dbExisting.request_hash && dbExisting.request_hash !== requestHash) {
          return res.status(409).json({ error: "Idempotency key reuse with different payload." });
        }
        return res.status(dbExisting.status_code || 200).json(dbExisting.response);
      }
    } catch (e) {
      // ignore DB cache errors
    }
  }

const existing = idempotencyStore.get(storeKey);
  if (existing) {
    if (existing.requestHash && existing.requestHash !== requestHash) {
      return res.status(409).json({ error: "Idempotency key reuse with different payload." });
    }
    return res.status(existing.statusCode || 200).json(existing.body);
  }

  const origStatus = res.status.bind(res);
  const origJson = res.json.bind(res);

  let statusCode = 200;
  res.status = (code) => {
    statusCode = code;
    return origStatus(code);
  };

  res.json = (body) => {
    idempotencyStore.set(storeKey, {
      requestHash,
      statusCode,
      body,
      createdAt: Date.now(),
    });
    if (dbEnabled()) { dbIdemSet(storeKey, requestHash, statusCode, body, IDEM_TTL_MS).catch(() => {}); }
    return origJson(body);
  };

  return next();
}



let nextItemNumber = 1002;

// -------- Helpers --------
function normalizeItemCode(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  // IMPORTANT: do NOT join all digit groups.
  // Example: "TP-1003-496" MUST resolve to item "1003", not "1003496".

  // If the code looks like an official TP code, prefer the first number after TP.
  const mTp = s.match(/tp\s*[-_#:\s]*\s*(\d+)/i);
  if (mTp && mTp[1]) return mTp[1];

  // Otherwise, grab the first digit group (e.g. "Item #1004" -> "1004")
  const groups = s.match(/\d+/g);
  return groups && groups.length ? groups[0] : s;
}

function findItem(code) {
  const want = normalizeItemCode(code);
  if (!want) return null;
  // Try normalized compare (handles TP-1004 style inputs)
  const byNorm = items.find((i) => normalizeItemCode(i.code) === want);
  if (byNorm) return byNorm;
  // Fallback to exact string match
  return items.find((i) => String(i.code) === String(code));
}
function nowIso() {
  return new Date().toISOString();
}

// -------- OTP START (demo: code logged to backend console) --------
app.post("/api/otp/start", requireAuth, (req, res) => {
  const { purpose, txId } = req.body || {};

  if (!purpose || !txId) {
    return res.status(400).json({ error: "Missing purpose or txId" });
  }

  const tx = transactions.find((t) => t.id === txId);
  if (!tx) {
    return res.status(404).json({ error: "Transaction not found" });
  }

  // Only allow seller (or admin) to start OTP for refund-agree
  if (purpose === "seller_refund_agree") {
    const isSeller =
      req.user.phone === tx.toPhone && req.user.role === "seller";
    const isAdmin = req.user.role === "admin";
    if (!isSeller && !isAdmin) {
      return res.status(403).json({
        error: "Only the seller (or admin) can initiate refund OTP for this transaction.",
      });
    }
  }

  const otpId = uuid();
  const code = generateOtpCode();
  const expiresAt = Date.now() + OTP_TTL_MS;

  otps.set(otpId, {
    code,
    userPhone: req.user.phone,
    purpose,
    txId,
    expiresAt,
    used: false,
  });

  // For demo: code is logged in backend console instead of SMS
  console.log(
    `🔐 OTP for ${purpose} on tx ${txId} for ${req.user.phone}: ${code}`
  );
  logAudit(req, "otp_start", {
    txId,
    purpose,
  });

  res.json({
    otpId,
    code,          // 👈 add this line so frontend can show the demo OTP
    expiresAt,     // or expiresInMs: OTP_TTL_MS if you prefer
  });
});

// -------- Auth (phone + PIN, demo only) --------
app.post("/api/auth/login", (req, res) => {
  const { phone, pin, rolePreference } = req.body || {};
  if (!phone || !pin) {
    return res.status(400).json({ error: "Phone and PIN are required." });
  }

  const phoneNorm = String(phone).trim();
  let user = findUserByPhone(phoneNorm);

  if (!user) {
    // Demo behaviour: auto-register new user with chosen role
    const allowedRoles = ["buyer", "seller", "admin"];
    const role =
      allowedRoles.includes(rolePreference) ? rolePreference : "buyer";

    user = {
      id: uuid(),
      phone: phoneNorm,
      role,
      pinHash: hashPin(pin),
      kycLevel: "basic",
    };
    users.push(user);
    if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
    console.log("Created demo user:", user.phone, user.role);
  } else {
    if (user.pinHash !== hashPin(pin)) {
  logAudit(req, "auth_login_failed", {
    reason: "invalid_pin",
    phoneTried: phoneNorm,
  });
  return res.status(401).json({ error: "Invalid PIN." });
}
    if (rolePreference && rolePreference !== user.role) {
      console.log(
        "Role preference",
        rolePreference,
        "ignored, existing role:",
        user.role
      );
    }
  }

  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, {
    id: user.id,
    phone: user.phone,
    role: user.role,
    kycLevel: user.kycLevel,
  });

  logAudit(req, "auth_login_success", {
  phone: user.phone,
  role: user.role,
  kycLevel: user.kycLevel,
});

  return res.json({
    token,
    user: {
      id: user.id,
      phone: user.phone,
      role: user.role,
      kycLevel: user.kycLevel,
    },
  });
});

// -------- Items --------
app.get("/api/items", (req, res) => {
  // Ensure images are served as /uploads files (not giant base64 blobs)
  items.forEach(migrateItemImagesInPlace);
  // Default: return a lightweight list (no huge base64 images).
  // Use ?full=1 to return full objects, including imageUrls/base64.
  const full = String(req.query.full || '').toLowerCase();
  const wantFull = full === '1' || full === 'true' || full === 'yes';

  if (wantFull) return res.json(items);

  const lite = items.map((it) => {
    const out = { ...it };
    const urls = Array.isArray(it.imageUrls) ? it.imageUrls : (it.imageUrl ? [it.imageUrl] : []);
    const thumb = urls.length ? urls[0] : null;
    // If thumb is a huge base64 blob, don't send it in list responses.
    if (typeof thumb === 'string' && thumb.startsWith('data:') && thumb.length > 2000) {
      out.imageUrl = null;
    } else {
      out.imageUrl = thumb;
    }
    out.imageCount = urls.length;
    delete out.imageUrls;
    return out;
  });

  res.json(lite);
});

// Fetch full item details (including imageUrls) when user opens a listing
app.get("/api/items/:id", (req, res) => {
  items.forEach(migrateItemImagesInPlace);
  const idOrCode = String(req.params.id || "");
  const it = items.find((x) => x.id === idOrCode) || findItem(idOrCode);
if (!it) return res.status(404).json({ error: "Item not found" });
  res.json(it);
});

app.post("/api/items", requireAuth, (req, res) => {
    const {
  title,
  details,
  price,
  sellerPhone,
  holdHours,
  imageUrl,
  imageUrls,
  availability,
  condition,
} = req.body || {};

  if (!sellerPhone) {
    return res
      .status(400)
      .json({ error: "Missing seller phone number" });
  }

  if (req.user.role !== "seller" && req.user.role !== "admin") {
    return res.status(403).json({ error: "Only sellers can list items." });
  }

  if (req.user.phone !== sellerPhone && req.user.role !== "admin") {
    return res.status(403).json({
      error: "You can only list items for your own phone number.",
    });
  }

  if (!title || price == null || !sellerPhone) {
    return res
      .status(400)
      .json({ error: "Missing title, price or seller phone" });
  }

  const itemNumber = String(nextItemNumber++);
  if (findItem(itemNumber)) {
    return res.status(409).json({ error: "Item number already exists" });
  }

const cache = new Map();
  const convert = (u) => {
    if (typeof u !== "string") return "";
    if (!u.startsWith("data:")) return u;
    if (cache.has(u)) return cache.get(u);
    const saved = saveDataUrlToUploads(u, "item");
    cache.set(u, saved);
    return saved;
  };

  const urlsArray = Array.isArray(imageUrls) ? imageUrls.slice(0, 15) : [];
  const convertedUrls = urlsArray.map(convert).filter(Boolean);
  const firstUrl = imageUrl || (convertedUrls[0] || (urlsArray[0] || ""));
  const convertedFirst = convert(firstUrl) || convertedUrls[0] || "";

  const item = {
    id: uuid(),
    code: itemNumber,
    title,
    details: details || "",
    price: Number(price),
    sellerPhone,
    holdHours: holdHours ? Number(holdHours) : 24,
    imageUrl: convertedFirst || "",
    imageUrls: convertedUrls,
    availability: availability || "available",
    condition: condition || "used",
    category: req.body && req.body.category ? String(req.body.category) : "",
  };

  items.push(item);
  res.status(201).json(item);
});

// Public: catalogue for a given seller
app.get("/api/public/seller/:sellerPhone", (req, res) => {
  const phone = req.params.sellerPhone;
  const sellerItems = items.filter((i) => i.sellerPhone === phone);
  res.json(sellerItems);
});

// Public: fetch item by code
app.get("/api/public/item/:code", (req, res) => {
  const codeRaw = String(req.params.code || "").trim();
  const item = findItem(codeRaw);
if (!item) {
    return res.status(404).json({ error: "Item not found." });
  }

  migrateItemImagesInPlace(item);

  res.json({
    id: item.id,
    code: item.code,
    title: item.title,
    details: item.details || "",
    price: item.price,
    holdHours: item.holdHours,
    imageUrl: item.imageUrl,
    imageUrls: Array.isArray(item.imageUrls)
      ? item.imageUrls
      : (item.imageUrl ? [item.imageUrl] : []),
    availability: item.availability,
    condition: item.condition || "used",
    category: item.category || "",
    sellerPhone: item.sellerPhone,
  });
});

// -------- Transactions (escrow) --------
app.post("/api/transactions", requireAuth, idempotencyMiddleware, (req, res) => {
  const {
    fromPhone,
    toPhone,
    itemCode,
    amount,
    deliveryMethod,
    deliveryPoint,
  } = req.body || {};

  if (req.user.role !== "buyer" && req.user.role !== "admin") {
    return res
      .status(403)
      .json({ error: "Only buyers can create transactions." });
  }

  if (req.user.phone !== fromPhone && req.user.role !== "admin") {
    return res.status(403).json({
      error: "You can only create transactions from your own phone number.",
    });
  }

  if (!fromPhone || !toPhone || !itemCode || !amount || !deliveryMethod) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const itemCodeStr = String(itemCode || "").trim();
const item = findItem(itemCodeStr);
  if (item) migrateItemImagesInPlace(item);
const priceNum = Number(amount);
  if (Number.isNaN(priceNum) || priceNum <= 0) {
    return res.status(400).json({ error: "Invalid amount" });
  }

  // 🔹🔹 KYC ENFORCEMENT GOES HERE 🔹🔹
  const kycLevel = req.user.kycLevel || "basic";
  const limits = KYC_LIMITS[kycLevel] || KYC_LIMITS.basic;

  // 1) Per-transaction limit
  if (priceNum > limits.maxPerTx) {
    return res.status(400).json({
      error: `Amount exceeds your per-transaction limit for your KYC level (${limits.maxPerTx} ZMW).`,
    });
  }

  // 2) Daily outgoing total limit for this buyer
  const todayStr = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
  const todayTotal = transactions
    .filter(
      (t) =>
        t.fromPhone === req.user.phone &&
        typeof t.amount === "number" &&
        t.createdAt &&
        t.createdAt.startsWith(todayStr)
    )
    .reduce((sum, t) => sum + t.amount, 0);

  if (todayTotal + priceNum > limits.maxDaily) {
    return res.status(400).json({
      error: `This payment would exceed your daily limit for your KYC level (${limits.maxDaily} ZMW total per day).`,
    });
  }
  // 🔹🔹 END KYC ENFORCEMENT 🔹🔹

  const now = new Date();
const holdDurationHours =
  item && item.holdHours != null ? Number(item.holdHours) : 24;

// Hold countdown starts when seller confirms "Hold item"
const holdExpiresAt = null;

const tx = {
    id: uuid(),
    fromPhone,
    toPhone,
  itemCode: itemCodeStr,
    amount: priceNum,
    deliveryMethod, // 'self_collect' or 'seller_delivery'
    deliveryPoint: deliveryPoint || "",
    liveLocation: null, // { lat, lng, updatedAt }
    status: "pending_payment",
    createdAt: nowIso(),
    paymentProvider: PAYMENTS_MODE,
    paymentStatus: "unpaid",
    paymentRef: null,
    paidAt: null,
    holdDurationHours: holdDurationHours,

    holdExpiresAt,
    holdStartedAt: null,
    transitStartedAt: null,
    completedAt: null,
    disputeActive: false,
    dispute: null,
    disputeDocs: [],
    itemSnapshot: item
      ? {
          code: item.code,
          title: item.title,
          details: item.details || "",
          price: item.price,
          holdHours: item.holdHours,
          imageUrl: item.imageUrl || "",
          imageUrls: Array.isArray(item.imageUrls)
            ? item.imageUrls
            : item.imageUrl
            ? [item.imageUrl]
            : [],
        }
      : null,
  };

  transactions.push(tx);
  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
  logAudit(req, "tx_create", {
  txId: tx.id,
  fromPhone,
  toPhone,
  itemCode: itemCodeStr,
  amount: priceNum,
  deliveryMethod,
  deliveryPoint: deliveryPoint || "",
});
res.status(201).json(tx);
});

// Option B: initiate payment AFTER escrow is created
app.post("/api/transactions/:id/pay", requireAuth, idempotencyMiddleware, async (req, res) => {
  const id = req.params.id;
  const tx = transactions.find((t) => t.id === id);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  const isBuyer = req.user.phone === tx.fromPhone && (req.user.role === "buyer" || req.user.role === "admin");
  const isAdmin = req.user.role === "admin";
  if (!isBuyer && !isAdmin) {
    return res.status(403).json({ error: "Only the buyer can initiate payment." });
  }

  if (tx.paymentStatus === "paid" || tx.status !== "pending_payment") {
    if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
    return res.json(tx);
  }

  if (PAYMENTS_MODE === "demo") {
    tx.paymentProvider = "demo";
    tx.paymentStatus = "paid";
    tx.paymentRef = tx.paymentRef || ("demo_" + uuid());
    tx.paidAt = nowIso();
    tx.status = "pending"; // now seller can hold
    logAudit(req, "tx_pay_demo", { txId: tx.id, paymentRef: tx.paymentRef });
    if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
    return res.json(tx);
  }

  // ===== Airtel Money sandbox (Collection / USSD Push) =====
  if (PAYMENTS_MODE === "airtel_sandbox") {
    tx.paymentProvider = "airtel_sandbox";
    tx.paymentStatus = "pending";
    tx.paymentRef = tx.paymentRef || uuid();

    const msisdn = airtelMsisdnFromPhone(tx.fromPhone);

    try {
      const resp = await airtelInitiateCollection({
        msisdn,
        amount: tx.amount,
        transactionId: tx.paymentRef,
        reference: `TutoPay-${tx.id}`,
      });

      tx.paymentMeta = tx.paymentMeta || {};
      tx.paymentMeta.airtel = {
        initiatedAt: nowIso(),
        transactionId: tx.paymentRef,
        response: resp,
      };

      logAudit(req, "tx_pay_airtel_start", {
        txId: tx.id,
        paymentRef: tx.paymentRef,
        msisdn,
      });

      if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
      return res.json(tx);
    } catch (err) {
      console.error("Airtel initiate error:", err);
      tx.paymentStatus = "unpaid"; // allow retry
      if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
      return res.status(502).json({
        error:
          "Airtel Money sandbox payment initiation failed. " +
          (err && err.message ? err.message : ""),
      });
    }
  } else if (PAYMENTS_MODE === "mtn_sandbox") {
    // ===== MTN MoMo sandbox (Collections: RequestToPay) =====
    try {
      const phone = (req.body && req.body.phone) || (req.user && req.user.phone) || "";
      if (!phone) return res.status(400).json({ error: "phone is required" });

      const { referenceId } = await momoRequestToPay({
        amount: tx.amount,
        msisdn: phone,
        externalId: tx.id,
        payerMessage: "TutoPay escrow deposit",
        payeeNote: "Escrow deposit",
        callbackUrl: MOMO_CALLBACK_URL,
      });

      tx.paymentProvider = "mtn_momo";
      tx.paymentStatus = "pending_payment";
      tx.paymentRef = referenceId;
      logAudit(req, "tx_pay_mtn_start", { txId: tx.id, provider: "mtn_momo", paymentRef: referenceId });
    } catch (err) {
      console.error("MTN MoMo sandbox requesttopay failed:", err && err.response ? err.response.data : err);
      return res.status(502).json({
        error:
          "MTN MoMo sandbox payment initiation failed. " +
          (err && err.message ? err.message : ""),
      });
    }
  } else {

    // ===== Default / other providers (placeholder) =====
    tx.paymentProvider = PAYMENTS_MODE;
    tx.paymentStatus = "pending";
    tx.paymentRef = tx.paymentRef || uuid();
    logAudit(req, "tx_pay_start", { txId: tx.id, provider: PAYMENTS_MODE, paymentRef: tx.paymentRef });

  }

  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
  return res.json(tx);
});

app.post("/api/transactions/:id/payment/requery", requireAuth, idempotencyMiddleware, async (req, res) => {
  const id = req.params.id;
  const tx = transactions.find((t) => t.id === id);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  const isBuyer = req.user.phone === tx.fromPhone && (req.user.role === "buyer" || req.user.role === "admin");
  const isSeller = req.user.phone === tx.toPhone && (req.user.role === "seller" || req.user.role === "admin");
  const isAdmin = req.user.role === "admin";
  if (!isBuyer && !isSeller && !isAdmin) {
    return res.status(403).json({ error: "Not allowed." });
  }

  // If already paid, nothing to do
  if (tx.paymentStatus === "paid" || tx.status === "pending") {
    if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
    return res.json(tx);
  }

  // ===== Airtel Money sandbox status check =====
  const provider = String(tx.paymentProvider || PAYMENTS_MODE || "").toLowerCase();
  if (provider === "airtel_sandbox") {
    if (!tx.paymentRef) {
      if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
      return res.json(tx);
    }

    try {
      const resp = await airtelCheckCollectionStatus(tx.paymentRef);

      // Common: resp.data.data.transaction.status OR resp.data.transaction.status OR resp.transaction.status
      const t =
        (resp && resp.data && resp.data.data && resp.data.data.transaction) ||
        (resp && resp.data && resp.data.transaction) ||
        (resp && resp.data && resp.data.txn) ||
        (resp && resp.transaction) ||
        null;

      const status = t && t.status ? String(t.status) : null;
      const message = t && t.message ? String(t.message) : null;

      tx.paymentMeta = tx.paymentMeta || {};
      tx.paymentMeta.airtel = tx.paymentMeta.airtel || {};
      tx.paymentMeta.airtel.lastRequeryAt = nowIso();
      tx.paymentMeta.airtel.lastStatus = status;
      tx.paymentMeta.airtel.lastMessage = message;
      tx.paymentMeta.airtel.lastResponse = resp;

      if (status === "TS") {
        tx.paymentProvider = "airtel_sandbox";
        tx.paymentStatus = "paid";
        tx.paidAt = nowIso();
        tx.status = "pending"; // seller can now hold
        logAudit(req, "tx_pay_airtel_paid", { txId: tx.id, paymentRef: tx.paymentRef });
      } else if (status === "TF") {
        tx.paymentProvider = "airtel_sandbox";
        tx.paymentStatus = "failed";
        tx.status = "pending_payment"; // allow buyer to try again
        logAudit(req, "tx_pay_airtel_failed", { txId: tx.id, paymentRef: tx.paymentRef, message });
      } else {
        // TIP (in progress), TA (ambiguous), or unknown
        tx.paymentProvider = "airtel_sandbox";
        tx.paymentStatus = "pending";
        logAudit(req, "tx_pay_airtel_pending", { txId: tx.id, paymentRef: tx.paymentRef, status, message });
      }

      if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
      return res.json(tx);
    } catch (err) {
      console.error("Airtel requery error:", err);
      return res.status(502).json({
        error:
          "Airtel Money sandbox status check failed. " +
          (err && err.message ? err.message : ""),
      });
    }
  } else if (tx.paymentProvider === "mtn_momo") {
    try {
      const data = await momoGetRequestToPayStatus(tx.paymentRef);
      const st = (data && data.status) ? String(data.status).toUpperCase() : "";

      if (st === "SUCCESSFUL") {
        tx.paymentStatus = "paid";
        tx.status = "paid";
        tx.paidAt = tx.paidAt || nowIso();
        logAudit(req, "tx_pay_mtn_success", { txId: tx.id, paymentRef: tx.paymentRef });
      } else if (st === "FAILED" || st === "REJECTED") {
        tx.paymentStatus = "failed";
        logAudit(req, "tx_pay_mtn_failed", { txId: tx.id, paymentRef: tx.paymentRef, status: st, data });
      } else {
        tx.paymentStatus = "pending_payment";
      }
    } catch (err) {
      console.error("MTN MoMo status requery failed:", err && err.response ? err.response.data : err);
      // keep existing status if requery fails
    }
  }

  // Default: no provider integration yet
  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
  return res.json(tx);
});



// Auto-resolve certain dispute states (e.g. auto-refund after 72h)
function maybeAutoResolveDispute(tx) {
  if (!tx.disputeActive || !tx.dispute) return;

  if (
    tx.dispute.type === "escrow_refund" &&
    tx.dispute.status === "pending_seller_response" &&
    tx.dispute.autoRefundAfter
  ) {
    const deadlineTs = Date.parse(tx.dispute.autoRefundAfter);
    if (!Number.isNaN(deadlineTs) && Date.now() >= deadlineTs) {
      tx.dispute.status = "auto_refunded";
      tx.dispute.resolvedAt = nowIso();
      tx.disputeActive = false;
      tx.status = "refunded";
    }
  }
}

app.get("/api/transactions", requireAuth, (req, res) => {
  transactions.forEach(maybeAutoResolveDispute);

  let view = transactions;
  if (req.user.role !== "admin") {
    view = transactions.filter(
      (t) => t.fromPhone === req.user.phone || t.toPhone === req.user.phone
    );
  }

  res.json(view);
});

// Advance or update a transaction state
app.post("/api/transactions/:id/action", requireAuth, idempotencyMiddleware, (req, res) => {
  const { action } = req.body || {};
  const id = req.params.id;
  const tx = transactions.find((t) => t.id === id);

  if (!tx) return res.status(404).json({ error: "Transaction not found" });
  if (!action) return res.status(400).json({ error: "Missing action" });
  
    const isBuyer =
    req.user.phone === tx.fromPhone && req.user.role === "buyer";
  const isSeller =
    req.user.phone === tx.toPhone && req.user.role === "seller";
  const isAdmin = req.user.role === "admin";

  if (action.startsWith("buyer_") && !isBuyer && !isAdmin) {
    return res
      .status(403)
      .json({ error: "Only the buyer can perform this action." });
  }

  if (action.startsWith("seller_") && !isSeller && !isAdmin) {
    return res
      .status(403)
      .json({ error: "Only the seller can perform this action." });
  }

  // 🔒 Dispute freeze – block normal actions while dispute is active
  const frozenActions = [
    "seller_hold",
    "seller_start_delivery",
    "seller_mark_delivered",
    "buyer_confirm_collected",
    "buyer_confirm_received",
  ];

  if (tx.disputeActive && frozenActions.includes(action) && !isAdmin) {
    return res.status(400).json({
      error:
        "Transaction is under dispute – actions are frozen until the issue is resolved.",
    });
  }
  const prevStatus = tx.status;
  const now = nowIso();

  switch (action) {
    case "seller_hold": {
      // Option B: cannot hold until buyer payment is confirmed
      if (tx.status === "pending_payment" || tx.paymentStatus !== "paid") {
        return res.status(400).json({ error: "Cannot hold item until payment is confirmed." });
      }

      if (tx.deliveryMethod !== "self_collect" || tx.status !== "pending") {
        return res
          .status(400)
          .json({ error: "Cannot hold item in current state" });
      }
      tx.status = "held";
tx.holdStartedAt = now;
const hrs = Number(tx.holdDurationHours || 24);
tx.holdExpiresAt = new Date(Date.now() + hrs * 60 * 60 * 1000).toISOString();
break;
    }

    case "seller_start_delivery": {
      if (tx.deliveryMethod === "self_collect" || tx.status !== "pending") {
        return res
          .status(400)
          .json({ error: "Cannot start delivery in current state" });
      }
      tx.status = "in_transit";
      tx.transitStartedAt = now;
      break;
    }

    case "seller_mark_delivered": {
      if (tx.deliveryMethod === "self_collect" || tx.status !== "in_transit") {
        return res
          .status(400)
          .json({ error: "Cannot mark delivered in current state" });
      }
      tx.status = "delivered";
      break;
    }

    case "buyer_confirm_collected": {
      if (
        tx.deliveryMethod !== "self_collect" ||
        !["held", "delivered"].includes(tx.status)
      ) {
        return res
          .status(400)
          .json({ error: "Cannot confirm collected in current state" });
      }
      tx.status = "completed";
      tx.completedAt = now;
      break;
    }

    case "buyer_confirm_received": {
      if (
        tx.deliveryMethod === "self_collect" ||
        !["in_transit", "delivered"].includes(tx.status)
      ) {
        return res
          .status(400)
          .json({ error: "Cannot confirm received in current state" });
      }
      tx.status = "completed";
      tx.completedAt = now;
      break;
    }

    case "open_dispute": {
      // Legacy simple dispute toggle (kept for backward compatibility)
      tx.disputeActive = true;
      tx.status = "disputed";
      break;
    }

    default:
      return res.status(400).json({ error: "Unknown action" });
  }

    logAudit(req, "tx_action", {
    txId: tx.id,
    action,
    prevStatus,
    newStatus: tx.status,
  });

  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
    return res.json(tx);
});


// Structured dispute / issue opening (buyer or seller)
app.post("/api/transactions/:id/dispute", requireAuth, (req, res) => {
  const id = req.params.id;
  const tx = transactions.find((t) => t.id === id);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  const isBuyer =
    req.user.phone === tx.fromPhone && req.user.role === "buyer";
  const isSeller =
    req.user.phone === tx.toPhone && req.user.role === "seller";
  const isAdmin = req.user.role === "admin";

  if (!isBuyer && !isSeller && !isAdmin) {
    return res
      .status(403)
      .json({ error: "Only buyer, seller, or admin can open a dispute." });
  }

  const { type, reasonCode, reasonText, openedBy } = req.body || {};
  const allowedTypes = ["escrow_refund", "report_seller", "report_admin"];

  if (!type || !allowedTypes.includes(type)) {
    return res.status(400).json({ error: "Invalid or missing dispute type" });
  }

  if (tx.disputeActive) {
    return res
      .status(400)
      .json({ error: "There is already an active issue on this transaction" });
  }

  // Only allow refund-style disputes while money is still locked in escrow
  const refundableStatuses = ["pending", "held", "in_transit", "delivered", "disputed"];
  if (type === "escrow_refund") {
    if (!refundableStatuses.includes(tx.status)) {
      return res
        .status(400)
        .json({ error: "Escrow refund can only be requested while funds are still held" });
    }
    if (tx.holdExpiresAt && Date.now() > Date.parse(tx.holdExpiresAt)) {
      return res
        .status(400)
        .json({ error: "Holding period has expired – refund window has closed" });
    }
  }

  const now = nowIso();
  const dispute = {
    id: uuid(),
    type,
    openedBy: openedBy || "buyer",
    reasonCode: reasonCode || null,
    reasonText: reasonText || "",
    status: type === "escrow_refund" ? "pending_seller_response" : "pending_admin_review",
    openedAt: now,
    sellerDecision: null,
    autoRefundAfter:
      type === "escrow_refund"
        ? new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString()
        : null,
  };

  tx.disputeActive = true;
  tx.dispute = dispute;
  tx.status = "disputed";

   logAudit(req, "dispute_open", {
    txId: tx.id,
    type,
    openedBy: tx.dispute.openedBy,
    reasonCode: tx.dispute.reasonCode,
    reasonText: tx.dispute.reasonText,
  });

  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
    return res.json(tx);
});

// Seller decision on an escrow refund request
app.post("/api/transactions/:id/dispute/decision", requireAuth, (req, res) => {
  const id = req.params.id;
  const tx = transactions.find((t) => t.id === id);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  const isSeller =
    req.user.phone === tx.toPhone && req.user.role === "seller";
  const isAdmin = req.user.role === "admin";

  if (!isSeller && !isAdmin) {
    return res
      .status(403)
      .json({ error: "Only the seller or admin can decide on this dispute." });
  }

  const { decision, reasonCode, reasonText, otpId, otpCode } = req.body || {};

  if (!tx.disputeActive || !tx.dispute) {
    return res.status(400).json({ error: "No active dispute on this transaction" });
  }

  if (tx.dispute.type !== "escrow_refund") {
    return res
      .status(400)
      .json({ error: "This dispute does not support seller decisions in the app" });
  }

  if (tx.dispute.status !== "pending_seller_response") {
    return res
      .status(400)
      .json({ error: "Dispute is not waiting for seller response" });
  }

  if (!decision || !["agree", "disagree"].includes(decision)) {
    return res.status(400).json({ error: "Missing or invalid decision" });
  }

  // 🔐 OTP check only when seller agrees to refund (admin can bypass)
  if (decision === "agree" && isSeller) {
    if (!otpId || !otpCode) {
      return res
        .status(400)
        .json({ error: "OTP is required to confirm refund." });
    }

    const otp = otps.get(otpId);
    if (!otp || otp.used) {
      return res
        .status(400)
        .json({ error: "Invalid or expired OTP (not found)." });
    }

    if (
      otp.userPhone !== req.user.phone ||
      otp.purpose !== "seller_refund_agree" ||
      otp.txId !== tx.id
    ) {
      return res
        .status(400)
        .json({ error: "OTP does not match this refund action." });
    }

    if (Date.now() > otp.expiresAt) {
      return res
        .status(400)
        .json({ error: "OTP has expired. Please request a new one." });
    }

    if (String(otp.code).trim() !== String(otpCode).trim()) {
      return res.status(400).json({ error: "Incorrect OTP code." });
    }

    // Mark OTP as used
    otp.used = true;
  }

  const now = nowIso();
  tx.dispute.sellerDecision = {
    decision,
    reasonCode: reasonCode || null,
    reasonText: reasonText || "",
    decidedAt: now,
  };

  if (decision === "agree") {
    tx.dispute.status = "seller_agreed_refund";
    tx.dispute.resolvedAt = now;
    tx.disputeActive = false;
    tx.status = "refunded";
  } else {
    tx.dispute.status = "seller_disagreed";
  }

   logAudit(req, "dispute_decision", {
    txId: tx.id,
    decision,
    reasonCode: reasonCode || null,
    reasonText: reasonText || "",
    bySeller: isSeller,
    byAdmin: isAdmin,
    disputeStatus: tx.dispute.status,
    txStatus: tx.status,
  });

  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }


  res.json(tx);
});

// Upload a supporting document for a dispute (up to 10 MB)
app.post("/api/transactions/:id/dispute/upload", requireAuth, (req, res) => {
  disputeUpload.single("file")(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: "File too large (max 10 MB)" });
      }
      return res.status(400).json({ error: err.message || "Upload failed" });
    }

    const id = req.params.id;
    const tx = transactions.find((t) => t.id === id);
    if (!tx) return res.status(404).json({ error: "Transaction not found" });

    if (!tx.disputeActive || !tx.dispute) {
      return res.status(400).json({ error: "No active dispute on this transaction" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    if (!Array.isArray(tx.disputeDocs)) {
      tx.disputeDocs = [];
    }

    const doc = {
      filename: req.file.filename,
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      uploadedAt: nowIso(),
      url: `/uploads/${req.file.filename}`,
    };

    tx.disputeDocs.push(doc);

    res.json({ ok: true, doc });
  });
});

// Seller updates live GPS location for a transaction
app.post("/api/transactions/:id/location", requireAuth, (req, res) => {
  const id = req.params.id;
  const tx = transactions.find((t) => t.id === id);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  const isSeller =
    req.user.phone === tx.toPhone && req.user.role === "seller";
  const isAdmin = req.user.role === "admin";

  if (!isSeller && !isAdmin) {
    return res.status(403).json({
      error: "Only the seller can send live location for this transaction.",
    });
  }

  const { lat, lng } = req.body || {};
  if (lat == null || lng == null) {
    return res.status(400).json({ error: "Missing lat or lng" });
  }

  tx.liveLocation = {
    lat,
    lng,
    updatedAt: nowIso(),
  };

  res.json({ ok: true, liveLocation: tx.liveLocation });
});

// -------- Quote Requests --------
app.get("/api/requests", requireAuth, (req, res) => {
  const isAdmin = req.user.role === "admin";

  if (isAdmin) {
    return res.json(requests);
  }

  const myReqs = requests.filter(
    (rq) => rq.fromPhone === req.user.phone || rq.toPhone === req.user.phone
  );

  res.json(myReqs);
});

app.post("/api/requests", requireAuth, (req, res) => {
  const { fromPhone, toPhone, itemCode, quantity, itemSnapshot } = req.body || {};

    if (req.user.role !== "buyer" && req.user.role !== "admin") {
    return res.status(403).json({ error: "Only buyers can create requests." });
  }

  if (req.user.phone !== fromPhone && req.user.role !== "admin") {
    return res.status(403).json({
      error: "You can only send requests from your own phone number.",
    });
  }

  if (!fromPhone || !toPhone || !itemCode) {
    return res
      .status(400)
      .json({ error: "Missing fromPhone, toPhone or itemCode" });
  }

  // Try live catalogue first, fall back to snapshot sent from frontend
  const item = findItem(itemCode);
  const snapSource = item || itemSnapshot || null;

  const reqObj = {
    id: uuid(),
    fromPhone,
    toPhone,
    itemCode,
    quantity: Number(quantity) || 1,
    status: "open",
    createdAt: nowIso(),
    repliedAt: null,
    reply: null,
       itemSnapshot: snapSource
      ? {
          code: snapSource.code,
          title: snapSource.title,
          details: snapSource.details || "",
          price: snapSource.price,
          imageUrl: snapSource.imageUrl || "",
          imageUrls: Array.isArray(snapSource.imageUrls)
            ? snapSource.imageUrls
            : (snapSource.imageUrl ? [snapSource.imageUrl] : []),
        }
      : null,
  };

  requests.push(reqObj);
  if (dbEnabled()) { dbUpsertRequest(reqObj).catch(() => {}); }
  res.status(201).json(reqObj);
});

// ---- Seller replies to a request (supports POST and PATCH) ----
function handleRequestReply(req, res) {
  try {
    if (!Array.isArray(requests)) {
      console.error("requests array is not defined properly");
      return res.status(500).json({ error: "Server misconfigured" });
    }

    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "Missing request id" });
    }

    const rIndex = requests.findIndex((x) => x && x.id === id);
    if (rIndex === -1) {
      return res.status(404).json({ error: "Request not found" });
    }

    const rq = requests[rIndex];

    const isSeller =
      req.user.role === "seller" && req.user.phone === rq.toPhone;
    const isAdmin = req.user.role === "admin";

    if (!isSeller && !isAdmin) {
      return res.status(403).json({
        error: "Only the seller for this request (or admin) can reply.",
      });
    }

    const r = requests[rIndex];

    const {
      price,
      itemCode,
      availability,
      preOrderDate,
      preOrderNote,
      message,
    } = req.body || {};

    const reply = {
      price: price != null ? Number(price) : null,
      itemCode: itemCode || null,
      availability: availability || null,
      preOrderDate: preOrderDate || null,
      preOrderNote: preOrderNote || null,
      message: message || "",
    };

    const updated = {
      ...r,
      reply,
      status: "answered",
      repliedAt: nowIso(),
    };

    requests[rIndex] = updated;

    if (dbEnabled()) { dbUpsertRequest(updated).catch(() => {}); }
    return res.json(updated);
  } catch (err) {
    console.error("handleRequestReply error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error while saving reply" });
  }
}

app.post("/api/requests/:id/reply", requireAuth, handleRequestReply);
app.patch("/api/requests/:id/reply", requireAuth, handleRequestReply);


// -------- Phone normalisation helper for public routes --------
function normalizePhone(phone) {
  if (!phone) return "";
  const p = String(phone).trim();
  // Simple Zambian style normalisation for demo:
  if (p.startsWith("+260")) return "0" + p.slice(4);
  if (p.startsWith("260")) return "0" + p.slice(3);
  return p;
}

// Public route: lookup seller catalogue from URL-short code later if needed
app.get("/api/public/seller-normalized/:phone", (req, res) => {
  const p = normalizePhone(req.params.phone);
  const sellerItems = items.filter((i) => normalizePhone(i.sellerPhone) === p);
  res.json(sellerItems);
});

// -------- Admin: view audit log (demo) --------
app.get("/api/admin/audit", requireAuth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }

  const limit = Number(req.query.limit) || 200;
  const entries = auditLog.slice(-limit).reverse(); // newest first

  res.json({ entries });
});

// -------- Start server --------

// ---- JSON error handler (so frontend doesn't get HTML/doctype) ----
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: err.message || 'Server error' });
});

/**
 * Boot order matters on Railway:
 * - Start HTTP listener immediately so Railway can hit /health.
 * - Initialize DB in the background; API routes are gated until dbReady=true.
 */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`TutoPay API running on port ${PORT}`);
});

// Run DB init in background (does NOT prevent the server from starting)
dbInit()
  .then(() => {
    dbReady = true;
    console.log('[DB] Ready.');
  })
  .catch((err) => {
    dbInitError = err;
    console.error('[DB] Init failed:', err);
  });

// Nice shutdown (Railway sends SIGTERM on deploy/stop)
process.on('SIGTERM', () => {
  console.log('[SYS] SIGTERM received, closing server...');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  console.log('[SYS] SIGINT received, closing server...');
  server.close(() => process.exit(0));
});
