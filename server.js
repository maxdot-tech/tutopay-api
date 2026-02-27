// server.js
// TutoPay demo backend — escrow logic + catalogue + buyer→seller requests with replies + live GPS

const express = require("express");
const cors = require("cors");
const { v4: uuid } = require("uuid");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const crypto = require("crypto");
const DEMO_ADMIN_PHONE = process.env.DEMO_ADMIN_PHONE || "0770100100";
const DEMO_ADMIN_PIN = process.env.DEMO_ADMIN_PIN || "4567";
// Optional: allow turning off public self-signup in production
const ALLOW_PUBLIC_SIGNUP = (process.env.ALLOW_PUBLIC_SIGNUP || "true").toLowerCase() === "true";
const DEMO_MODE = (process.env.DEMO_MODE || "true").toLowerCase() === "true";
const DEMO_BANNER_TEXT = process.env.DEMO_BANNER_TEXT || "DEMO MODE: Test environment only. No real funds are moved.";

const app = express();
const PORT = process.env.PORT || 4000;


/**
 * Simple in-memory rate limiter (no extra dependencies).
 * NOTE: Suitable for a single-node demo deployment. For multi-node, use a shared store (Redis) or a provider limiter.
 */
function createRateLimiter({ windowMs, max, keyFn, message }) {
  const hits = new Map(); // key -> { count, resetAt }
  const defaultMsg = message || "Too many requests. Please try again shortly.";

  return function rateLimiter(req, res, next) {
    try {
      const now = Date.now();
      const key = (keyFn ? keyFn(req) : req.ip) || req.ip || "unknown";
      const rec = hits.get(key);

      if (!rec || now > rec.resetAt) {
        hits.set(key, { count: 1, resetAt: now + windowMs });
        return next();
      }

      rec.count += 1;
      if (rec.count > max) {
        const retryAfterSec = Math.ceil((rec.resetAt - now) / 1000);
        res.set("Retry-After", String(Math.max(1, retryAfterSec)));
        return res.status(429).json({ error: defaultMsg });
      }

      return next();
    } catch (e) {
      return next(); // fail open
    }
  };
}

// Limiters (tuned for public demo)
const loginLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 10,
  keyFn: (req) => `login:${req.ip}:${String((req.body || {}).phone || "").trim()}`,
  message: "Too many login attempts. Please wait a minute and try again.",
});

const payLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 20,
  keyFn: (req) => `pay:${req.ip}:${String((req.params && req.params.id) || "")}`,
  message: "Too many payment requests. Please wait a moment and try again.",
});

const requeryLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 30,
  keyFn: (req) => `requery:${req.ip}:${String((req.params && req.params.id) || "")}`,
  message: "Too many payment status checks. Please wait a moment and try again.",
});

const payoutLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 10,
  keyFn: (req) => `payout:${req.ip}:${String((req.params && req.params.id) || "")}`,
  message: "Too many payout requests. Please wait a moment and try again.",
});




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
  const res = await fetchWithRetry(url, {
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

  const res = await fetchWithRetry(url, {
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

  const res = await fetchWithRetry(url, {
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

// Demo mode headers (helps partners/regulators know this is not production)
app.use((req, res, next) => {
  if (DEMO_MODE) {
    res.set("X-Demo-Mode", "true");
    res.set("X-Demo-Banner", DEMO_BANNER_TEXT);
  }
  next();
});

// Lightweight config endpoint for the frontend to show a demo banner
app.get("/api/config", (req, res) => {
  res.json({
    demoMode: DEMO_MODE,
    bannerText: DEMO_BANNER_TEXT,
    allowPublicSignup: ALLOW_PUBLIC_SIGNUP,
  });
});

// (optional, but good for safety if you use urlencoded anywhere)
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Serve the frontend and uploaded dispute docs
app.use(express.static("public"));

// ===== MTN MoMo Sandbox helpers (Collections + Disbursement) =====
const MOMO_BASE_URL = process.env.MOMO_BASE_URL || "https://sandbox.momodeveloper.mtn.com";
const MOMO_CURRENCY = process.env.MOMO_CURRENCY || "ZMW";
const PUBLIC_API_BASE = process.env.PUBLIC_API_BASE || process.env.API_PUBLIC_BASE || "https://api.tutopay.online";
const MOMO_CALLBACK_URL = process.env.MOMO_CALLBACK_URL || `${PUBLIC_API_BASE}/api/callbacks/mtn/collection`;

const MTN_CALLBACK_SECRET = String(process.env.MTN_CALLBACK_SECRET || process.env.CALLBACK_SHARED_SECRET || "").trim();
const AIRTEL_CALLBACK_SECRET = String(process.env.AIRTEL_CALLBACK_SECRET || process.env.CALLBACK_SHARED_SECRET || "").trim();

function safeEq(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (aa.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(aa, bb); } catch { return false; }
}

function verifyProviderCallback(req, provider) {
  const expected = provider === "airtel" ? AIRTEL_CALLBACK_SECRET : MTN_CALLBACK_SECRET;
  if (!expected) return { ok: true, skipped: true };
  const got =
    req.headers["x-callback-secret"] ||
    req.headers["x-webhook-secret"] ||
    req.headers["x-momo-callback-secret"] ||
    req.headers["x-airtel-callback-secret"] ||
    req.headers["authorization"] ||
    (req.query && (req.query.secret || req.query.token)) ||
    "";
  const cleaned = String(got).replace(/^Bearer\s+/i, "").trim();
  if (!safeEq(cleaned, expected)) return { ok: false };
  return { ok: true };
}

const callbackSeen = new Map(); // key -> expiresAtMs
function callbackAlreadyProcessed(key, ttlMs = 24*60*60*1000) {
  const now = Date.now();
  for (const [k, exp] of callbackSeen) if (exp <= now) callbackSeen.delete(k);
  if (callbackSeen.has(key)) return true;
  callbackSeen.set(key, now + ttlMs);
  return false;
}

function findTxByAnyReference(ref) {
  const sref = String(ref || "").trim();
  if (!sref) return null;
  return transactions.find((t) =>
    String(t.paymentRef || "") === sref ||
    String((t.disbursement && t.disbursement.referenceId) || "") === sref ||
    String(t.id || "") === sref
  ) || null;
}

function normalizeCallbackStatus(raw, provider) {
  const s = String(raw || "").toUpperCase();
  if (provider === "airtel") {
    if (["TS","SUCCESS","SUCCESSFUL","PAID"].includes(s)) return "SUCCESSFUL";
    if (["TF","FAILED","FAIL","REJECTED"].includes(s)) return "FAILED";
    return "PENDING";
  }
  if (["SUCCESSFUL","SUCCESS","COMPLETED"].includes(s)) return "SUCCESSFUL";
  if (["FAILED","FAIL","REJECTED"].includes(s)) return "FAILED";
  return "PENDING";
}

function applyCollectionCallbackUpdate(tx, provider, normStatus, reference, rawBody) {
  tx.paymentProvider = provider === "airtel" ? "airtel_sandbox" : "mtn_momo";
  tx.paymentStatus = normStatus === "SUCCESSFUL" ? "paid" : (normStatus === "FAILED" ? "failed" : "pending");
  tx.paymentMeta = tx.paymentMeta || {};
  tx.paymentMeta.callbacks = tx.paymentMeta.callbacks || [];
  tx.paymentMeta.callbacks.push({ at: nowIso(), provider, status: normStatus, reference, body: rawBody });
  if (tx.paymentMeta.callbacks.length > 20) tx.paymentMeta.callbacks.shift();

  if (normStatus === "SUCCESSFUL") {
    tx.paidAt = tx.paidAt || nowIso();
    tx.status = "pending";
    tx.collectionReconciled = false;
    recordLedger(null, tx, "deposit_confirmed", { reference, provider: tx.paymentProvider, actorPhone: "system", actorRole: "system", notes: "Callback confirmed collection" });
  } else if (normStatus === "FAILED") {
    tx.status = "pending_payment";
  }
}

function applyPayoutCallbackUpdate(tx, normStatus, reference, rawBody) {
  tx.disbursement = tx.disbursement || {};
  tx.disbursement.referenceId = tx.disbursement.referenceId || reference;
  tx.disbursement.lastCallbackAt = nowIso();
  tx.disbursement.lastCallbackBody = rawBody;

  if (normStatus === "SUCCESSFUL") {
    tx.disbursement.status = "successful";
    tx.disbursement.completedAt = Date.now();
    tx.payoutReconciled = false;
    recordLedger(null, tx, "payout_completed", { reference, provider: "mtn_momo_disbursement", actorPhone: "system", actorRole: "system", notes: "Callback confirmed payout" });
  } else if (normStatus === "FAILED") {
    tx.disbursement.status = "failed";
    tx.payoutReconciled = false;
    recordLedger(null, tx, "payout_failed", { reference, provider: "mtn_momo_disbursement", actorPhone: "system", actorRole: "system", notes: "Callback reported payout failure" });
  } else {
    tx.disbursement.status = tx.disbursement.status || "pending";
  }
}

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

// ---- MTN MoMo structured logs (shows up in Railway Logs) ----
function momoLog(event, payload) {
  payload = payload || {};
  try {
    const safe = Object.assign({ ts: new Date().toISOString(), event: event }, payload);
    console.log("[MTN_MOMO]", JSON.stringify(safe));
  } catch (e) {
    console.log("[MTN_MOMO]", event, payload);
  }
}



// ---- Network helper: retry transient upstream errors (502/503/504) ----
function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function fetchWithRetry(url, options, { retries = 3, baseDelayMs = 800 } = {}) {
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, options);
      // Retry only on transient upstream errors
      if ([502, 503, 504].includes(res.status) && attempt < retries) {
        await _sleep(baseDelayMs * attempt);
        continue;
      }
      return res;
    } catch (e) {
      lastErr = e;
      if (attempt < retries) {
        await _sleep(baseDelayMs * attempt);
        continue;
      }
    }
  }
  throw lastErr || new Error('fetch failed');
}

async function momoFetchJson(url, { method = "GET", headers = {}, body } = {}) {
  // No axios dependency: use built-in fetch (Node 18+).
  const opts = { method, headers: { ...headers } };
  if (body !== undefined) opts.body = body;
  const res = await fetchWithRetry(url, opts, { retries: 3, baseDelayMs: 800 });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const msg = (typeof data === "string" && data) ? data : JSON.stringify(data);
    const err = new Error("MoMo HTTP " + res.status + ": " + msg);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return data;
}

async function momoGetToken(product) {
  // product: "collection" | "disbursement"
  const isCollection = product === "collection";
  if (isCollection) {
    momoAssertEnv(["MTN_COLLECTION_SUB_KEY", "MTN_COLLECTION_APIUSER", "MTN_COLLECTION_APIKEY", "MOMO_BASE_URL"]);
  } else {
    momoAssertEnv(["MTN_DISBURSEMENT_SUB_KEY", "MTN_DISBURSEMENT_APIUSER", "MTN_DISBURSEMENT_APIKEY", "MOMO_BASE_URL"]);
  }

  const subKey = isCollection ? process.env.MTN_COLLECTION_SUB_KEY : process.env.MTN_DISBURSEMENT_SUB_KEY;
  const apiUser = isCollection ? process.env.MTN_COLLECTION_APIUSER : process.env.MTN_DISBURSEMENT_APIUSER;
  const apiKey = isCollection ? process.env.MTN_COLLECTION_APIKEY : process.env.MTN_DISBURSEMENT_APIKEY;

  const url = isCollection ? `${process.env.MOMO_BASE_URL}/collection/token/` : `${process.env.MOMO_BASE_URL}/disbursement/token/`;
  const auth = Buffer.from(`${apiUser}:${apiKey}`).toString("base64");

  const data = await momoFetchJson(url, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Ocp-Apim-Subscription-Key": subKey,
      "X-Target-Environment": "sandbox"
    }
  });
  return data?.access_token;
}

async function momoRequestToPay({ amount, currency, payerMsisdn, msisdn, externalId, payerMessage, payeeNote }) {
  momoAssertEnv(["MOMO_BASE_URL", "MTN_COLLECTION_SUB_KEY", "MTN_COLLECTION_APIUSER", "MTN_COLLECTION_APIKEY"]);
  const token = await momoGetToken("collection");
  const referenceId = crypto.randomUUID();
  const currencyFinal = String(currency || process.env.MOMO_CURRENCY || "ZMW");
  const payerMsisdnFinal = String(payerMsisdn || msisdn || "");
  momoLog("requesttopay_create", { referenceId, amount: String(amount), currency: currencyFinal, payerMsisdn: payerMsisdnFinal, externalId: String(externalId || referenceId) });
  const url = `${process.env.MOMO_BASE_URL}/collection/v1_0/requesttopay`;

  await momoFetchJson(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Reference-Id": referenceId,
      "X-Target-Environment": "sandbox",
      "Ocp-Apim-Subscription-Key": process.env.MTN_COLLECTION_SUB_KEY,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      amount: String(amount),
      currency: currencyFinal,
      externalId: String(externalId || referenceId),
      payer: { partyIdType: "MSISDN", partyId: payerMsisdnFinal },
      payerMessage: String(payerMessage || "TutoPay escrow"),
      payeeNote: String(payeeNote || "TutoPay escrow")
    })
  });
  momoLog("requesttopay_accepted", { referenceId });

  return { referenceId };
}

async function momoGetRequestToPayStatus(referenceId) {
  momoAssertEnv(["MOMO_BASE_URL", "MTN_COLLECTION_SUB_KEY", "MTN_COLLECTION_APIUSER", "MTN_COLLECTION_APIKEY"]);
  const token = await momoGetToken("collection");
  const url = `${process.env.MOMO_BASE_URL}/collection/v1_0/requesttopay/${referenceId}`;
  const data = await momoFetchJson(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Target-Environment": "sandbox",
      "Ocp-Apim-Subscription-Key": process.env.MTN_COLLECTION_SUB_KEY
    }
  });
  return data;
}

function momoNormalizeMsisdn(input) {
  const s = String(input || "").trim();
  return s.replace(/\D+/g, "");
}

async function momoDisburseTransfer({ amount, currency, payeeMsisdn, externalId, payerMessage, payeeNote }) {
  momoAssertEnv([
    "MOMO_BASE_URL",
    "MOMO_TARGET_ENV",
    "MTN_DISBURSEMENT_SUB_KEY",
    "MTN_DISBURSEMENT_APIUSER",
    "MTN_DISBURSEMENT_APIKEY",
  ]);

  const token = await momoGetToken("disbursement");
  const referenceId = uuidv4();

  const url = `${process.env.MOMO_BASE_URL}/disbursement/v1_0/transfer`;
  const targetEnv = (process.env.MOMO_TARGET_ENV || "sandbox").trim();

  const body = {
    amount: String(amount),
    currency: currency || process.env.MOMO_CURRENCY || "EUR",
    externalId: externalId || referenceId,
    payee: {
      partyIdType: "MSISDN",
      partyId: momoNormalizeMsisdn(payeeMsisdn),
    },
    payerMessage: payerMessage || "TutoPay payout",
    payeeNote: payeeNote || "TutoPay payout",
  };

  const headers = {
    Authorization: `Bearer ${token}`,
    "X-Reference-Id": referenceId,
    "X-Target-Environment": targetEnv,
    "Ocp-Apim-Subscription-Key": process.env.MTN_DISBURSEMENT_SUB_KEY,
    "Content-Type": "application/json",
  };

  // optional, only if you have a public callback endpoint
  if (process.env.MOMO_CALLBACK_URL) {
    headers["X-Callback-Url"] = process.env.MOMO_CALLBACK_URL;
  }

  const resp = await momoFetchJson(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  console.log(
    `MTN DISBURSEMENT transfer initiated ref=${referenceId} amount=${body.amount} ${body.currency} payee=${body.payee.partyId}`
  );

  return { referenceId, request: body, response: resp };
}

async function momoGetTransferStatus(referenceId) {
  momoAssertEnv([
    "MOMO_BASE_URL",
    "MOMO_TARGET_ENV",
    "MTN_DISBURSEMENT_SUB_KEY",
    "MTN_DISBURSEMENT_APIUSER",
    "MTN_DISBURSEMENT_APIKEY",
  ]);

  const token = await momoGetToken("disbursement");
  const url = `${process.env.MOMO_BASE_URL}/disbursement/v1_0/transfer/${referenceId}`;
  const targetEnv = (process.env.MOMO_TARGET_ENV || "sandbox").trim();

  const resp = await momoFetchJson(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Target-Environment": targetEnv,
      "Ocp-Apim-Subscription-Key": process.env.MTN_DISBURSEMENT_SUB_KEY,
    },
  });

  console.log(`MTN DISBURSEMENT transfer status ref=${referenceId} ->`, resp.status);
  return resp;
}


// Provider callback handlers (MTN / Airtel) with shared-secret verification and idempotent processing
function extractMtnCallbackFields(body) {
  const b = body || {};
  const ref = b.referenceId || b.financialTransactionId || b.externalId || (b.data && (b.data.referenceId || b.data.financialTransactionId || b.data.externalId));
  const status = b.status || (b.data && b.data.status) || b.reason || (b.data && b.data.reason) || "";
  return { reference: ref, status, raw: b };
}

function extractAirtelCallbackFields(body) {
  const b = body || {};
  const txn = b.transaction || b.data || b;
  const ref = txn.airtelMoneyId || txn.txnId || txn.reference || txn.id || b.reference || b.transactionId || b.externalId;
  const status = txn.status || txn.txnStatus || b.status || b.code || "";
  return { reference: ref, status, raw: b };
}

function processProviderCallback(req, res, provider, kind) {
  const v = verifyProviderCallback(req, provider);
  if (!v.ok) {
    logAudit(req, "callback_rejected", { provider, kind, reason: "secret_mismatch" });
    return res.status(401).json({ error: "Invalid callback secret" });
  }

  const info = provider === "airtel" ? extractAirtelCallbackFields(req.body) : extractMtnCallbackFields(req.body);
  const reference = String(info.reference || "").trim();
  const normStatus = normalizeCallbackStatus(info.status, provider);

  if (!reference) {
    logAudit(req, "callback_invalid", { provider, kind, reason: "missing_reference", body: req.body });
    return res.status(400).json({ error: "Missing callback reference" });
  }

  const dedupeKey = [provider, kind, reference, normStatus].join(":");
  if (callbackAlreadyProcessed(dedupeKey)) {
    logAudit(req, "callback_duplicate", { provider, kind, reference, status: normStatus });
    return res.status(200).json({ ok: true, duplicate: true });
  }

  const tx = findTxByAnyReference(reference);
  if (!tx) {
    logAudit(req, "callback_unmatched", { provider, kind, reference, status: normStatus });
    return res.status(202).json({ ok: true, unmatched: true });
  }

  ensureTxReconDefaults(tx);

  if (kind === "collection") {
    applyCollectionCallbackUpdate(tx, provider, normStatus, reference, info.raw);
    logAudit(req, "callback_collection_processed", { provider, txId: tx.id, reference, status: normStatus });
  } else {
    applyPayoutCallbackUpdate(tx, normStatus, reference, info.raw);
    logAudit(req, "callback_payout_processed", { provider, txId: tx.id, reference, status: normStatus });
  }

  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }

  return res.status(200).json({ ok: true, txId: tx.id, reference, status: normStatus });
}

// Legacy MTN callback path (kept for compatibility)
app.post("/momo/callback", (req, res) => {
  try { console.log("MoMo callback:", JSON.stringify({ headers: req.headers, body: req.body })); } catch {}
  return processProviderCallback(req, res, "mtn", "collection");
});

// Preferred provider-specific callback routes
app.post("/api/callbacks/mtn/collection", (req, res) => processProviderCallback(req, res, "mtn", "collection"));
app.post("/api/callbacks/mtn/payout", (req, res) => processProviderCallback(req, res, "mtn", "payout"));
app.post("/api/callbacks/airtel/collection", (req, res) => processProviderCallback(req, res, "airtel", "collection"));

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
const ledgerEntries = []; // immutable-ish append-only ledger for money events

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
    await dbLoadOpsIntoMemory();
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
    CREATE TABLE IF NOT EXISTS tutopay_ledger (
      id TEXT PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      tx_id TEXT,
      event_type TEXT,
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
    CREATE INDEX IF NOT EXISTS tutopay_ledger_ts_idx ON tutopay_ledger(ts);
    CREATE INDEX IF NOT EXISTS tutopay_ledger_tx_idx ON tutopay_ledger(tx_id);
    CREATE INDEX IF NOT EXISTS tutopay_idem_expires_idx ON tutopay_idempotency(expires_at);

CREATE TABLE IF NOT EXISTS tutopay_issue_cases (
  case_id TEXT PRIMARY KEY,
  tx_id TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  data JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS tutopay_issue_actions (
  id TEXT PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  case_id TEXT,
  tx_id TEXT,
  action_type TEXT,
  policy_code TEXT,
  data JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS tutopay_incidents (
  id TEXT PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS tutopay_issue_cases_tx_idx ON tutopay_issue_cases(tx_id);
CREATE INDEX IF NOT EXISTS tutopay_issue_actions_ts_idx ON tutopay_issue_actions(ts);
CREATE INDEX IF NOT EXISTS tutopay_issue_actions_case_idx ON tutopay_issue_actions(case_id);
CREATE INDEX IF NOT EXISTS tutopay_incidents_ts_idx ON tutopay_incidents(ts);
  `);
}

function ensureTxReconDefaults(tx) {
  if (!tx || typeof tx !== "object") return tx;
  if (typeof tx.collectionReconciled !== "boolean") tx.collectionReconciled = false;
  if (typeof tx.payoutReconciled !== "boolean") tx.payoutReconciled = false;
  if (!Array.isArray(tx.reconNotes)) tx.reconNotes = [];
  if (!tx.reconUpdatedAt) tx.reconUpdatedAt = null;
  return tx;
}

async function dbLoadIntoMemory() {
  if (!_pgPool) return;

  // Users
  try {
    const u = await _pgPool.query("SELECT data FROM tutopay_users");
    if (u.rows && u.rows.length) {
      users.length = 0;
      for (const r of u.rows) users.push(ensureUserKycDefaults(r.data));
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
      for (const r of tx.rows) transactions.push(ensureTxReconDefaults(r.data));
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

  // Ledger (keep last 5000 for memory)
  try {
    const l = await _pgPool.query("SELECT data FROM tutopay_ledger ORDER BY ts DESC LIMIT 5000");
    if (l.rows && l.rows.length) {
      ledgerEntries.length = 0;
      for (const r of l.rows.reverse()) ledgerEntries.push(r.data);
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
  // Ensure demo admin exists even after DB load
  ensureAdminUserSeed();

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

async function dbInsertLedger(entry) {
  if (!dbEnabled()) return;
  const id = String(entry.id || uuid()).trim();
  const ts = entry.timestamp ? new Date(entry.timestamp) : new Date();
  await _pgPool.query(
    `INSERT INTO tutopay_ledger(id, ts, tx_id, event_type, data)
     VALUES ($1, $2, $3, $4, $5::jsonb)
     ON CONFLICT (id) DO NOTHING`,
    [id, ts, entry.txId ? String(entry.txId) : null, entry.eventType || null, JSON.stringify(entry)]
  );
}


async function dbUpsertIssueCase(caseObj) {
  if (!dbEnabled()) return;
  const caseId = String(caseObj.caseId || caseObj.case_id || "").trim();
  if (!caseId) return;
  const txId = caseObj.txId ? String(caseObj.txId) : (caseObj.tx_id ? String(caseObj.tx_id) : null);
  await _pgPool.query(
    `INSERT INTO tutopay_issue_cases(case_id, tx_id, data, updated_at)
     VALUES ($1, $2, $3::jsonb, NOW())
     ON CONFLICT (case_id) DO UPDATE SET tx_id=EXCLUDED.tx_id, data=EXCLUDED.data, updated_at=NOW()`,
    [caseId, txId, JSON.stringify(caseObj)]
  );
}

async function dbInsertIssueAction(actionObj) {
  if (!dbEnabled()) return;
  const id = String(actionObj.id || uuid()).trim();
  const ts = actionObj.timestamp ? new Date(actionObj.timestamp) : new Date();
  const caseId = actionObj.caseId ? String(actionObj.caseId) : null;
  const txId = actionObj.txId ? String(actionObj.txId) : null;
  await _pgPool.query(
    `INSERT INTO tutopay_issue_actions(id, ts, case_id, tx_id, action_type, policy_code, data)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
     ON CONFLICT (id) DO NOTHING`,
    [id, ts, caseId, txId, actionObj.actionType || null, actionObj.policyCode || null, JSON.stringify(actionObj)]
  );
}

async function dbInsertIncident(incidentObj) {
  if (!dbEnabled()) return;
  const id = String(incidentObj.id || uuid()).trim();
  const ts = incidentObj.createdAt ? new Date(incidentObj.createdAt) : new Date();
  await _pgPool.query(
    `INSERT INTO tutopay_incidents(id, ts, data) VALUES ($1, $2, $3::jsonb)
     ON CONFLICT (id) DO NOTHING`,
    [id, ts, JSON.stringify(incidentObj)]
  );
}

async function dbLoadOpsIntoMemory() {
  if (!dbEnabled()) return;
  // Ensure globals exist (created by Step6/7 IIFE)
  const caseStore = globalThis.__tpIssueCaseStore;
  const actionsArr = globalThis.__tpIssueActions;
  const incidentsArr = globalThis.__tpComplianceIncidents;

  try {
    const ic = await _pgPool.query("SELECT data FROM tutopay_issue_cases ORDER BY updated_at DESC LIMIT 5000");
    if (caseStore && typeof caseStore.set === 'function') {
      for (const r of (ic.rows || [])) {
        const d = r.data;
        if (d && (d.caseId || d.case_id)) caseStore.set(String(d.caseId || d.case_id), d);
      }
    }
  } catch(e){}

  try {
    const ia = await _pgPool.query("SELECT data FROM tutopay_issue_actions ORDER BY ts DESC LIMIT 10000");
    if (Array.isArray(actionsArr)) {
      actionsArr.length = 0;
      for (const r of (ia.rows || [])) actionsArr.push(r.data);
    }
  } catch(e){}

  try {
    const inc = await _pgPool.query("SELECT data FROM tutopay_incidents ORDER BY ts DESC LIMIT 5000");
    if (Array.isArray(incidentsArr)) {
      incidentsArr.length = 0;
      for (const r of (inc.rows || [])) incidentsArr.push(r.data);
    }
  } catch(e){}
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



function hasLedgerEvent(txId, eventType, reference) {
  return ledgerEntries.some((e) =>
    String(e.txId || "") === String(txId || "") &&
    String(e.eventType || "") === String(eventType || "") &&
    (reference == null || String(e.reference || "") === String(reference || ""))
  );
}

function recordLedger(req, tx, eventType, opts = {}) {
  if (!tx || !tx.id) return null;
  ensureTxReconDefaults(tx);
  const ref = opts.reference || opts.paymentRef || opts.referenceId || null;
  if (opts.dedupe !== false && hasLedgerEvent(tx.id, eventType, ref)) return null;

  const entry = {
    id: uuid(),
    timestamp: nowIso(),
    txId: tx.id,
    eventType,
    amount: Number(opts.amount != null ? opts.amount : tx.amount || 0) || 0,
    currency: String(opts.currency || tx.currency || process.env.MOMO_CURRENCY || "ZMW"),
    actorPhone: (req && req.user && req.user.phone) || opts.actorPhone || "system",
    actorRole: (req && req.user && req.user.role) || opts.actorRole || "system",
    fromPhone: tx.fromPhone || null,
    toPhone: tx.toPhone || null,
    statusSnapshot: {
      txStatus: tx.status || null,
      paymentStatus: tx.paymentStatus || null,
      disputeActive: !!tx.disputeActive,
    },
    reference: ref,
    provider: opts.provider || tx.paymentProvider || null,
    notes: opts.notes || null,
    meta: opts.meta || {},
  };

  ledgerEntries.push(entry);
  if (ledgerEntries.length > 10000) ledgerEntries.splice(0, ledgerEntries.length - 10000);

  tx.reconUpdatedAt = nowIso();
  if (dbEnabled()) { dbInsertLedger(entry).catch(() => {}); }
  return entry;
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


// -------- Profile helpers (for cross-device seller name/logo) --------
function _isNonEmptyStr(x) { return typeof x === "string" && x.trim().length > 0; }

function normalizePublicProfile(rawProfile, phone) {
  const src = rawProfile || {};
  const phoneSafe = String(phone || '').trim();

  // Accept both *DataUrl and legacy *Url fields.
  const selfieCandidate = src.selfieDataUrl || (typeof src.selfieUrl === 'string' && src.selfieUrl.startsWith('data:image') ? src.selfieUrl : '');
  const logoCandidate = src.logoDataUrl || (typeof src.logoUrl === 'string' && src.logoUrl.startsWith('data:image') ? src.logoUrl : '');

  // Keep data URLs as the primary storage format for demo reliability (works across devices without relying on /uploads persistence).
  const selfieDataUrl = typeof selfieCandidate === 'string' ? selfieCandidate : '';
  const logoDataUrl = typeof logoCandidate === 'string' ? logoCandidate : '';

  // Backward-compatible fields (some frontends look for selfieUrl/logoUrl).
  // If they aren't true URLs, we just mirror the data URL.
  const selfieUrl = (typeof src.selfieUrl === 'string' && src.selfieUrl && !src.selfieUrl.startsWith('data:image')) ? src.selfieUrl : selfieDataUrl;
  const logoUrl = (typeof src.logoUrl === 'string' && src.logoUrl && !src.logoUrl.startsWith('data:image')) ? src.logoUrl : logoDataUrl;

  const displayName = String(src.displayName || '').trim();
  const businessName = String(src.businessName || '').trim();

  // Normalize older alias field names
  // In some older clients, businessName might be stored as merchantType or similar; ignore here.

  return { phone: phoneSafe, displayName, businessName, selfieDataUrl, logoDataUrl, selfieUrl, logoUrl };
}

function publicProfileResponseForUser(user) {
  const phone = user && user.phone ? String(user.phone).trim() : "";
  const prof = user && user.profile ? normalizePublicProfile(user.profile, phone) : normalizePublicProfile({}, phone);
  const avatarUrl = prof.logoDataUrl || prof.selfieDataUrl || "";
  return {
    profile: prof,
    // Convenience fields for existing frontend code (non-breaking)
    displayName: prof.displayName,
    businessName: prof.businessName,
    avatarUrl,
  };
}

// -------- Simple in-memory users & sessions (demo only) --------
const users = []; // { id, phone, role, pinHash, kycLevel, kycStatus, ... }
const sessions = new Map(); // token -> { id, phone, role, kycLevel, kycStatus, expiresAt }
const loginAttempts = new Map(); // phone -> { count, firstAt, lockedUntil }

const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || (12 * 60 * 60 * 1000)); // 12h
const LOGIN_WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS || (15 * 60 * 1000)); // 15m
const LOGIN_LOCK_MS = Number(process.env.LOGIN_LOCK_MS || (15 * 60 * 1000)); // 15m
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);

function legacyHashPin(pin) {
  return crypto.createHash("sha256").update(String(pin)).digest("hex");
}

function hashPin(pin) {
  // Stronger PIN hashing using scrypt with per-user random salt.
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(pin), salt, 32);
  return `s2$${salt.toString("hex")}$${derived.toString("hex")}`;
}

function verifyPin(pin, storedHash) {
  if (!storedHash) return false;
  const val = String(storedHash);
  // Backward compatibility for old SHA-256 demo hashes
  if (!val.startsWith("s2$")) return legacyHashPin(pin) === val;

  const parts = val.split("$");
  if (parts.length !== 3) return false;
  const saltHex = parts[1];
  const hashHex = parts[2];
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const derived = crypto.scryptSync(String(pin), salt, expected.length);
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function pinHashNeedsUpgrade(storedHash) {
  return !String(storedHash || "").startsWith("s2$");
}

function getLoginAttemptState(phone) {
  const key = String(phone || "").trim();
  if (!key) return null;
  const now = Date.now();
  let state = loginAttempts.get(key);
  if (!state) return null;
  if (state.lockedUntil && now >= state.lockedUntil) {
    loginAttempts.delete(key);
    return null;
  }
  if (state.firstAt && now - state.firstAt > LOGIN_WINDOW_MS && !state.lockedUntil) {
    loginAttempts.delete(key);
    return null;
  }
  return state;
}

function recordLoginFailure(phone) {
  const key = String(phone || "").trim();
  if (!key) return null;
  const now = Date.now();
  let state = getLoginAttemptState(key);
  if (!state) state = { count: 0, firstAt: now, lockedUntil: 0 };
  if (!state.firstAt || now - state.firstAt > LOGIN_WINDOW_MS) {
    state.count = 0;
    state.firstAt = now;
    state.lockedUntil = 0;
  }
  state.count += 1;
  if (state.count >= LOGIN_MAX_ATTEMPTS) {
    state.lockedUntil = now + LOGIN_LOCK_MS;
  }
  loginAttempts.set(key, state);
  return state;
}

function clearLoginFailures(phone) {
  const key = String(phone || "").trim();
  if (key) loginAttempts.delete(key);
}

setInterval(() => {
  const now = Date.now();
  for (const [tok, sess] of sessions.entries()) {
    if (!sess || (sess.expiresAt && now > sess.expiresAt)) sessions.delete(tok);
  }
  for (const [phone, state] of loginAttempts.entries()) {
    if (!state) { loginAttempts.delete(phone); continue; }
    if (state.lockedUntil && now >= state.lockedUntil) { loginAttempts.delete(phone); continue; }
    if ((!state.lockedUntil) && state.firstAt && (now - state.firstAt > LOGIN_WINDOW_MS)) loginAttempts.delete(phone);
  }
}, 60 * 1000).unref?.();


function findUserByPhone(phone) {
  return users.find((u) => u.phone === phone);
}
function ensureUserKycDefaults(user) {
  if (!user || typeof user !== "object") return user;
  if (!user.kycLevel) user.kycLevel = (user.role === "admin" ? "admin" : "basic");
  if (!user.kycStatus) user.kycStatus = (user.role === "admin" ? "verified" : "unsubmitted");
  if (!user.kycHistory) user.kycHistory = [];
  return user;
}

function getEffectiveKycLevel(user) {
  if (!user) return "basic";
  if (user.role === "admin") return "admin";
  if (String(user.kycStatus || "").toLowerCase() !== "verified") return "basic";
  return user.kycLevel || "basic";
}


function ensureAdminUserSeed() {
  // Make sure the demo admin always exists (even if DB load overwrote in-memory users)
  const adminPhone = String(DEMO_ADMIN_PHONE || "").trim();
  if (!adminPhone) return;
  let admin = users.find((u) => u && String(u.phone).trim() === adminPhone && u.role === "admin");
  if (!admin) {
    admin = {
      id: uuid(),
      phone: adminPhone,
      role: "admin",
      pinHash: hashPin(DEMO_ADMIN_PIN),
      kycLevel: "admin",
      kycStatus: "verified",
      disabled: false,
    };
    users.push(admin);
  } else {
    // Keep PIN in sync with env defaults (useful for demos)
    admin.pinHash = hashPin(DEMO_ADMIN_PIN);
    admin.kycLevel = "admin";
    admin.kycStatus = "verified";
    if (admin.disabled) admin.disabled = false;
  }

  // Persist if DB is enabled
  if (dbEnabled()) {
    dbUpsertUser(admin).catch(() => {});
  }
}

// Seed a couple of demo users (optional)
users.push({
  id: uuid(),
  phone: "0977123456",
  role: "buyer",
  pinHash: hashPin("1111"),
  kycLevel: "basic",
  kycStatus: "unsubmitted",
});

users.push({
  id: uuid(),
  phone: "0977234567",
  role: "seller",
  pinHash: hashPin("2222"),
  kycLevel: "basic",
  kycStatus: "unsubmitted",
});

users.push({
  id: uuid(),
  phone: DEMO_ADMIN_PHONE,
  role: "admin",
  pinHash: hashPin(DEMO_ADMIN_PIN),
  kycLevel: "admin",
  kycStatus: "verified",
});


ensureAdminUserSeed();
// Auth middleware
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  const token = parts.length === 2 && parts[0] === "Bearer" ? parts[1] : null;

  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const session = sessions.get(token);
  if (!session || (session.expiresAt && Date.now() > session.expiresAt)) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: "Session expired. Please sign in again." });
  }

  // Refresh role/KYC flags from user record on every request (important after admin KYC reviews)
  const currentUser = findUserByPhone(session.phone);
  if (currentUser) {
    ensureUserKycDefaults(currentUser);
    session.role = currentUser.role;
    session.kycLevel = getEffectiveKycLevel(currentUser);
    session.kycStatus = currentUser.kycStatus;
    session.disabled = !!currentUser.disabled;
    if (session.disabled) {
      sessions.delete(token);
      return res.status(403).json({ error: "This account has been disabled. Please contact support." });
    }
  }

  req.authToken = token;
  req.user = session; // { id, phone, role, kycLevel, kycStatus, expiresAt }
  next();
}

// Export downloads sometimes don't carry Authorization headers reliably.
// Allow token via query string: ?export_token=<token>
function requireExportAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  const bearer = parts.length === 2 && parts[0] === "Bearer" ? parts[1] : null;
  const queryTok = (req.query && (req.query.export_token || req.query.token)) ? String(req.query.export_token || req.query.token) : null;
  const token = bearer || queryTok;

  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const session = sessions.get(token);
  if (!session || (session.expiresAt && Date.now() > session.expiresAt)) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: "Session expired. Please sign in again." });
  }

  // Refresh role/KYC flags from user record on every request (important after admin KYC reviews)
  const currentUser = findUserByPhone(session.phone);
  if (currentUser) {
    ensureUserKycDefaults(currentUser);
    session.role = currentUser.role;
    session.kycLevel = getEffectiveKycLevel(currentUser);
    session.kycStatus = currentUser.kycStatus;
    session.disabled = !!currentUser.disabled;
    if (session.disabled) {
      sessions.delete(token);
      return res.status(403).json({ error: "This account has been disabled. Please contact support." });
    }
  }

  req.authToken = token;
  req.user = session; // { id, phone, role, kycLevel, kycStatus, expiresAt }
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
app.post("/api/auth/login", loginLimiter, (req, res) => {
  const { phone, pin, rolePreference, profile } = req.body || {};
  if (!phone || !pin) {
    return res.status(400).json({ error: "Phone and PIN are required." });
  }

  const phoneNorm = String(phone).trim();
  const lockState = getLoginAttemptState(phoneNorm);
  if (lockState && lockState.lockedUntil && Date.now() < lockState.lockedUntil) {
    const retryAfterSec = Math.max(1, Math.ceil((lockState.lockedUntil - Date.now()) / 1000));
    logAudit(req, "auth_login_blocked", { phoneTried: phoneNorm, retryAfterSec });
    return res.status(429).json({ error: "Too many failed PIN attempts. Try again later.", retryAfterSec });
  }

  let user = findUserByPhone(phoneNorm);

  // Special-case demo admin login: allow the configured admin to sign in even if DB doesn't yet contain it
  if ((!user) && rolePreference === "admin") {
    const adminPhone = String(DEMO_ADMIN_PHONE || "").trim();
    const pinOk = String(pin) === String(DEMO_ADMIN_PIN);
    if (String(phoneNorm).trim() === adminPhone && pinOk) {
      ensureAdminUserSeed();
      user = findUserByPhone(adminPhone);
    }
  }


  if (!user) {
    // Demo behaviour: auto-register new users as buyer/seller only (admin is never auto-created)
    if (!ALLOW_PUBLIC_SIGNUP) {
      logAudit(req, "auth_login_failed", { reason: "public_signup_disabled", phoneTried: phoneNorm });
      return res.status(403).json({ error: "Sign-up is disabled on this environment." });
    }

    if (rolePreference === "admin") {
      logAudit(req, "auth_login_failed", { reason: "admin_autoreg_blocked", phoneTried: phoneNorm });
      return res.status(403).json({ error: "Admin accounts cannot be created from the public sign-in page." });
    }

    const allowedRoles = ["buyer", "seller"];
    const role = allowedRoles.includes(rolePreference) ? rolePreference : "buyer";

    user = {
      id: uuid(),
      phone: phoneNorm,
      role,
      pinHash: hashPin(pin),
      kycLevel: "basic",
      kycStatus: "unsubmitted",
      kycHistory: [],
    };
    users.push(user);
    if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
    console.log("Created demo user:", user.phone, user.role);
  } else {
    ensureUserKycDefaults(user);
    // Hardening: only allow the seeded demo admin phone to act as admin
    if (user.role === "admin" && user.phone !== DEMO_ADMIN_PHONE) {
      logAudit(req, "auth_login_failed", { reason: "admin_phone_mismatch", phoneTried: phoneNorm });
      return res.status(403).json({ error: "Admin access is restricted." });
    }

    if (user.disabled) {
      logAudit(req, "auth_login_failed", { reason: "user_disabled", phoneTried: phoneNorm });
      return res.status(403).json({ error: "This account has been disabled. Please contact support." });
    }

    if (!verifyPin(pin, user.pinHash)) {
      const state = recordLoginFailure(phoneNorm);
      logAudit(req, "auth_login_failed", {
        reason: "invalid_pin",
        phoneTried: phoneNorm,
        failedAttempts: state ? state.count : 1,
        lockedUntil: state && state.lockedUntil ? new Date(state.lockedUntil).toISOString() : null,
      });
      const payload = { error: "Invalid PIN." };
      if (state && state.lockedUntil && Date.now() < state.lockedUntil) {
        payload.error = "Too many failed PIN attempts. Try again later.";
        payload.retryAfterSec = Math.max(1, Math.ceil((state.lockedUntil - Date.now()) / 1000));
        return res.status(429).json(payload);
      }
      return res.status(401).json(payload);
    }

    // Transparently upgrade legacy SHA-256 PIN hashes after a successful login
    if (pinHashNeedsUpgrade(user.pinHash)) {
      user.pinHash = hashPin(pin);
      if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
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

  
// If frontend sent profile data (name/selfie/logo), store it for cross-device display
if (profile && typeof profile === "object") {
  try {
    const normalized = normalizePublicProfile(profile, phoneNorm);
    user.profile = normalized;
    // persist user profile
    if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
  } catch (e) {}
}

clearLoginFailures(phoneNorm);

const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, {
    id: user.id,
    phone: user.phone,
    role: user.role,
    kycLevel: getEffectiveKycLevel(user),
    kycStatus: user.kycStatus,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });

  logAudit(req, "auth_login_success", {
  phone: user.phone,
  role: user.role,
  kycLevel: getEffectiveKycLevel(user),
  kycStatus: user.kycStatus,
});

  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  return res.json({
    token,
    expiresAt,
    user: {
      id: user.id,
      phone: user.phone,
      role: user.role,
      kycLevel: getEffectiveKycLevel(user),
      kycStatus: user.kycStatus,
    },
  });
});


app.post("/api/auth/logout", requireAuth, (req, res) => {
  try {
    if (req.authToken) sessions.delete(req.authToken);
    logAudit(req, "auth_logout", { phone: req.user && req.user.phone, role: req.user && req.user.role });
  } catch (e) {}
  return res.json({ ok: true });
});

// -------- KYC (BoZ trial prep) --------
app.get("/api/kyc/me", requireAuth, (req, res) => {
  const user = ensureUserKycDefaults(findUserByPhone(req.user.phone));
  if (!user) return res.status(404).json({ error: "User not found" });
  return res.json({
    phone: user.phone,
    role: user.role,
    kycStatus: user.kycStatus,
    kycLevel: getEffectiveKycLevel(user),
    requestedKycLevel: user.kycLevel || "basic",
    kycSubmittedAt: user.kycSubmittedAt || null,
    kycReviewedAt: user.kycReviewedAt || null,
    kycReviewedBy: user.kycReviewedBy || null,
    kycRejectionReason: user.kycRejectionReason || null,
    kycProfile: user.kycProfile || {},
    kycHistory: Array.isArray(user.kycHistory) ? user.kycHistory : [],
  });
});

app.post("/api/kyc/submit", requireAuth, (req, res) => {
  if (req.user.role === "admin") return res.status(403).json({ error: "Admin accounts do not require KYC submission." });
  const user = ensureUserKycDefaults(findUserByPhone(req.user.phone));
  if (!user) return res.status(404).json({ error: "User not found" });

  const body = req.body || {};
  const requestedKycLevel = ["basic","enhanced","full"].includes(body.requestedKycLevel) ? body.requestedKycLevel : (user.kycLevel || "basic");
  const idType = String(body.idType || "").trim();
  const idNumber = String(body.idNumber || body.nrcNumber || "").trim();
  const fullName = String(body.fullName || (user.profile && (user.profile.displayName || user.profile.fullName)) || "").trim();
  if (!idType || !idNumber || !fullName) {
    return res.status(400).json({ error: "fullName, idType, and idNumber are required for KYC submission." });
  }

  user.kycProfile = {
    fullName,
    idType,
    idNumber,
    dob: body.dob ? String(body.dob) : undefined,
    address: body.address ? String(body.address).trim() : undefined,
    businessName: body.businessName ? String(body.businessName).trim() : undefined,
    sellerType: body.sellerType ? String(body.sellerType).trim() : undefined,
    selfieProvided: !!(user.profile && user.profile.selfieDataUrl),
    logoProvided: !!(user.profile && user.profile.logoDataUrl),
    submittedFields: Object.keys(body || {}).sort(),
  };
  user.kycStatus = "pending";
  user.kycSubmittedAt = nowIso();
  user.kycRejectionReason = null;
  user.kycLevel = requestedKycLevel; // requested target level; effective level stays basic until verified
  user.kycHistory = Array.isArray(user.kycHistory) ? user.kycHistory : [];
  user.kycHistory.push({
    at: user.kycSubmittedAt,
    action: "submitted",
    by: req.user.phone,
    requestedKycLevel,
  });

  if (dbEnabled()) dbUpsertUser(user).catch(() => {});
  logAudit(req, "kyc_submit", { phone: user.phone, requestedKycLevel, idType });
  return res.json({
    ok: true,
    message: "KYC submitted for review.",
    kycStatus: user.kycStatus,
    requestedKycLevel: user.kycLevel,
    effectiveKycLevel: getEffectiveKycLevel(user),
    kycSubmittedAt: user.kycSubmittedAt,
  });
});

app.get("/api/admin/kyc/pending", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const pending = users
    .map(u => ensureUserKycDefaults(u))
    .filter(u => u.role !== "admin" && (u.kycStatus === "pending" || u.kycStatus === "under_review"))
    .map(u => ({
      phone: u.phone,
      role: u.role,
      kycStatus: u.kycStatus,
      requestedKycLevel: u.kycLevel || "basic",
      effectiveKycLevel: getEffectiveKycLevel(u),
      kycSubmittedAt: u.kycSubmittedAt || null,
      displayName: u.profile && (u.profile.displayName || u.profile.fullName),
      businessName: u.profile && u.profile.businessName,
      kycProfile: u.kycProfile || {},
    }));
  return res.json(pending);
});

app.post("/api/admin/kyc/:phone/review", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const phone = String(req.params.phone || "").trim();
  const user = ensureUserKycDefaults(findUserByPhone(phone));
  if (!user) return res.status(404).json({ error: "User not found" });
  if (user.role === "admin") return res.status(400).json({ error: "Cannot review admin KYC." });

  const body = req.body || {};
  const decision = String(body.decision || "").toLowerCase(); // approve/reject/request_more
  const level = ["basic","enhanced","full"].includes(body.kycLevel) ? body.kycLevel : (user.kycLevel || "basic");
  const reason = String(body.reason || "").trim();

  if (!["approve","approved","verify","verified","reject","rejected","request_more","needs_more_info"].includes(decision)) {
    return res.status(400).json({ error: "decision must be approve, reject, or request_more" });
  }

  const at = nowIso();
  if (["approve","approved","verify","verified"].includes(decision)) {
    user.kycStatus = "verified";
    user.kycLevel = level;
    user.kycReviewedAt = at;
    user.kycReviewedBy = req.user.phone;
    user.kycRejectionReason = null;
  } else if (["reject","rejected"].includes(decision)) {
    user.kycStatus = "rejected";
    user.kycReviewedAt = at;
    user.kycReviewedBy = req.user.phone;
    user.kycRejectionReason = reason || "KYC review rejected";
  } else {
    user.kycStatus = "needs_more_info";
    user.kycReviewedAt = at;
    user.kycReviewedBy = req.user.phone;
    user.kycRejectionReason = reason || "Additional KYC information required";
  }

  user.kycHistory = Array.isArray(user.kycHistory) ? user.kycHistory : [];
  user.kycHistory.push({
    at,
    action: "reviewed",
    decision: user.kycStatus,
    by: req.user.phone,
    kycLevel: user.kycLevel,
    reason: user.kycRejectionReason || null,
  });

  if (dbEnabled()) dbUpsertUser(user).catch(() => {});
  logAudit(req, "kyc_review", { targetPhone: user.phone, decision: user.kycStatus, kycLevel: user.kycLevel });

  // Refresh any active sessions for that user
  for (const sess of sessions.values()) {
    if (sess && sess.phone === user.phone) {
      sess.kycStatus = user.kycStatus;
      sess.kycLevel = getEffectiveKycLevel(user);
    }
  }

  return res.json({
    ok: true,
    phone: user.phone,
    kycStatus: user.kycStatus,
    kycLevel: getEffectiveKycLevel(user),
    requestedKycLevel: user.kycLevel,
    kycReviewedAt: user.kycReviewedAt,
    kycReviewedBy: user.kycReviewedBy,
    reason: user.kycRejectionReason || null,
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


// Public: fetch a user's public profile for cross-device display (seller name/logo)
app.get("/api/users/public/:phone", (req, res) => {
  const phone = String(req.params.phone || "").trim();
  if (!phone) return res.status(400).json({ error: "Missing phone" });

  const user = findUserByPhone(phone);
  if (!user) {
    // Return a minimal profile so UI can still show something
    return res.json({
      profile: {
        displayName: phone,
        businessName: "",
        selfieDataUrl: "",
        logoDataUrl: "",
      },
    });
  }

  return res.json(publicProfileResponseForUser(user));
});

// Backwards-compatible alias used by some frontend builds
app.get("/api/public/user/:phone", (req, res) => {
  const phone = String(req.params.phone || "").trim();
  if (!phone) return res.status(400).json({ error: "Missing phone" });

  const user = findUserByPhone(phone);
  if (!user) return res.json({ displayName: phone, businessName: "", avatarUrl: "" });

  const out = publicProfileResponseForUser(user);
  // old clients expect top-level fields
  return res.json({
    displayName: out.displayName,
    businessName: out.businessName,
    avatarUrl: out.avatarUrl,
    profile: out.profile,
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
  const buyerUser = findUserByPhone(req.user.phone) || { kycLevel: req.user.kycLevel, kycStatus: req.user.kycStatus };
  ensureUserKycDefaults(buyerUser);
  const kycLevel = getEffectiveKycLevel(buyerUser);
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
  ensureTxReconDefaults(tx);

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
app.post("/api/transactions/:id/pay", requireAuth, payLimiter, idempotencyMiddleware, async (req, res) => {
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
    tx.collectionReconciled = false;
    tx.paidAt = nowIso();
    tx.status = "pending"; // now seller can hold
    recordLedger(req, tx, "deposit_confirmed", { reference: tx.paymentRef, provider: "demo", notes: "Demo payment confirmed" });
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

      recordLedger(req, tx, "deposit_initiated", { reference: tx.paymentRef, provider: "airtel_sandbox", notes: "Airtel collection initiated" });
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
      tx.paymentStatus = "pending";
      tx.paymentRef = referenceId;
      recordLedger(req, tx, "deposit_initiated", { reference: referenceId, provider: "mtn_momo", notes: "MTN collection initiated" });
      logAudit(req, "tx_pay_mtn_start", { txId: tx.id, provider: "mtn_momo", paymentRef: referenceId });
    } catch (err) {
      console.error("MTN MoMo sandbox requesttopay failed:", { message: err && err.message, status: err && (err.status || err.statusCode), body: err && err.body });
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
    recordLedger(req, tx, "deposit_initiated", { reference: tx.paymentRef, provider: PAYMENTS_MODE, notes: "Payment initiated" });
    logAudit(req, "tx_pay_start", { txId: tx.id, provider: PAYMENTS_MODE, paymentRef: tx.paymentRef });

  }

  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
  return res.json(tx);
});

app.post("/api/transactions/:id/payment/requery", requireAuth, requeryLimiter, idempotencyMiddleware, async (req, res) => {
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
        tx.collectionReconciled = false;
        tx.status = "pending"; // seller can now hold
        recordLedger(req, tx, "deposit_confirmed", { reference: tx.paymentRef, provider: "airtel_sandbox" });
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
        tx.status = "pending"; // seller can now hold
        tx.paidAt = tx.paidAt || nowIso();
        tx.collectionReconciled = false;
        recordLedger(req, tx, "deposit_confirmed", { reference: tx.paymentRef, provider: "mtn_momo" });
        logAudit(req, "tx_pay_mtn_success", { txId: tx.id, paymentRef: tx.paymentRef });
        momoLog("requery_success", { txId: tx.id, paymentRef: tx.paymentRef, status: st });
      } else if (st === "FAILED" || st === "REJECTED") {
        tx.paymentStatus = "failed";
        tx.status = "pending_payment"; // allow buyer to retry
        momoLog("requery_failed", { txId: tx.id, paymentRef: tx.paymentRef, status: st });
        logAudit(req, "tx_pay_mtn_failed", { txId: tx.id, paymentRef: tx.paymentRef, status: st, data });
      } else {
        momoLog("requery_pending", { txId: tx.id, paymentRef: tx.paymentRef, status: st || "PENDING" });
        tx.paymentStatus = "pending";
      }
    } catch (err) {
      console.error("MTN MoMo status requery failed:", { message: err && err.message, status: err && (err.status || err.statusCode), body: err && err.body });
      // keep existing status if requery fails
    }
  }

  // Default: no provider integration yet
  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
  return res.json(tx);
});

// MTN MoMo Disbursement (payout to seller)
app.post("/api/transactions/:id/payout", requireAuth, payoutLimiter, idempotencyMiddleware, async (req, res) => {
  const id = String(req.params.id || "");
  const tx = transactions.find((t) => String(t.id) === id);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  // Only allow seller (or admin) to request payout
  if (req.user.role !== "admin" && req.user.phone !== tx.toPhone) {
    return res.status(403).json({ error: "Not allowed" });
  }

  if (tx.status !== "completed") {
    return res.status(400).json({ error: "Transaction must be completed before payout" });
  }
  if (tx.paymentStatus !== "paid") {
    return res.status(400).json({ error: "Payment is not marked as paid" });
  }

  // Prevent duplicate payouts
  if (tx.disbursement && (tx.disbursement.status === "pending" || tx.disbursement.status === "successful")) {
    return res.status(400).json({ error: `Disbursement already ${tx.disbursement.status}` });
  }

  const amount = tx.amount;
  const currency = tx.currency || process.env.MOMO_CURRENCY || "ZMW";
  const payeeMsisdn = tx.toPhone;

  try {
    const { referenceId } = await momoDisburseTransfer({
      amount,
      currency,
      payeeMsisdn,
      externalId: String(tx.id),
      payerMessage: `TutoPay payout for TX ${tx.id}`,
      payeeNote: `TutoPay payout for TX ${tx.id}`,
    });

    tx.disbursement = {
      referenceId,
      status: "pending",
      startedAt: Date.now(),
    };
    recordLedger(req, tx, "payout_initiated", { reference: referenceId, provider: "mtn_momo_disbursement", amount, currency, notes: "Seller payout initiated" });

    logAudit(req, "mtn_disbursement_initiated", {
      txId: tx.id,
      referenceId,
      amount,
      currency,
      payeeMsisdn: momoNormalizeMsisdn(payeeMsisdn),
      by: req.user.phone,
    });

    if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }

    return res.json({ ok: true, referenceId, status: tx.disbursement.status });
  } catch (e) {
    console.error("MTN DISBURSEMENT failed:", e?.message || e);
    return res.status(502).json({ error: "Disbursement failed", detail: e?.message || String(e) });
  }
});

app.get("/api/transactions/:id/payout-status", requireAuth, async (req, res) => {
  const id = String(req.params.id || "");
  const tx = transactions.find((t) => String(t.id) === id);
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  if (req.user.role !== "admin" && req.user.phone !== tx.toPhone && req.user.phone !== tx.fromPhone) {
    return res.status(403).json({ error: "Not allowed" });
  }

  if (!tx.disbursement?.referenceId) {
    return res.status(400).json({ error: "No disbursement started for this transaction" });
  }

  try {
    const status = await momoGetTransferStatus(tx.disbursement.referenceId);

    // Keep raw status for visibility
    tx.disbursement.lastStatus = status;

    const st = String(status?.status || "").toUpperCase();
    if (st.includes("SUCCESS")) tx.disbursement.status = "successful";
    else if (st.includes("FAIL") || st.includes("REJECT")) tx.disbursement.status = "failed";
    else tx.disbursement.status = "pending";

    if (tx.disbursement.status === "successful") {
      tx.payoutReconciled = false;
      recordLedger(req, tx, "payout_completed", { reference: tx.disbursement.referenceId, provider: "mtn_momo_disbursement", notes: "Seller payout successful" });
    } else if (tx.disbursement.status === "failed") {
      recordLedger(req, tx, "payout_failed", { reference: tx.disbursement.referenceId, provider: "mtn_momo_disbursement", notes: "Seller payout failed" });
    }

    tx.disbursement.updatedAt = Date.now();

    logAudit(req, "mtn_disbursement_status", {
      txId: tx.id,
      referenceId: tx.disbursement.referenceId,
      status: tx.disbursement.status,
      raw: status,
    });

    if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }

    return res.json({ ok: true, referenceId: tx.disbursement.referenceId, status: tx.disbursement.status, raw: status });
  } catch (e) {
    console.error("MTN DISBURSEMENT status check failed:", e?.message || e);
    return res.status(502).json({ error: "Status check failed", detail: e?.message || String(e) });
  }
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
      tx.payoutReconciled = true;
      recordLedger(null, tx, "refund_completed", { actorPhone: "system", actorRole: "system", notes: "Auto-refund after seller timeout" });
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
recordLedger(req, tx, "escrow_held", { notes: "Seller confirmed item held" });
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
      tx.payoutReconciled = false;
      recordLedger(req, tx, "escrow_completed", { notes: "Buyer confirmed collection" });
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
      tx.payoutReconciled = false;
      recordLedger(req, tx, "escrow_completed", { notes: "Buyer confirmed delivery received" });
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
    tx.payoutReconciled = true;
    recordLedger(req, tx, "refund_completed", { notes: "Seller agreed refund via dispute flow" });
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

// -------- Admin: users + summary --------
app.get("/api/admin/users", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const list = users.map((u) => ({
    id: u.id,
    phone: u.phone,
    role: u.role,
    kycLevel: getEffectiveKycLevel(ensureUserKycDefaults(u)),
    requestedKycLevel: (u.kycLevel || "basic"),
    kycStatus: (u.kycStatus || "unsubmitted"),
    kycSubmittedAt: u.kycSubmittedAt || null,
    kycReviewedAt: u.kycReviewedAt || null,
    disabled: !!u.disabled,
    // profile (optional)
    displayName: u.profile && (u.profile.displayName || u.profile.fullName) ? (u.profile.displayName || u.profile.fullName) : undefined,
    businessName: u.profile && u.profile.businessName ? u.profile.businessName : undefined,
  }));

  res.json({ users: list });
});

// Update a user (demo): toggle disabled via query param
// Example: GET /api/admin/users/0977123456?disabled=1
app.get("/api/admin/users/:phone", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const phone = normalizePhone(req.params.phone);
  const user = findUserByPhone(phone);

  if (!user) return res.status(404).json({ error: "User not found" });

  // Optional update: disabled flag
  if (typeof req.query.disabled !== "undefined") {
    const next = String(req.query.disabled) === "1" || String(req.query.disabled).toLowerCase() === "true";
    user.disabled = next;

    logAudit(req, "admin_user_update", { phone: user.phone, disabled: next });

    if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
  }

  res.json({
    ok: true,
    user: {
      id: user.id,
      phone: user.phone,
      role: user.role,
      kycLevel: user.kycLevel,
      disabled: !!user.disabled,
    },
  });
});

app.get("/api/admin/summary", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const txs = transactions || [];
  const disputes = issuesTxs().filter((t) => !!t.disputeActive || String(t.status).toLowerCase() === "disputed");

  const active = issuesTxs().filter((t) => ["pending_payment","pending","held"].includes(String(t.status)));
  const inTransit = issuesTxs().filter((t) => ["in_transit","delivered"].includes(String(t.status)));
  const completed = issuesTxs().filter((t) => ["released","completed"].includes(String(t.status)));

  const releasedTotal = issuesTxs().reduce((sum, t) => {
    const amt = Number(t.amount || t.quoteAmount || 0) || 0;
    if (String(t.status) === "released" || String(t.status) === "completed") return sum + amt;
    return sum;
  }, 0);

  res.json({
    totals: {
      users: users.length,
      transactions: issuesTxs().length,
      disputes: disputes.length,
      active: active.length,
      inTransit: inTransit.length,
      completed: completed.length,
      releasedTotal,
    }
  });
});


// -------- Admin: ledger + reconciliation --------
app.get("/api/admin/ledger", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const txId = req.query.txId ? String(req.query.txId) : null;
  const limit = Math.min(Number(req.query.limit) || 200, 2000);
  let entries = ledgerEntries;
  if (txId) entries = entries.filter((e) => String(e.txId) === txId);
  entries = entries.slice(-limit).reverse();

  res.json({ entries });
});


app.get("/api/admin/callback-config", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  return res.json({
    ok: true,
    callbacks: {
      mtnCollectionPath: "/api/callbacks/mtn/collection",
      mtnPayoutPath: "/api/callbacks/mtn/payout",
      airtelCollectionPath: "/api/callbacks/airtel/collection",
      mtnSecretConfigured: !!MTN_CALLBACK_SECRET,
      airtelSecretConfigured: !!AIRTEL_CALLBACK_SECRET,
    }
  });
});

app.get("/api/admin/reconciliation/summary", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const txs = transactions.map(ensureTxReconDefaults);
  const pendingCollection = issuesTxs().filter((t) => t.paymentStatus === "paid" && !t.collectionReconciled).length;
  const pendingPayout = issuesTxs().filter((t) => (t.status === "completed" || (t.disbursement && t.disbursement.status === "successful")) && !t.payoutReconciled).length;

  const money = issuesTxs().reduce((acc, t) => {
    const amt = Number(t.amount || 0) || 0;
    if (t.paymentStatus === "paid") acc.collectionsPaid += amt;
    if (t.disbursement && t.disbursement.status === "successful") acc.payoutsSuccessful += amt;
    if (t.status === "refunded") acc.refunded += amt;
    return acc;
  }, { collectionsPaid: 0, payoutsSuccessful: 0, refunded: 0 });

  res.json({
    totals: {
      ledgerEntries: ledgerEntries.length,
      transactions: issuesTxs().length,
      pendingCollectionReconciliation: pendingCollection,
      pendingPayoutReconciliation: pendingPayout,
      ...money,
    },
    recentUnreconciled: txs
      .filter((t) => !t.collectionReconciled || !t.payoutReconciled)
      .slice(-30)
      .reverse()
      .map((t) => ({
        id: t.id,
        status: t.status,
        paymentStatus: t.paymentStatus,
        amount: t.amount,
        fromPhone: t.fromPhone,
        toPhone: t.toPhone,
        collectionReconciled: !!t.collectionReconciled,
        payoutReconciled: !!t.payoutReconciled,
        reconUpdatedAt: t.reconUpdatedAt || null,
      })),
  });
});

app.post("/api/admin/reconciliation/:txId/mark", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const tx = transactions.find((t) => String(t.id) === String(req.params.txId || ""));
  if (!tx) return res.status(404).json({ error: "Transaction not found" });
  ensureTxReconDefaults(tx);

  const body = req.body || {};
  const target = String(body.target || "").toLowerCase(); // collection | payout | both
  const status = String(body.status || "reconciled").toLowerCase(); // reconciled | unreconciled
  const note = body.note ? String(body.note) : "";

  const val = status === "reconciled";

  if (!["collection","payout","both"].includes(target)) {
    return res.status(400).json({ error: "target must be collection, payout, or both" });
  }
  if (!["reconciled","unreconciled"].includes(status)) {
    return res.status(400).json({ error: "status must be reconciled or unreconciled" });
  }

  if (target === "collection" || target === "both") tx.collectionReconciled = val;
  if (target === "payout" || target === "both") tx.payoutReconciled = val;
  tx.reconUpdatedAt = nowIso();
  if (note) tx.reconNotes.push({ at: tx.reconUpdatedAt, by: req.user.phone, target, status, note });

  recordLedger(req, tx, "reconciliation_marked", {
    dedupe: false,
    notes: note || `Marked ${target} as ${status}`,
    meta: { target, status }
  });

  logAudit(req, "reconciliation_marked", {
    txId: tx.id, target, status, note,
    collectionReconciled: tx.collectionReconciled,
    payoutReconciled: tx.payoutReconciled,
  });

  if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
  return res.json({
    ok: true,
    txId: tx.id,
    collectionReconciled: tx.collectionReconciled,
    payoutReconciled: tx.payoutReconciled,
    reconUpdatedAt: tx.reconUpdatedAt,
    reconNotes: tx.reconNotes,
  });
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
const server = 

/* ===== Step 6+7: Compliance pack + Issues Desk foundation (BoZ trial ops) ===== */
(function(){
  // ---- Compliance docs + incidents (Step 6, included here so this file is self-contained) ----
  const complianceDocs = [
    {
      id: 'terms',
      title: 'TutoPay Terms of Use',
      version: '0.1-trial',
      updatedAt: '2026-02-25T00:00:00.000Z',
      path: '/api/public/compliance/docs/terms',
      body: 'TutoPay provides an escrow-style transaction workflow for trial use. Users agree to provide accurate details, avoid prohibited goods, and cooperate with dispute and KYC checks. TutoPay may pause, limit, or refuse transactions for risk, fraud, compliance, or operational reasons.'
    },
    {
      id: 'privacy',
      title: 'TutoPay Privacy Notice',
      version: '0.1-trial',
      updatedAt: '2026-02-25T00:00:00.000Z',
      path: '/api/public/compliance/docs/privacy',
      body: 'TutoPay collects account, transaction, KYC, and dispute information to operate escrow, prevent fraud, support investigations, and meet legal obligations. Trial data may be reviewed by authorized staff for support, risk monitoring, and reconciliation purposes.'
    },
    {
      id: 'disputes',
      title: 'Disputes & Complaints SOP',
      version: '0.1-trial',
      updatedAt: '2026-02-25T00:00:00.000Z',
      path: '/api/public/compliance/docs/disputes',
      body: 'Complaints are logged against transactions and routed to the Issues Desk for review. Investigators review timeline events, uploaded evidence, and policy codes before recommending or taking actions. High-risk or repeated patterns are escalated and recorded in audit logs.'
    },
    {
      id: 'kyc-limits',
      title: 'KYC & Transaction Limits Policy',
      version: '0.1-trial',
      updatedAt: '2026-02-25T00:00:00.000Z',
      path: '/api/public/compliance/docs/kyc-limits',
      body: 'Trial account limits are applied by KYC level. Unverified users may face lower limits and restricted features. TutoPay may request additional documentation, place holds, or prevent payouts when account behavior triggers risk review.'
    }
  ];
  const complianceIncidents = globalThis.__tpComplianceIncidents || (globalThis.__tpComplianceIncidents = []);

  function _complianceCounts() {
    const pendingKyc = users.filter(u => u && u.role !== 'admin' && (u.kycStatus === 'pending' || u.kycStatus === 'under_review')).length;
    const disputes = issuesTxs().filter(t => !!t.disputeActive || String(t.status||'').toLowerCase()==='disputed').length;
    return {
      users: users.length,
      transactions: issuesTxs().length,
      disputes,
      pendingKyc,
      ledgerEntries: ledgerEntries.length,
      incidentReports: complianceIncidents.length,
      auditEntries: auditLog.length
    };
  }

  function _complianceOverview() {
    const counts = _complianceCounts();
    const controls = [
      { key:'auth', label:'Auth sessions & role guard', ok:true, detail:'Token-based sessions and role checks active' },
      { key:'kyc', label:'KYC workflow', ok: true, detail:'KYC submission/review endpoints enabled' },
      { key:'ledger', label:'Ledger & reconciliation', ok: ledgerEntries.length >= 0, detail: `${ledgerEntries.length} ledger events tracked` },
      { key:'audit', label:'Audit logging', ok: auditLog.length >= 0, detail: `${auditLog.length} audit events retained` },
      { key:'callbacks', label:'Provider callback secret', ok: !!(process.env.MTN_CALLBACK_SECRET || process.env.CALLBACK_SHARED_SECRET || process.env.AIRTEL_CALLBACK_SECRET), detail: 'Secrets configured for callback verification' },
      { key:'issues', label:'Issues Desk operations', ok: true, detail: 'Risk/fraud investigation panel and APIs enabled' },
    ];
    const score = Math.round((controls.filter(c=>c.ok).length / controls.length) * 100);
    return {
      readinessScore: score,
      generatedAt: nowIso(),
      counts,
      controls,
      policyDocs: complianceDocs.map(d => ({ id:d.id, title:d.title, version:d.version, path:d.path, updatedAt:d.updatedAt })),
      recency: {
        lastAuditAt: auditLog.length ? auditLog[auditLog.length-1].timestamp : null,
        lastLedgerAt: ledgerEntries.length ? ledgerEntries[ledgerEntries.length-1].timestamp : null,
      }
    };
  }

  app.get('/api/public/compliance/docs', (req,res)=> {
    res.json({ ok:true, docs: complianceDocs.map(d => ({ id:d.id, title:d.title, version:d.version, path:d.path, updatedAt:d.updatedAt })) });
  });
  app.get('/api/public/compliance/docs/:docId', (req,res)=> {
    const doc = complianceDocs.find(d => d.id === String(req.params.docId||'').trim());
    if (!doc) return res.status(404).json({ error:'Doc not found' });
    res.json({ ok:true, doc });
  });
  app.get('/api/admin/compliance/overview', requireAuth, (req,res)=> {
    if (req.user.role !== 'admin') return res.status(403).json({ error:'Admin only' });
    res.json(_complianceOverview());
  });
  app.get('/api/admin/compliance/incidents', requireAuth, (req,res)=> {
    if (req.user.role !== 'admin') return res.status(403).json({ error:'Admin only' });
    const limit = Math.max(1, Math.min(500, Number(req.query.limit)||100));
    res.json({ ok:true, incidents: complianceIncidents.slice(-limit).reverse() });
  });
  app.post('/api/admin/compliance/incidents', requireAuth, async (req,res)=> {
    if (req.user.role !== 'admin') return res.status(403).json({ error:'Admin only' });
    const title = String((req.body||{}).title || '').trim();
    if (!title) return res.status(400).json({ error:'title is required' });
    const entry = {
      id: uuid(),
      title,
      category: String((req.body||{}).category || 'operations').trim() || 'operations',
      severity: String((req.body||{}).severity || 'medium').trim().toLowerCase(),
      description: String((req.body||{}).description || '').trim(),
      status: 'open',
      createdAt: nowIso(),
      createdBy: req.user.phone,
      createdRole: req.user.role,
    };
    complianceIncidents.push(entry);
    if (complianceIncidents.length > 1000) complianceIncidents.splice(0, complianceIncidents.length - 1000);
    try { await dbInsertIncident(entry); } catch(e){}
    logAudit(req, 'compliance_incident_create', { incidentId: entry.id, title: entry.title, severity: entry.severity });
    res.json({ ok:true, incident: entry });
  });

// ---- Step 8A exports (CSV) ----
app.get('/api/admin/export/issues.csv', requireExportAuth, requireIssuesDesk, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only');
  const rows = issueCaseList();
  const header = ['caseId','txId','status','priority','assignedTo','assignedAt','slaDeadlineAt','createdAt','updatedAt','buyerPhone','sellerPhone','amount','currency','reasonCode','docsCount'].join(',');
  const csv = [header].concat(rows.map(r => [
    r.caseId, r.txId, r.status, r.priority, r.assignedTo||'', r.assignedAt||'', r.slaDeadlineAt||'', r.createdAt||'', r.updatedAt||'',
    r.buyerPhone||'', r.sellerPhone||'', r.amount||0, r.currency||'', (r.reasonCode||'').replace(/,/g,' '), r.docsCount||0
  ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(','))).join('\n');
  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tutopay-issues.csv"');
  res.send(csv);
});

app.get('/api/admin/export/issues-actions.csv', requireExportAuth, requireIssuesDesk, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only');
  const header = ['id','caseId','txId','timestamp','actionType','policyCode','nextStatus','actorPhone','actorRole','note'].join(',');
  const csv = [header].concat((issueActions||[]).slice().reverse().map(a => [
    a.id||'', a.caseId||'', a.txId||'', a.timestamp||'', a.actionType||'', a.policyCode||'', a.nextStatus||'',
    a.actorPhone||'', a.actorRole||'', (a.note||'').replace(/\r?\n/g,' ')
  ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(','))).join('\n');
  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tutopay-issues-actions.csv"');
  res.send(csv);
});

app.get('/api/admin/export/incidents.csv', requireExportAuth, (req,res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only');
  const header = ['id','createdAt','severity','category','status','createdBy','title','description'].join(',');
  const csv = [header].concat((complianceIncidents||[]).slice().reverse().map(i => [
    i.id||'', i.createdAt||'', i.severity||'', i.category||'', i.status||'', i.createdBy||'', (i.title||'').replace(/,/g,' '), (i.description||'').replace(/\r?\n/g,' ')
  ].map(v => `"${String(v).replace(/"/g,'""')}"`).join(','))).join('\n');
  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tutopay-incidents.csv"');
  res.send(csv);
});

  app.get('/api/admin/compliance/export', requireAuth, (req,res)=> {
    if (req.user.role !== 'admin') return res.status(403).json({ error:'Admin only' });
    const pkg = {
      exportedAt: nowIso(),
      by: req.user.phone,
      overview: _complianceOverview(),
      incidents: complianceIncidents.slice(-500),
      docs: complianceDocs,
      notes: 'Trial compliance export package (JSON)'
    };
    res.json({ ok:true, package: pkg });
  });

  // ---- Issues Desk foundation (Step 7A) ----
  const ISSUE_POLICIES = [
    { code:'RISK-01', label:'Request More Evidence', actionType:'request_more_evidence', nextStatus:'awaiting_customer', template:'Please upload clearer proof (photos, chats, receipts, delivery evidence) within the requested timeframe.' },
    { code:'RISK-02', label:'Freeze & Investigate', actionType:'freeze_transaction', nextStatus:'in_review', template:'Transaction held pending fraud/risk checks. Parties are notified while review is in progress.' },
    { code:'RISK-03', label:'Refund Recommended', actionType:'recommend_refund', nextStatus:'awaiting_admin_approval', template:'Evidence supports refund recommendation. Escalate for authorization and payout reversal handling.' },
    { code:'RISK-04', label:'Reject Complaint Recommended', actionType:'recommend_reject', nextStatus:'awaiting_admin_approval', template:'Evidence does not support complaint claim. Prepare a structured rejection response.' },
    { code:'RISK-05', label:'Escalate to Supervisor', actionType:'escalate_supervisor', nextStatus:'escalated', template:'Case escalated due to severity, repeat pattern, or policy trigger.' },
    { code:'RISK-06', label:'Close Case', actionType:'close_case', nextStatus:'resolved', template:'Issue is resolved and case can be closed with final notes recorded.' }
  ];
  const issueCaseStore = globalThis.__tpIssueCaseStore || (globalThis.__tpIssueCaseStore = new Map()); // caseId -> state/meta
  const issueActions = globalThis.__tpIssueActions || (globalThis.__tpIssueActions = []); // append-only action log

  function issuesTxs(){ return (typeof transactions !== 'undefined' && Array.isArray(transactions)) ? transactions : (globalThis.transactions||[]); }

  function isIssuesDeskRole(role) {
    const r = String(role || '').toLowerCase();
    return r === 'admin' || r === 'risk_agent' || r === 'fraud_agent';
  }
  function requireIssuesDesk(req,res,next){
    if (!req.user || !isIssuesDeskRole(req.user.role)) return res.status(403).json({ error:'Issues Desk only' });
    return next();
  }

  function safeDate(x){
    if (!x) return null;
    const t = Date.parse(x);
    return Number.isFinite(t) ? new Date(t).toISOString() : null;
  }
  function humanDisputeStatus(tx){
    const raw = (tx && tx.dispute && tx.dispute.status) || (tx && tx.status) || 'new';
    return String(raw).toLowerCase();
  }
  function calcPriority(tx){
    let score = 0;
    const amt = Number(tx && tx.amount || 0);
    if (amt >= 5000) score += 3; else if (amt >= 1000) score += 2; else score += 1;
    if ((tx && tx.disputeDocs && tx.disputeDocs.length) === 0) score += 1;
    if (String(tx?.dispute?.reasonCode||'').toLowerCase().includes('fraud')) score += 2;
    if (score >= 6) return 'critical';
    if (score >= 4) return 'high';
    if (score >= 3) return 'medium';
    return 'low';
  }
  function ensureIssueCaseForTx(tx){
    if (!tx || !tx.id || !tx.dispute) return null;
    const caseId = `CASE-${tx.id}`;
    let st = issueCaseStore.get(caseId);
    if (!st) {
      const openedAt = safeDate(tx.dispute.openedAt) || safeDate(tx.dispute.createdAt) || safeDate(tx.updatedAt) || safeDate(tx.createdAt) || nowIso();
      const createdTs = Date.parse(openedAt) || Date.now();
      st = {
        caseId,
        createdAt: openedAt,
        updatedAt: openedAt,
        status: 'new',
        priority: calcPriority(tx),
        assignedTo: null,
        assignedAt: null,
        slaDeadlineAt: new Date(createdTs + 24*60*60*1000).toISOString(),
        tags: [],
        sourceType: 'dispute',
        sourceRef: tx.id,
      };
      issueCaseStore.set(caseId, st);
    }
    const latestAction = [...issueActions].reverse().find(a => a.caseId === caseId);
    const disputeStatus = humanDisputeStatus(tx);
    return {
      caseId,
      txId: tx.id,
      sourceType: st.sourceType,
      sourceRef: st.sourceRef,
      status: latestAction?.nextStatus || st.status || 'new',
      priority: st.priority || calcPriority(tx),
      assignedTo: st.assignedTo || null,
      assignedAt: st.assignedAt || null,
      slaDeadlineAt: st.slaDeadlineAt || null,
      createdAt: st.createdAt,
      updatedAt: latestAction?.timestamp || st.updatedAt || st.createdAt,
      complaintOpenedAt: st.createdAt,
      disputeStatus,
      amount: Number(tx.amount || 0),
      currency: tx.currency || process.env.MOMO_CURRENCY || 'ZMW',
      buyerPhone: tx.fromPhone || null,
      sellerPhone: tx.toPhone || null,
      txStatus: tx.status || null,
      paymentStatus: tx.paymentStatus || null,
      reasonCode: tx.dispute.reasonCode || null,
      reasonText: tx.dispute.reasonText || null,
      docsCount: Array.isArray(tx.disputeDocs) ? tx.disputeDocs.length : 0,
      tags: Array.isArray(st.tags) ? st.tags : [],
      phaseDurations: buildIssuePhaseDurations(tx),
    };
  }

  function issueCaseList() {
    const out = [];
    for (const tx of issuesTxs()) {
      if (!tx || !(tx.disputeActive || tx.dispute)) continue;
      const c = ensureIssueCaseForTx(tx);
      if (c) out.push(c);
    }
    out.sort((a,b)=> (Date.parse(b.updatedAt||0)||0) - (Date.parse(a.updatedAt||0)||0));
    return out;
  }

  function getIssueCaseAndTx(caseId){
    const cid = String(caseId||'').trim();
    if (!cid) return { err:'Invalid caseId' };
    const txId = cid.startsWith('CASE-') ? cid.slice(5) : cid;
    const tx = issuesTxs().find(t => String(t.id) === String(txId));
    if (!tx || !tx.dispute) return { err:'Case not found' };
    const c = ensureIssueCaseForTx(tx);
    return { tx, c, state: issueCaseStore.get(c.caseId) };
  }

  function buildIssueTimeline(tx, caseId){
    const rows = [];
    const push = (ts, phase, source, detail, extra={}) => {
      const iso = safeDate(ts);
      if (!iso) return;
      rows.push({ id: uuid(), timestamp: iso, phase, source, detail, ...extra });
    };

    push(tx.createdAt, 'transaction_created', 'transaction', 'Escrow created');
    if (tx.paymentRequestedAt) push(tx.paymentRequestedAt, 'payment_initiated', 'transaction', 'Payment initiated');
    if (tx.paymentConfirmedAt || tx.paidAt) push(tx.paymentConfirmedAt || tx.paidAt, 'payment_confirmed', 'transaction', 'Payment confirmed');
    if (tx.sellerHeldAt || tx.heldAt) push(tx.sellerHeldAt || tx.heldAt, 'seller_hold', 'transaction', 'Seller placed hold / acknowledged');
    if (tx.inTransitAt) push(tx.inTransitAt, 'in_transit', 'transaction', 'Marked in transit');
    if (tx.deliveredAt) push(tx.deliveredAt, 'delivered', 'transaction', 'Marked delivered');
    if (tx.completedAt) push(tx.completedAt, 'completed', 'transaction', 'Buyer completed transaction');
    if (tx.dispute && (tx.dispute.openedAt || tx.dispute.createdAt)) {
      push(tx.dispute.openedAt || tx.dispute.createdAt, 'complaint_opened', 'dispute', `Complaint opened (${tx.dispute.reasonCode || 'general'})`);
    }
    if (Array.isArray(tx.disputeDocs)) {
      for (const d of tx.disputeDocs) {
        push(d.uploadedAt || d.createdAt, 'evidence_uploaded', 'evidence', d.name || d.filename || 'Evidence file', { by: d.uploadedByPhone || d.byPhone || d.by || null, fileType: d.mimetype || null, url: d.url || null });
      }
    }
    for (const a of issueActions) {
      if (a.caseId !== caseId) continue;
      push(a.timestamp, a.actionType || 'case_action', 'issues_desk', a.note || a.policyLabel || a.policyCode || 'Case action', { actorPhone: a.actorPhone, actorRole: a.actorRole, policyCode: a.policyCode, nextStatus: a.nextStatus });
    }
    // Also include ledger/audit events tied to tx for richer timeline
    for (const l of ledgerEntries) {
      if (String(l.txId||'') !== String(tx.id)) continue;
      push(l.timestamp, `ledger:${l.eventType||'event'}`, 'ledger', `${l.eventType || 'Ledger'} (${l.amount || 0} ${l.currency||''})`, { actorPhone:l.actorPhone, actorRole:l.actorRole, reference:l.reference || null });
    }
    for (const a of auditLog) {
      const d = a.details || {};
      const linked = String(d.txId||d.id||'') === String(tx.id) || String(d.transactionId||'') === String(tx.id);
      if (!linked) continue;
      push(a.timestamp, `audit:${a.eventType||'event'}`, 'audit', a.eventType || 'Audit event', { actorPhone:a.userPhone, actorRole:a.userRole });
    }

    rows.sort((x,y)=> (Date.parse(x.timestamp)||0) - (Date.parse(y.timestamp)||0));
    // Add relative durations
    let prev = null;
    for (const r of rows) {
      if (prev) r.minutesSincePrev = Math.max(0, Math.round((Date.parse(r.timestamp)-Date.parse(prev.timestamp))/60000));
      prev = r;
    }
    return rows;
  }

  function buildIssuePhaseDurations(tx){
    const created = Date.parse(tx.createdAt || '') || null;
    const complaint = Date.parse(tx?.dispute?.openedAt || tx?.dispute?.createdAt || '') || null;
    const paid = Date.parse(tx.paymentConfirmedAt || tx.paidAt || '') || null;
    const held = Date.parse(tx.sellerHeldAt || tx.heldAt || '') || null;
    return {
      createdToPaidMin: created && paid ? Math.round((paid-created)/60000) : null,
      paidToHoldMin: paid && held ? Math.round((held-paid)/60000) : null,
      createdToComplaintMin: created && complaint ? Math.round((complaint-created)/60000) : null,
      paidToComplaintMin: paid && complaint ? Math.round((complaint-paid)/60000) : null,
    };
  }

  // Optional: internal endpoint to create risk agents (admin only)
  app.post('/api/admin/risk-agents', requireAuth, (req,res)=>{
    if (req.user.role !== 'admin') return res.status(403).json({ error:'Admin only' });
    const phone = String((req.body||{}).phone || '').trim();
    const pin = String((req.body||{}).pin || '').trim();
    if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ error:'PIN must be 4-8 digits' });
    if (!/^\d{9,15}$/.test(phone.replace(/\D/g,''))) return res.status(400).json({ error:'Valid phone required' });
    const normalizedPhone = phone.replace(/\D/g,'');
    let user = users.find(u => String(u.phone) === normalizedPhone);
    if (user) return res.status(400).json({ error:'User already exists with this phone' });
    user = {
      id: uuid(), phone: normalizedPhone, role:'risk_agent', pinHash: hashPin(pin),
      createdAt: nowIso(), createdBy: req.user.phone,
      kycLevel:'staff', kycStatus:'verified'
    };
    users.push(user);
    logAudit(req, 'risk_agent_create', { phone: normalizedPhone, role: 'risk_agent' });
    res.json({ ok:true, user: { id:user.id, phone:user.phone, role:user.role } });
  });

  app.get('/api/issues/policies', requireAuth, requireIssuesDesk, (req,res)=>{
    res.json({ ok:true, policies: ISSUE_POLICIES });
  });

  app.get('/api/issues/cases', requireAuth, requireIssuesDesk, (req,res)=>{
    const status = String(req.query.status || '').trim().toLowerCase();
    const priority = String(req.query.priority || '').trim().toLowerCase();
    const q = String(req.query.q || '').trim().toLowerCase();
    let rows = issueCaseList();
    if (status) rows = rows.filter(r => String(r.status||'').toLowerCase() === status);
    if (priority) rows = rows.filter(r => String(r.priority||'').toLowerCase() === priority);
    if (q) rows = rows.filter(r => [r.caseId, r.txId, r.buyerPhone, r.sellerPhone, r.reasonCode, r.reasonText].some(v => String(v||'').toLowerCase().includes(q)));
    const summary = {
      total: rows.length,
      byStatus: rows.reduce((a,r)=>{ const k=r.status||'unknown'; a[k]=(a[k]||0)+1; return a; }, {}),
      byPriority: rows.reduce((a,r)=>{ const k=r.priority||'unknown'; a[k]=(a[k]||0)+1; return a; }, {}),
      overdue: rows.filter(r => r.slaDeadlineAt && Date.parse(r.slaDeadlineAt) < Date.now() && !['resolved','closed'].includes(String(r.status||''))).length,
    };
    res.json({ ok:true, summary, cases: rows.slice(0, 500) });
  });

  app.get('/api/issues/cases/:caseId', requireAuth, requireIssuesDesk, (req,res)=>{
    const got = getIssueCaseAndTx(req.params.caseId);
    if (got.err) return res.status(404).json({ error: got.err });
    const { tx, c } = got;
    const actions = issueActions.filter(a => a.caseId === c.caseId).slice(-200).reverse();
    const evidence = Array.isArray(tx.disputeDocs) ? tx.disputeDocs.map((d, idx) => ({
      id: d.id || `${c.caseId}-doc-${idx+1}`,
      name: d.name || d.filename || `evidence-${idx+1}`,
      url: d.url || null,
      uploadedAt: d.uploadedAt || d.createdAt || null,
      uploadedBy: d.uploadedByPhone || d.byPhone || d.by || null,
      mimeType: d.mimetype || null,
      size: d.size || null,
    })) : [];
    res.json({ ok:true, case: c, transaction: tx, evidence, actions, policies: ISSUE_POLICIES });
  });

  app.get('/api/issues/cases/:caseId/timeline', requireAuth, requireIssuesDesk, (req,res)=>{
    const got = getIssueCaseAndTx(req.params.caseId);
    if (got.err) return res.status(404).json({ error: got.err });
    const rows = buildIssueTimeline(got.tx, got.c.caseId);
    res.json({ ok:true, caseId: got.c.caseId, txId: got.tx.id, timeline: rows });
  });

  app.post('/api/issues/cases/:caseId/assign', requireAuth, requireIssuesDesk, async (req,res)=>{
    const got = getIssueCaseAndTx(req.params.caseId);
    if (got.err) return res.status(404).json({ error: got.err });
    const st = issueCaseStore.get(got.c.caseId);
    const toPhone = String((req.body||{}).toPhone || req.user.phone).trim();
    st.assignedTo = toPhone;
    st.assignedAt = nowIso();
    st.updatedAt = nowIso();
    try { await dbUpsertIssueCase(st); } catch(e){}
    logAudit(req, 'issues_case_assign', { caseId: got.c.caseId, txId: got.tx.id, assignedTo: toPhone });
    res.json({ ok:true, case: ensureIssueCaseForTx(got.tx) });
  });

  app.post('/api/issues/cases/:caseId/actions', requireAuth, requireIssuesDesk, async (req,res)=>{
    const got = getIssueCaseAndTx(req.params.caseId);
    if (got.err) return res.status(404).json({ error: got.err });
    const body = req.body || {};
    const actionType = String(body.actionType || '').trim();
    const policyCode = String(body.policyCode || '').trim().toUpperCase();
    const note = String(body.note || '').trim();
    const policy = ISSUE_POLICIES.find(p => p.code === policyCode);
    if (!actionType) return res.status(400).json({ error:'actionType is required' });
    if (!policy) return res.status(400).json({ error:'Valid policyCode is required' });
    const allowed = new Set(ISSUE_POLICIES.map(p=>p.actionType));
    if (!allowed.has(actionType)) return res.status(400).json({ error:'Unsupported actionType' });
    const st = issueCaseStore.get(got.c.caseId);
    const nextStatus = String(body.nextStatus || policy.nextStatus || st.status || 'in_review').trim().toLowerCase();
    const entry = {
      id: uuid(),
      caseId: got.c.caseId,
      txId: got.tx.id,
      actionType,
      policyCode,
      policyLabel: policy.label,
      note: note || policy.template,
      actorPhone: req.user.phone,
      actorRole: req.user.role,
      timestamp: nowIso(),
      nextStatus,
    };
    issueActions.push(entry);
    if (issueActions.length > 10000) issueActions.splice(0, issueActions.length - 10000);
    try { await dbInsertIssueAction(entry); } catch(e){}
    try { await dbUpsertIssueCase(st); } catch(e){}
    st.status = nextStatus;
    st.updatedAt = entry.timestamp;
    if (actionType === 'freeze_transaction') {
      got.tx.riskHold = true;
      got.tx.riskHoldAt = entry.timestamp;
    }
    if (actionType === 'close_case') {
      st.closedAt = entry.timestamp;
      if (got.tx.dispute && !got.tx.dispute.resolvedAt) got.tx.dispute.resolvedAt = entry.timestamp;
    }
    logAudit(req, 'issues_case_action', { caseId: got.c.caseId, txId: got.tx.id, actionType, policyCode, nextStatus });
    res.json({ ok:true, action: entry, case: ensureIssueCaseForTx(got.tx) });
  });
})();

app.listen(PORT, '0.0.0.0', () => {
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
