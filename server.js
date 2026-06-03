

/* === Accounting roles (global) === */
function isAccountingRole(role) {
  const r = String(role || "").toLowerCase();
  return r === "admin" || r === "accounts_agent" || r === "accounts" || r === "finance_agent";
}
function isIssuesDeskRoleGlobal(role) {
  const r = String(role || "").toLowerCase();
  return r === "admin" || r === "risk_agent" || r === "fraud_agent";
}
function isComplianceRole(role) {
  const r = String(role || "").toLowerCase();
  return r === "admin" || r === "compliance_agent" || r === "compliance_officer";
}
function isInternalStaffRole(role) {
  const r = String(role || "").toLowerCase();
  return isIssuesDeskRoleGlobal(r) || isAccountingRole(r) || isComplianceRole(r);
}
function isPublicRole(role) {
  const r = String(role || "").toLowerCase();
  return r === "buyer" || r === "seller";
}
// server.js
// TutoPay backend — non-custodial transaction workflow + catalogue + requests + disputes + partner-rail payment callbacks

const express = require("express");
const cors = require("cors");
const { v4: uuid } = require("uuid");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const crypto = require("crypto");

// ===== Partner Demo v1 operating mode =====
// APP_STAGE options used by this file: local, partner_demo, pilot, production.
// partner_demo is intentionally polished for PSP/BoZ/investor demonstrations while
// still avoiding any claim that TutoPay itself holds or moves customer funds.
const APP_ENV = String(process.env.APP_ENV || process.env.NODE_ENV || "").toLowerCase();
const APP_STAGE = String(process.env.APP_STAGE || process.env.TUTOPAY_STAGE || "partner_demo").toLowerCase();
const IS_PARTNER_DEMO = ["partner_demo", "partner-demo", "pilot"].includes(APP_STAGE);
const PLATFORM_NOTICE_TEXT = process.env.PLATFORM_NOTICE_TEXT || (
  IS_PARTNER_DEMO
    ? "Controlled partner demo: TutoPay manages workflow, evidence, confirmations, disputes and records. Customer funds must be processed, settled, refunded or reversed by licensed PSP/mobile-money/bank rails."
    : "TutoPay manages transaction workflow and records. Customer funds are processed by licensed payment partners, not held by TutoPay."
);

// Public self-signup remains available for buyer/seller onboarding unless explicitly turned off.
const DEFAULT_PUBLIC_SIGNUP = "true";
const ALLOW_PUBLIC_SIGNUP = String(process.env.ALLOW_PUBLIC_SIGNUP || DEFAULT_PUBLIC_SIGNUP).toLowerCase() !== "false";

// Demo/test flags. Keep demo wording available for internal testing, but do not make it the default public posture.
const DEMO_MODE = String(process.env.DEMO_MODE || "false").toLowerCase() === "true";
const DEMO_BANNER_TEXT = process.env.DEMO_BANNER_TEXT || "Internal test environment: no real funds are moved.";

// Staff/admin seeding: use explicit env values for partner demos instead of hard-coded public credentials.
const SEED_DEMO_USERS = String(process.env.SEED_DEMO_USERS || (APP_STAGE === "local" ? "true" : "false")).toLowerCase() === "true";
const SEED_STAFF_ADMIN = String(process.env.SEED_STAFF_ADMIN || (process.env.DEMO_ADMIN_PHONE && process.env.DEMO_ADMIN_PIN ? "true" : "false")).toLowerCase() === "true";
const DEMO_ADMIN_PHONE = process.env.DEMO_ADMIN_PHONE || (APP_STAGE === "local" ? "0770100100" : "");
const DEMO_ADMIN_PIN = process.env.DEMO_ADMIN_PIN || (APP_STAGE === "local" ? "4567" : "");

const app = express();
const PORT = process.env.PORT || 4000;
const STRICT_DB_MODE = String(process.env.STRICT_DB_MODE || ((APP_ENV === "production") ? "true" : "false")).toLowerCase() === "true";
const DB_INIT_RETRIES = Math.max(1, Number(process.env.DB_INIT_RETRIES || 10));
const DB_INIT_RETRY_DELAY_MS = Math.max(500, Number(process.env.DB_INIT_RETRY_DELAY_MS || 3000));


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

app.get('/ready', (req, res) => {
  if (dbReady) {
    return res.status(200).json({ ok: true, ready: true, time: new Date().toISOString() });
  }
  return res.status(dbInitError ? 500 : 503).json({ ok: false, ready: false, status: dbInitError ? 'DB init failed' : 'Server starting' });
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

// Public operating-mode headers for partner/demo transparency.
app.use((req, res, next) => {
  res.set("X-App-Stage", APP_STAGE);
  res.set("X-Non-Custodial", "true");
  res.set("X-Funds-Handled-By", "licensed_partner");
  if (IS_PARTNER_DEMO) res.set("X-Partner-Demo", "true");
  if (DEMO_MODE) {
    res.set("X-Demo-Mode", "true");
    res.set("X-Demo-Banner", DEMO_BANNER_TEXT);
  }
  next();
});

// Lightweight config endpoint for the frontend disclosure bar.
app.get("/api/config", (req, res) => {
  res.json({
    appStage: APP_STAGE,
    partnerDemoMode: IS_PARTNER_DEMO,
    demoMode: DEMO_MODE,
    bannerText: DEMO_MODE ? DEMO_BANNER_TEXT : PLATFORM_NOTICE_TEXT,
    platformNoticeText: PLATFORM_NOTICE_TEXT,
    allowPublicSignup: ALLOW_PUBLIC_SIGNUP,
    nonCustodial: true,
    fundsHandledBy: "licensed_partner",
    moneyMovementBy: "licensed_partner",
    tutoPayRole: "workflow_evidence_disputes_records",
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

function markPartnerProcessing(tx, patch) {
  if (!tx || typeof tx !== "object") return tx;
  tx.partnerProcessing = Object.assign({
    nonCustodial: true,
    fundsCustodian: "licensed_partner",
    paymentExecutionBy: "licensed_partner",
    settlementBy: "licensed_partner",
    refundBy: "licensed_partner",
    reversalBy: "licensed_partner",
  }, tx.partnerProcessing || {}, patch || {});
  return tx;
}

function applyCollectionCallbackUpdate(tx, provider, normStatus, reference, rawBody) {
  markPartnerProcessing(tx, {
    provider: provider === "airtel" ? "airtel_sandbox" : "mtn_momo",
    collectionStatus: normStatus,
    lastCollectionReference: reference,
    lastCollectionCallbackAt: nowIso(),
  });
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
  markPartnerProcessing(tx, {
    payoutStatus: normStatus,
    lastPayoutReference: reference,
    lastPayoutCallbackAt: nowIso(),
  });
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
  const referenceId = uuid();

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

// ===== Item image helpers (Cloudinary-first when configured; local /uploads fallback otherwise) =====
function extFromMime(mime) {
  if (!mime) return "png";
  if (mime.includes("jpeg")) return "jpg";
  if (mime.includes("png")) return "png";
  if (mime.includes("webp")) return "webp";
  if (mime.includes("gif")) return "gif";
  return "png";
}

function cloudinaryConfigured() {
  return !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
}

function normalizeCloudinaryFolder(folder) {
  return String(folder || "tutopay/catalogue")
    .replace(/\\+/g, "/")
    .replace(/^\/+|\/+$/g, "")
    .replace(/[^a-zA-Z0-9/_-]+/g, "-") || "tutopay/catalogue";
}

function cloudinarySignature(params, apiSecret) {
  const toSign = Object.keys(params)
    .filter((k) => params[k] !== undefined && params[k] !== null && params[k] !== "")
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("&");
  return crypto.createHash("sha1").update(toSign + apiSecret).digest("hex");
}

async function uploadDataUrlToCloudinary(dataUrl, opts = {}) {
  if (typeof dataUrl !== "string") return "";
  if (!dataUrl.startsWith("data:")) return dataUrl;
  if (!cloudinaryConfigured()) return "";

  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  const folder = normalizeCloudinaryFolder(opts.folder || "tutopay/catalogue");
  const timestamp = Math.floor(Date.now() / 1000);
  const publicId = `${String(opts.prefix || "item")}-${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  const paramsToSign = { folder, public_id: publicId, timestamp };
  const signature = cloudinarySignature(paramsToSign, apiSecret);

  const form = new FormData();
  form.append("file", dataUrl);
  form.append("api_key", apiKey);
  form.append("timestamp", String(timestamp));
  form.append("folder", folder);
  form.append("public_id", publicId);
  form.append("signature", signature);

  const resp = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, {
    method: "POST",
    body: form,
  });

  let payload = null;
  try { payload = await resp.json(); } catch (e) {}
  if (!resp.ok || !payload || !payload.secure_url) {
    const msg = payload && payload.error && payload.error.message ? payload.error.message : `Cloudinary upload failed (${resp.status})`;
    throw new Error(msg);
  }
  return payload.secure_url;
}

async function uploadLocalFileToCloudinary(filePath, opts = {}) {
  if (!filePath || !cloudinaryConfigured()) return null;
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  const folder = normalizeCloudinaryFolder(opts.folder || "tutopay/evidence");
  const timestamp = Math.floor(Date.now() / 1000);
  const publicId = `${String(opts.prefix || "file")}-${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  const paramsToSign = { folder, public_id: publicId, resource_type: "auto", timestamp };
  const signature = cloudinarySignature(paramsToSign, apiSecret);

  const fileBuf = fs.readFileSync(filePath);
  const mimeType = String(opts.mimetype || "application/octet-stream");
  const form = new FormData();
  form.append("file", new Blob([fileBuf], { type: mimeType }), String(opts.filename || path.basename(filePath)));
  form.append("api_key", apiKey);
  form.append("timestamp", String(timestamp));
  form.append("folder", folder);
  form.append("public_id", publicId);
  form.append("resource_type", "auto");
  form.append("signature", signature);

  const resp = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/auto/upload`, {
    method: "POST",
    body: form,
  });
  let payload = null;
  try { payload = await resp.json(); } catch (e) {}
  if (!resp.ok || !payload || !payload.secure_url) {
    const msg = payload && payload.error && payload.error.message ? payload.error.message : `Cloudinary file upload failed (${resp.status})`;
    throw new Error(msg);
  }
  return {
    secureUrl: payload.secure_url,
    publicId: payload.public_id || publicId,
    resourceType: payload.resource_type || "auto",
    bytes: payload.bytes || opts.size || null,
    format: payload.format || null,
    originalFilename: payload.original_filename || null,
  };
}

async function persistKycDataUrl(dataUrl, opts = {}) {
  if (typeof dataUrl !== "string" || !dataUrl) return "";
  if (!dataUrl.startsWith("data:")) return dataUrl;
  return await persistImageDataUrl(dataUrl, {
    folder: opts.folder || "tutopay/kyc",
    prefix: opts.prefix || "kyc",
  });
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

async function persistImageDataUrl(dataUrl, opts = {}) {
  if (typeof dataUrl !== "string") return "";
  if (!dataUrl.startsWith("data:")) return dataUrl;
  if (cloudinaryConfigured()) {
    try {
      return await uploadDataUrlToCloudinary(dataUrl, opts);
    } catch (err) {
      console.error("[cloudinary] upload failed, falling back to local uploads:", err && err.message ? err.message : err);
    }
  }
  return saveDataUrlToUploads(dataUrl, String(opts.prefix || "item"));
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

// -------- KYC TIERS & LIMITS (controlled partner-demo defaults) --------
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function dbInit() {
  if (!HAS_DATABASE_URL) {
    const err = new Error("DATABASE_URL not set");
    dbInitError = err;
    console.error("[DB] DATABASE_URL not set.");
    if (STRICT_DB_MODE) throw err;
    console.warn("[DB] Continuing in memory-only mode because STRICT_DB_MODE=false.");
    return false;
  }

  let Pool;
  try {
    ({ Pool } = require("pg"));
  } catch (e) {
    dbInitError = e;
    console.error("[DB] pg module not installed. Run: npm i pg.");
    if (STRICT_DB_MODE) throw e;
    console.warn("[DB] Continuing in memory-only mode because STRICT_DB_MODE=false.");
    return false;
  }

  let lastErr = null;
  for (let attempt = 1; attempt <= DB_INIT_RETRIES; attempt++) {
    try {
      if (_pgPool) {
        try { await _pgPool.end(); } catch (_) {}
        _pgPool = null;
      }

      _pgPool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        max: 5,
      });

      await _pgPool.query("SELECT 1 as ok");
      await dbEnsureSchema();
      await dbLoadIntoMemory();
      await dbLoadOpsIntoMemory();
      _dbReady = true;
      dbInitError = null;
      console.log(`[DB] Connected + schema ready. attempt=${attempt}/${DB_INIT_RETRIES}`);
      return true;
    } catch (e) {
      lastErr = e;
      dbInitError = e;
      _dbReady = false;
      if (_pgPool) {
        try { await _pgPool.end(); } catch (_) {}
      }
      _pgPool = null;
      console.error(`[DB] Init attempt ${attempt}/${DB_INIT_RETRIES} failed: ${e && e.message ? e.message : e}`);
      if (attempt < DB_INIT_RETRIES) {
        await sleep(DB_INIT_RETRY_DELAY_MS * attempt);
      }
    }
  }

  console.error("[DB] Failed to init Postgres after retries.");
  if (STRICT_DB_MODE) throw lastErr || new Error("Postgres init failed");
  console.warn("[DB] Continuing in memory-only mode because STRICT_DB_MODE=false.");
  return false;
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

    CREATE TABLE IF NOT EXISTS tutopay_sessions (
      token TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      expires_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_tutopay_sessions_expires ON tutopay_sessions(expires_at);
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
  // Ensure optional bootstrap admin exists only when explicitly enabled.
  if (SEED_STAFF_ADMIN) ensureAdminUserSeed();

}


async function dbUpsertSession(token, sessionObj) {
  if (!_pgPool) return;
  const expiresAtIso = sessionObj && sessionObj.expiresAt ? new Date(sessionObj.expiresAt).toISOString() : null;
  await _pgPool.query(
    `INSERT INTO tutopay_sessions (token, data, expires_at, updated_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (token) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at, updated_at = NOW()`,
    [String(token), sessionObj, expiresAtIso]
  );
}

async function dbGetSession(token) {
  if (!_pgPool) return null;
  const r = await _pgPool.query(`SELECT token, data, expires_at FROM tutopay_sessions WHERE token = $1 LIMIT 1`, [String(token)]);
  if (!r.rows || !r.rows.length) return null;
  const row = r.rows[0];
  const data = row.data || null;
  if (!data) return null;
  // normalize expiresAt for runtime checks
  if (row.expires_at) {
    try { data.expiresAt = new Date(row.expires_at).getTime(); } catch(e){}
  }
  return data;
}

async function dbDeleteSession(token) {
  if (!_pgPool) return;
  await _pgPool.query(`DELETE FROM tutopay_sessions WHERE token = $1`, [String(token)]);
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


function ensureKycThreadDefaults(user) {
  if (!user || typeof user !== "object") return user;
  if (!Array.isArray(user.kycThread)) user.kycThread = [];
  return user;
}

function kycAttachmentEntriesFromProfile(profile) {
  const p = profile && typeof profile === "object" ? profile : {};
  const specs = [
    ["idFrontUrl", "ID Front"],
    ["idBackUrl", "ID Back"],
    ["passportUrl", "Passport"],
    ["selfieUrl", "Selfie"],
    ["proofOfAddressUrl", "Proof of Address"],
    ["businessCertUrl", "Business Certificate"],
  ];
  return specs
    .map(([key, label]) => {
      const url = typeof p[key] === "string" ? p[key].trim() : "";
      return url ? { key, label, url } : null;
    })
    .filter(Boolean);
}

function sanitizeKycThread(thread) {
  return (Array.isArray(thread) ? thread : []).map((m) => ({
    id: m && m.id ? String(m.id) : uuid(),
    at: m && m.at ? String(m.at) : nowIso(),
    byRole: m && m.byRole ? String(m.byRole) : "user",
    byPhone: m && m.byPhone ? String(m.byPhone) : "",
    message: m && m.message ? String(m.message) : "",
    attachments: Array.isArray(m && m.attachments) ? m.attachments.filter(Boolean) : [],
    statusAfter: m && m.statusAfter ? String(m.statusAfter) : null,
  }));
}

function pushKycThreadMessage(user, msg) {
  ensureKycThreadDefaults(user);
  const clean = sanitizeKycThread([msg])[0];
  user.kycThread.push(clean);
  if (user.kycThread.length > 100) user.kycThread.splice(0, user.kycThread.length - 100);
  return clean;
}

function getEffectiveKycLevel(user) {
  if (!user) return "basic";
  if (user.role === "admin") return "admin";
  if (String(user.kycStatus || "").toLowerCase() !== "verified") return "basic";
  return user.kycLevel || "basic";
}


function ensureAdminUserSeed() {
  // Optional staff/admin bootstrap for controlled environments only.
  const adminPhone = String(DEMO_ADMIN_PHONE || "").trim();
  if (!SEED_STAFF_ADMIN || !adminPhone || !DEMO_ADMIN_PIN) return;
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
    // Keep PIN in sync only with explicit environment bootstrap values.
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

// Optional seeded accounts are disabled by default in Partner Demo v1.
if (SEED_DEMO_USERS) {
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
}

if (SEED_STAFF_ADMIN) ensureAdminUserSeed();
// Auth middleware
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const parts = auth.split(" ");
  let token = parts.length === 2 && parts[0] === "Bearer" ? parts[1] : null;
  // Some browser download flows cannot attach Authorization headers reliably.
  // For CSV exports we also allow token via query string: ?export_token=...
  if (!token) {
    const q = req.query || {};
    token = (q.export_token || q.token || null);
  }

  
  // If running multiple instances, the in-memory session map may not have the token.
  // Fallback to Postgres-backed sessions for consistency across instances.
  if (token && !sessions.has(token) && dbEnabled()) {
    try {
      const s = await dbGetSession(token);
      if (s) sessions.set(token, s);
    } catch (e) {
      // ignore DB lookup errors; will fail auth below
    }
  }

if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const session = sessions.get(token);
  if (!session || (session.expiresAt && Date.now() > session.expiresAt)) {
    if (token) { sessions.delete(token); if (dbEnabled()) { dbDeleteSession(token).catch(()=>{}); } }
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

// -------- Auth (phone + PIN) --------
app.post("/api/auth/login", loginLimiter, (req, res) => {
  const { phone, pin, rolePreference, profile } = req.body || {};
  const pilotInviteCode = String(((req.body || {}).pilotInviteCode || (profile && profile.pilotInviteCode) || "")).trim().toUpperCase();
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

  // Optional bootstrap admin login: enabled only when explicit env values are present.
  if ((!user) && rolePreference === "admin" && SEED_STAFF_ADMIN) {
    const adminPhone = String(DEMO_ADMIN_PHONE || "").trim();
    const pinOk = String(pin) === String(DEMO_ADMIN_PIN);
    if (String(phoneNorm).trim() === adminPhone && pinOk) {
      ensureAdminUserSeed();
      user = findUserByPhone(adminPhone);
    }
  }


  if (!user) {
    const wantedRole = String(rolePreference || "").trim().toLowerCase();
    if (isInternalStaffRole(wantedRole) || wantedRole === "admin") {
      logAudit(req, "auth_login_failed", { reason: "staff_autoreg_blocked", phoneTried: phoneNorm, rolePreference: wantedRole });
      return res.status(403).json({ error: "Staff accounts cannot be created from the public sign-in page." });
    }

    // Controlled onboarding: auto-register new public users as buyer/seller only.
    if (!ALLOW_PUBLIC_SIGNUP) {
      logAudit(req, "auth_login_failed", { reason: "public_signup_disabled", phoneTried: phoneNorm });
      return res.status(403).json({ error: "Sign-up is disabled on this environment." });
    }

    const allowedRoles = ["buyer", "seller"];
    const role = allowedRoles.includes(wantedRole) ? wantedRole : "buyer";

    let pilotSignupResult = null;
    if (typeof globalThis.__tpPilotConsumeInviteForSignup === "function") {
      pilotSignupResult = globalThis.__tpPilotConsumeInviteForSignup({ req, code: pilotInviteCode, role, phone: phoneNorm, profile });
      if (pilotSignupResult && pilotSignupResult.error) {
        logAudit(req, "pilot_signup_invite_failed", { phoneTried: phoneNorm, role, code: pilotInviteCode || null, reason: pilotSignupResult.error });
        return res.status(pilotSignupResult.statusCode || 400).json({ error: pilotSignupResult.error });
      }
    }

    user = {
      id: uuid(),
      phone: phoneNorm,
      role,
      pinHash: hashPin(pin),
      kycLevel: "basic",
      kycStatus: "unsubmitted",
      kycHistory: [],
      consents: profile && profile.consents ? profile.consents : {},
      pilotOnboarding: pilotSignupResult && pilotSignupResult.participant ? pilotSignupResult.participant : null,
    };
    users.push(user);
    if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
    console.log("Created public user:", user.phone, user.role);
  } else {
    ensureUserKycDefaults(user);
    // Hardening: if an admin bootstrap phone is configured, restrict bootstrap admin access to it.
    if (DEMO_ADMIN_PHONE && user.role === "admin" && user.phone !== DEMO_ADMIN_PHONE) {
      logAudit(req, "auth_login_failed", { reason: "admin_phone_mismatch", phoneTried: phoneNorm });
      return res.status(403).json({ error: "Admin access is restricted." });
    }

    if (user.disabled) {
      logAudit(req, "auth_login_failed", { reason: "user_disabled", phoneTried: phoneNorm });
      return res.status(403).json({ error: "This account has been disabled. Please contact support." });
    }

    if (rolePreference && String(rolePreference).trim()) {
      const requestedRole = String(rolePreference).trim().toLowerCase();
      const actualRole = String(user.role || "").trim().toLowerCase();
      if (requestedRole !== actualRole) {
        logAudit(req, "auth_login_failed", { reason: "role_mismatch", phoneTried: phoneNorm, requestedRole, actualRole });
        return res.status(403).json({ error: "Selected role does not match this account." });
      }
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
    if (profile.consents && typeof profile.consents === "object") user.consents = profile.consents;
    // persist user profile
    if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
  } catch (e) {}
}

// Link a pilot invite to an existing account when a valid invite code is submitted during signup.
if (pilotInviteCode && (!user.pilotOnboarding || !user.pilotOnboarding.inviteCode)) {
  try {
    if (typeof globalThis.__tpPilotConsumeInviteForSignup === "function") {
      const linkResult = globalThis.__tpPilotConsumeInviteForSignup({ req, code: pilotInviteCode, role: user.role, phone: phoneNorm, profile });
      if (linkResult && linkResult.error) {
        logAudit(req, "pilot_existing_invite_failed", { phoneTried: phoneNorm, role: user.role, code: pilotInviteCode, reason: linkResult.error });
        return res.status(linkResult.statusCode || 400).json({ error: linkResult.error });
      }
      if (linkResult && linkResult.participant) {
        user.pilotOnboarding = linkResult.participant;
        if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }
      }
    }
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
  if (dbEnabled()) { dbUpsertSession(token, sessions.get(token)).catch(()=>{}); }

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
      pilotOnboarding: user.pilotOnboarding || null,
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

// -------- KYC (PSP/BoZ partner-demo prep) --------
app.get("/api/kyc/me", requireAuth, (req, res) => {
  const user = ensureUserKycDefaults(findUserByPhone(req.user.phone));
  if (!user) return res.status(404).json({ error: "User not found" });
  ensureKycThreadDefaults(user);
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
    kycThread: sanitizeKycThread(user.kycThread),
    attachmentList: kycAttachmentEntriesFromProfile(user.kycProfile || {}),
  });
});

app.post("/api/kyc/submit", requireAuth, async (req, res) => {
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

  const kycDocs = {};
  const kycDocSpecs = [
    ["idFrontDataUrl", "idFrontUrl", "id-front"],
    ["idBackDataUrl", "idBackUrl", "id-back"],
    ["passportDataUrl", "passportUrl", "passport"],
    ["selfieDataUrl", "selfieUrl", "selfie"],
    ["proofOfAddressDataUrl", "proofOfAddressUrl", "proof-address"],
    ["businessCertDataUrl", "businessCertUrl", "business-cert"],
  ];
  for (const [srcKey, dstKey, prefix] of kycDocSpecs) {
    const raw = body[srcKey] || body[dstKey] || "";
    if (typeof raw === "string" && raw.trim()) {
      try {
        kycDocs[dstKey] = await persistKycDataUrl(raw, { folder: "tutopay/kyc", prefix });
      } catch (e) {
        console.error(`[kyc] failed to persist ${srcKey}:`, e && e.message ? e.message : e);
        kycDocs[dstKey] = raw;
      }
    }
  }

  user.kycProfile = {
    ...(user.kycProfile || {}),
    fullName,
    idType,
    idNumber,
    dob: body.dob ? String(body.dob) : undefined,
    address: body.address ? String(body.address).trim() : undefined,
    businessName: body.businessName ? String(body.businessName).trim() : undefined,
    sellerType: body.sellerType ? String(body.sellerType).trim() : undefined,
    selfieProvided: !!((user.profile && user.profile.selfieDataUrl) || kycDocs.selfieUrl),
    logoProvided: !!(user.profile && user.profile.logoDataUrl),
    submittedFields: Object.keys(body || {}).sort(),
    ...kycDocs,
  };
  ensureKycThreadDefaults(user);
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
    docsStored: Object.keys(kycDocs),
  });
  const submitMessage = String(body.message || "").trim() || "Initial KYC submission sent for review.";
  pushKycThreadMessage(user, {
    at: user.kycSubmittedAt,
    byRole: user.role || "user",
    byPhone: req.user.phone,
    message: submitMessage,
    attachments: kycAttachmentEntriesFromProfile(kycDocs).length ? kycAttachmentEntriesFromProfile(kycDocs) : kycAttachmentEntriesFromProfile(user.kycProfile),
    statusAfter: user.kycStatus,
  });

  if (dbEnabled()) dbUpsertUser(user).catch(() => {});
  logAudit(req, "kyc_submit", { phone: user.phone, requestedKycLevel, idType, docsStored: Object.keys(kycDocs) });
  return res.json({
    ok: true,
    message: "KYC submitted for review.",
    kycStatus: user.kycStatus,
    requestedKycLevel: user.kycLevel,
    effectiveKycLevel: getEffectiveKycLevel(user),
    kycSubmittedAt: user.kycSubmittedAt,
    docsStored: Object.keys(kycDocs),
  });
});



app.post("/api/kyc/reply", requireAuth, async (req, res) => {
  if (req.user.role === "admin") return res.status(403).json({ error: "Admin cannot use the KYC reply endpoint." });
  const user = ensureKycThreadDefaults(ensureUserKycDefaults(findUserByPhone(req.user.phone)));
  if (!user) return res.status(404).json({ error: "User not found" });

  const body = req.body || {};
  const message = String(body.message || "").trim();
  const kycDocs = {};
  const kycDocSpecs = [
    ["idFrontDataUrl", "idFrontUrl", "id-front"],
    ["idBackDataUrl", "idBackUrl", "id-back"],
    ["passportDataUrl", "passportUrl", "passport"],
    ["selfieDataUrl", "selfieUrl", "selfie"],
    ["proofOfAddressDataUrl", "proofOfAddressUrl", "proof-address"],
    ["businessCertDataUrl", "businessCertUrl", "business-cert"],
  ];

  for (const [srcKey, dstKey, prefix] of kycDocSpecs) {
    const raw = body[srcKey] || body[dstKey] || "";
    if (typeof raw === "string" && raw.trim()) {
      try {
        kycDocs[dstKey] = await persistKycDataUrl(raw, { folder: "tutopay/kyc", prefix });
      } catch (e) {
        console.error(`[kyc-reply] failed to persist ${srcKey}:`, e && e.message ? e.message : e);
        kycDocs[dstKey] = raw;
      }
    }
  }

  if (!message && !Object.keys(kycDocs).length) {
    return res.status(400).json({ error: "Add a message or at least one attachment." });
  }

  user.kycProfile = { ...(user.kycProfile || {}), ...kycDocs };
  user.kycStatus = "pending";
  user.kycSubmittedAt = nowIso();
  user.kycHistory = Array.isArray(user.kycHistory) ? user.kycHistory : [];
  user.kycHistory.push({
    at: user.kycSubmittedAt,
    action: "user_reply",
    by: req.user.phone,
    docsStored: Object.keys(kycDocs),
    message: message || null,
  });

  const attachments = kycAttachmentEntriesFromProfile(kycDocs);
  pushKycThreadMessage(user, {
    at: user.kycSubmittedAt,
    byRole: user.role || "user",
    byPhone: req.user.phone,
    message: message || "Additional KYC information submitted.",
    attachments,
    statusAfter: user.kycStatus,
  });

  if (dbEnabled()) dbUpsertUser(user).catch(() => {});
  logAudit(req, "kyc_reply", { phone: user.phone, docsStored: Object.keys(kycDocs), hasMessage: !!message });

  return res.json({
    ok: true,
    message: "KYC reply sent to admin.",
    kycStatus: user.kycStatus,
    attachmentList: attachments,
    kycThread: sanitizeKycThread(user.kycThread),
  });
});

app.get("/api/admin/kyc/pending", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const pending = users
    .map(u => ensureUserKycDefaults(u))
    .filter(u => u.role !== "admin" && (u.kycStatus === "pending" || u.kycStatus === "under_review" || u.kycStatus === "needs_more_info"))
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
      kycThread: sanitizeKycThread(u.kycThread),
      attachmentList: kycAttachmentEntriesFromProfile(u.kycProfile || {}),
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
  ensureKycThreadDefaults(user);
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
  pushKycThreadMessage(user, {
    at,
    byRole: "admin",
    byPhone: req.user.phone,
    message: user.kycRejectionReason || (user.kycStatus === "verified" ? `KYC approved at ${level} level.` : "KYC reviewed."),
    attachments: [],
    statusAfter: user.kycStatus,
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
    kycThread: sanitizeKycThread(user.kycThread),
    attachmentList: kycAttachmentEntriesFromProfile(user.kycProfile || {}),
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

app.post("/api/items", requireAuth, async (req, res) => {
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
  const convert = async (u) => {
    if (typeof u !== "string") return "";
    if (!u.startsWith("data:")) return u;
    if (cache.has(u)) return cache.get(u);
    const saved = await persistImageDataUrl(u, {
      prefix: "item",
      folder: `tutopay/catalogue/${String(sellerPhone || "unknown").replace(/[^0-9A-Za-z_-]+/g, "-")}`
    });
    cache.set(u, saved);
    return saved;
  };

  const urlsArray = Array.isArray(imageUrls) ? imageUrls.slice(0, 15) : [];
  const convertedUrls = (await Promise.all(urlsArray.map(convert))).filter(Boolean);
  const firstUrl = imageUrl || (convertedUrls[0] || (urlsArray[0] || ""));
  const convertedFirst = (await convert(firstUrl)) || convertedUrls[0] || "";

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
  try { await dbUpsertItem(item); } catch (e) { console.error("[items] dbUpsertItem failed:", e && e.message ? e.message : e); }
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
    markPartnerProcessing(tx, { provider: "demo", collectionStatus: "SUCCESSFUL", settlementStatus: "pending_workflow", lastCollectionCallbackAt: nowIso() });
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
    markPartnerProcessing(tx, { provider: "airtel_sandbox", collectionStatus: "PENDING", paymentExecutionBy: "licensed_partner", lastCollectionReference: tx.paymentRef });

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
        payerMessage: "TutoPay transaction payment",
        payeeNote: "Transaction payment",
        callbackUrl: MOMO_CALLBACK_URL,
      });

      tx.paymentProvider = "mtn_momo";
      tx.paymentStatus = "pending";
      tx.paymentRef = referenceId;
      markPartnerProcessing(tx, { provider: "mtn_momo", collectionStatus: "PENDING", paymentExecutionBy: "licensed_partner", lastCollectionReference: referenceId });
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
    markPartnerProcessing(tx, { provider: PAYMENTS_MODE, collectionStatus: "PENDING", paymentExecutionBy: "licensed_partner", lastCollectionReference: tx.paymentRef });
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
      processedBy: "licensed_partner",
    };
    markPartnerProcessing(tx, {
      payoutStatus: "pending",
      provider: "mtn_momo_disbursement",
      settlementBy: "licensed_partner",
      payoutInitiatedAt: nowIso(),
      lastPayoutReference: referenceId,
    });
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
      markPartnerProcessing(tx, { payoutStatus: "successful", settlementStatus: "settled", lastPayoutReference: tx.disbursement.referenceId, lastPayoutCheckAt: nowIso() });
      recordLedger(req, tx, "payout_completed", { reference: tx.disbursement.referenceId, provider: "mtn_momo_disbursement", notes: "Seller payout successful" });
    } else if (tx.disbursement.status === "failed") {
      markPartnerProcessing(tx, { payoutStatus: "failed", settlementStatus: "failed", lastPayoutReference: tx.disbursement.referenceId, lastPayoutCheckAt: nowIso() });
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
  // Internal staff consoles need platform-wide visibility for operational work.
  // Public buyers/sellers still only see their own transactions.
  if (req.user.role !== "admin" && !isInternalStaffRole(req.user.role)) {
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
  disputeUpload.single("file")(req, res, async (err) => {
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

    let urlPath = `/uploads/${req.file.filename}`;
    let finalUrl = `${PUBLIC_API_BASE}${urlPath}`;
    let cloudinaryMeta = null;
    if (cloudinaryConfigured()) {
      try {
        cloudinaryMeta = await uploadLocalFileToCloudinary(req.file.path, {
          folder: "tutopay/evidence",
          prefix: "evidence",
          filename: req.file.originalname || req.file.filename,
          mimetype: req.file.mimetype,
          size: req.file.size,
        });
        if (cloudinaryMeta && cloudinaryMeta.secureUrl) {
          finalUrl = cloudinaryMeta.secureUrl;
          urlPath = null;
        }
      } catch (e) {
        console.error('[cloudinary] evidence upload failed, keeping local upload:', e && e.message ? e.message : e);
      }
    }

    const doc = {
      id: uuid(),
      filename: req.file.filename,
      originalname: req.file.originalname,
      name: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      uploadedAt: nowIso(),
      uploadedByPhone: (req.user && req.user.phone) ? String(req.user.phone) : null,
      urlPath,
      // Absolute URL so evidence links work from tutopay.online (frontend) to api.tutopay.online (backend)
      url: finalUrl,
      cloudinary: cloudinaryMeta ? {
        publicId: cloudinaryMeta.publicId,
        resourceType: cloudinaryMeta.resourceType,
        bytes: cloudinaryMeta.bytes,
        format: cloudinaryMeta.format,
      } : null,
    };

    tx.disputeDocs.push(doc);
    if (dbEnabled()) { dbUpsertTransaction(tx).catch(() => {}); }
    logAudit(req, 'dispute_evidence_upload', { txId: tx.id, filename: doc.name, mimeType: doc.mimetype, cloudinary: !!cloudinaryMeta });

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

// -------- Admin: view audit log --------
app.get("/api/admin/audit", requireAuth, (req, res) => {
  if (!isInternalStaffRole(req.user.role)) {
    return res.status(403).json({ error: "Internal staff only" });
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
    staffAccount: !!u.staffAccount,
    createdBy: u.createdBy || null,
    createdAt: u.createdAt || null,
    // profile (optional)
    displayName: u.profile && (u.profile.displayName || u.profile.fullName) ? (u.profile.displayName || u.profile.fullName) : undefined,
    businessName: u.profile && u.profile.businessName ? u.profile.businessName : undefined,
  }));

  res.json({ users: list });
});

// -------- Admin: create internal staff accounts --------
// Staff accounts are created by an authenticated admin only; they are NOT auto-registered from the public sign-in page.
app.post("/api/admin/staff", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const body = req.body || {};
  const phone = normalizePhone(body.phone);
  const pin = String(body.pin || "").trim();
  const role = String(body.role || "").trim().toLowerCase();
  const displayName = String(body.displayName || body.name || "").trim();

  const allowedStaffRoles = ["risk_agent", "accounts_agent", "finance_agent", "compliance_agent"];

  if (!phone) return res.status(400).json({ error: "Staff phone number is required." });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "Staff PIN must be exactly 4 digits." });
  if (!allowedStaffRoles.includes(role)) {
    return res.status(400).json({
      error: "Invalid staff role.",
      allowedRoles: allowedStaffRoles,
    });
  }

  const existing = findUserByPhone(phone);
  if (existing) {
    return res.status(409).json({ error: "An account with this phone number already exists." });
  }

  const staffUser = {
    id: uuid(),
    phone,
    role,
    pinHash: hashPin(pin),
    kycLevel: "staff",
    kycStatus: "verified",
    disabled: false,
    staffAccount: true,
    createdAt: nowIso(),
    createdBy: req.user.phone,
    profile: displayName ? { displayName, fullName: displayName } : {},
    permissions: {
      internalAccess: true,
      createdFromAdminConsole: true,
    },
  };

  users.push(staffUser);
  if (dbEnabled()) {
    try { await dbUpsertUser(staffUser); } catch (e) { console.warn("Could not persist staff user", e.message || e); }
  }

  logAudit(req, "admin_staff_created", {
    staffPhone: phone,
    staffRole: role,
    displayName: displayName || null,
    createdBy: req.user.phone,
  });

  return res.status(201).json({
    ok: true,
    user: {
      id: staffUser.id,
      phone: staffUser.phone,
      role: staffUser.role,
      kycLevel: staffUser.kycLevel,
      kycStatus: staffUser.kycStatus,
      disabled: false,
      displayName: displayName || undefined,
      staffAccount: true,
    },
  });
});

// Update a user: toggle disabled via query param
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
  if (!isAccountingRole(req.user.role)) return res.status(403).json({ error: "Accounting only" });

  const txId = req.query.txId ? String(req.query.txId) : null;
  const limit = Math.min(Number(req.query.limit) || 200, 2000);
  let entries = ledgerEntries;
  if (txId) entries = entries.filter((e) => String(e.txId) === txId);
  entries = entries.slice(-limit).reverse();

  res.json({ entries });
});


app.get("/api/admin/callback-config", requireAuth, (req, res) => {
  if (!isAccountingRole(req.user.role)) return res.status(403).json({ error: "Accounting only" });
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
  if (!isAccountingRole(req.user.role)) return res.status(403).json({ error: "Accounting only" });

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
  if (!isAccountingRole(req.user.role)) return res.status(403).json({ error: "Accounting only" });

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
/* ===== Step 6+7: Compliance pack + Issues Desk foundation (Partner Demo v1 controls) ===== */
(function(){
  // ---- Compliance docs + incidents (Step 6, included here so this file is self-contained) ----
  const complianceDocs = [
    {
      id: 'terms',
      title: 'TutoPay Terms of Use',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/terms',
      body: 'TutoPay provides a non-custodial marketplace transaction workflow. TutoPay manages transaction records, evidence capture, confirmations, issue handling and dispute workflow. Customer funds are processed, settled, refunded and reversed by licensed PSP, mobile-money or banking partners. Users must provide accurate information, avoid prohibited goods, cooperate with KYC and dispute checks, and accept that TutoPay may pause or refuse transactions for fraud, risk, compliance, legal or operational reasons.'
    },
    {
      id: 'privacy',
      title: 'TutoPay Privacy Notice',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/privacy',
      body: 'TutoPay collects account details, contact details, transaction records, catalogue records, KYC information, device/session metadata and dispute evidence to operate the platform, verify users, prevent fraud, support investigations, resolve complaints, maintain audit trails and meet legal or partner obligations. Access is restricted to authorised staff according to role and purpose.'
    },
    {
      id: 'kyc-limits',
      title: 'KYC/CDD & Transaction Limits Policy',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/kyc-limits',
      body: 'TutoPay applies account limits according to verification level and risk. Unverified users remain on basic limits. Higher activity may require NRC, selfie, business details, supporting documents, manual review or partner verification. TutoPay may restrict accounts, pause releases or escalate cases when identity, transaction behaviour or evidence indicates increased risk.'
    },
    {
      id: 'aml-cft',
      title: 'AML/CFT Controls Summary',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/aml-cft',
      body: 'TutoPay monitors transaction patterns, repeat disputes, unusual amounts, suspicious behaviour, prohibited goods indicators and failed verification attempts. Cases may be escalated to compliance staff, restricted, documented in the incident register, or referred to the licensed payment partner for additional action under the partner\'s AML/CFT obligations.'
    },
    {
      id: 'disputes',
      title: 'Disputes, Refunds & Complaints SOP',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/disputes',
      body: 'Complaints are linked to transaction records and routed to the Issues Desk. Staff review timelines, uploaded evidence, delivery/collection records, buyer and seller statements, risk indicators and policy codes before recommending release, refund, reversal request or escalation. Maker-checker controls apply to sensitive outcomes, and all staff actions are logged.'
    },
    {
      id: 'data-retention',
      title: 'Data Retention & Evidence Handling Policy',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/data-retention',
      body: 'TutoPay retains transaction records, audit logs, KYC submissions, evidence files and incident records for compliance, dispute resolution, fraud prevention, reconciliation and legal purposes. Access to sensitive evidence is limited to authorised staff and should be protected through authenticated or expiring access mechanisms in production.'
    },
    {
      id: 'incident-response',
      title: 'Incident Response Policy',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/incident-response',
      body: 'Operational, fraud, security, reconciliation and partner-callback incidents are recorded in the compliance incident register. Incidents are classified by severity, assigned to responsible staff, investigated, documented, escalated when necessary and closed with an audit trail.'
    },
    {
      id: 'psp-settlement',
      title: 'PSP Settlement & Reconciliation SOP',
      version: '1.0-partner-demo',
      updatedAt: '2026-06-02T00:00:00.000Z',
      path: '/api/public/compliance/docs/psp-settlement',
      body: 'TutoPay does not custody customer funds. Collections, payouts, reversals, refunds and settlement occur on licensed partner rails. TutoPay records partner references, callback statuses, workflow events, release/refund decisions and reconciliation flags so every transaction can be matched against partner statements and operational evidence.'
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

  function _readinessFlag(ok, label, detail, action, category, weight){
    return { ok: !!ok, label, detail: String(detail || ''), action: String(action || ''), category: category || 'general', weight: Number(weight || 1) || 1 };
  }
  function _envSet(name){ return !!String(process.env[name] || '').trim(); }
  function _envAny(names){ return names.some(_envSet); }
  function _maskedEnvStatus(name){ return _envSet(name) ? 'configured' : 'missing'; }
  function _kycBreakdown(){
    const out = { unsubmitted:0, pending:0, under_review:0, verified:0, rejected:0, needs_more_info:0, other:0 };
    users.forEach(u => {
      const s = String((u && u.kycStatus) || 'unsubmitted').toLowerCase();
      if (Object.prototype.hasOwnProperty.call(out, s)) out[s] += 1;
      else out.other += 1;
    });
    return out;
  }
  function _staffBreakdown(){
    const out = { admin:0, risk_agent:0, accounts_agent:0, finance_agent:0, compliance_agent:0, other_staff:0 };
    users.forEach(u => {
      const r = String((u && u.role) || '').toLowerCase();
      if (Object.prototype.hasOwnProperty.call(out, r)) out[r] += 1;
      else if (isInternalStaffRole(r)) out.other_staff += 1;
    });
    return out;
  }
  function _readinessScore(controls){
    const total = controls.reduce((s,c)=>s + (Number(c.weight)||1), 0) || 1;
    const got = controls.reduce((s,c)=>s + (c.ok ? (Number(c.weight)||1) : 0), 0);
    return Math.round((got / total) * 100);
  }
  function _complianceOverview() {
    const counts = _complianceCounts();
    const txs = issuesTxs().map(ensureTxReconDefaults);
    const pendingCollection = txs.filter((t) => t.paymentStatus === 'paid' && !t.collectionReconciled).length;
    const pendingPayout = txs.filter((t) => (t.status === 'completed' || (t.disbursement && t.disbursement.status === 'successful')) && !t.payoutReconciled).length;
    const openIncidents = complianceIncidents.filter(i => String(i.status || 'open').toLowerCase() !== 'closed').length;
    const openDisputes = txs.filter(t => !!t.disputeActive || String(t.status||'').toLowerCase()==='disputed').length;
    const paymentsConfigured = PAYMENTS_MODE === 'demo' || _envAny(['MTN_COLLECTION_SUB_KEY','AIRTEL_CLIENT_ID']);
    const payoutConfigured = PAYMENTS_MODE === 'demo' || _envAny(['MTN_DISBURSEMENT_SUB_KEY']);
    const cloudinaryConfigured = _envAny(['CLOUDINARY_URL']) || (_envSet('CLOUDINARY_CLOUD_NAME') && _envSet('CLOUDINARY_API_KEY') && _envSet('CLOUDINARY_API_SECRET'));
    const callbackSecretConfigured = !!(process.env.MTN_CALLBACK_SECRET || process.env.CALLBACK_SHARED_SECRET || process.env.AIRTEL_CALLBACK_SECRET);
    const staff = _staffBreakdown();
    const kyc = _kycBreakdown();

    const controls = [
      _readinessFlag(DEMO_MODE === false, 'Demo mode disabled', `DEMO_MODE=${DEMO_MODE}`, 'Set DEMO_MODE=false for partner-facing demonstrations.', 'environment', 2),
      _readinessFlag(String(APP_STAGE||'').toLowerCase().includes('partner'), 'Partner-demo stage set', `APP_STAGE=${APP_STAGE || 'unset'}`, 'Set APP_STAGE=partner_demo to identify controlled demo deployments.', 'environment', 1),
      _readinessFlag(dbReady && (dbEnabled() || !STRICT_DB_MODE), 'Database/startup readiness', `dbReady=${dbReady}, dbEnabled=${dbEnabled()}, strict=${STRICT_DB_MODE}`, 'Use Postgres DATABASE_URL and STRICT_DB_MODE=true before live money movement.', 'infrastructure', 2),
      _readinessFlag(!!PUBLIC_API_BASE && /^https:/.test(String(PUBLIC_API_BASE)), 'HTTPS public API base', `PUBLIC_API_BASE=${PUBLIC_API_BASE || 'unset'}`, 'Use an HTTPS API base for callbacks and partner integrations.', 'infrastructure', 1),
      _readinessFlag(callbackSecretConfigured, 'Callback shared secret configured', `MTN=${_maskedEnvStatus('MTN_CALLBACK_SECRET')}, Airtel=${_maskedEnvStatus('AIRTEL_CALLBACK_SECRET')}`, 'Configure provider callback secrets and share only with PSP partners.', 'payments', 2),
      _readinessFlag(paymentsConfigured, 'Collection rail configuration', `PAYMENTS_MODE=${PAYMENTS_MODE}`, 'Configure MTN/Airtel collection credentials or keep clearly marked sandbox mode.', 'payments', 2),
      _readinessFlag(payoutConfigured, 'Payout/disbursement configuration', `PAYMENTS_MODE=${PAYMENTS_MODE}`, 'Configure disbursement credentials or document PSP-led settlement procedure.', 'payments', 2),
      _readinessFlag(cloudinaryConfigured, 'Persistent evidence/image storage', cloudinaryConfigured ? 'Cloudinary configured' : 'Cloudinary not configured', 'Configure durable private storage for catalogue, KYC and evidence files.', 'data', 1),
      _readinessFlag(complianceDocs.length >= 8, 'Compliance policy pack available', `${complianceDocs.length} policy documents`, 'Keep policy versions current and export them for PSP/BoZ packs.', 'compliance', 2),
      _readinessFlag(staff.admin >= 1 && staff.risk_agent >= 1 && staff.compliance_agent >= 1 && (staff.accounts_agent + staff.finance_agent) >= 1, 'Segregated staff roles', `Admin=${staff.admin}, Risk=${staff.risk_agent}, Compliance=${staff.compliance_agent}, Accounts/Finance=${staff.accounts_agent + staff.finance_agent}`, 'Create at least one Risk, Compliance and Accounts/Finance staff account.', 'governance', 2),
      _readinessFlag(auditLog.length >= 0, 'Audit trail active', `${auditLog.length} audit events`, 'Continue to capture staff actions, approvals and account changes.', 'governance', 1),
      _readinessFlag(ledgerEntries.length >= 0, 'Ledger/reconciliation trail active', `${ledgerEntries.length} ledger events`, 'Use reconciliation exports and match against PSP statements during pilot.', 'finance', 2),
      _readinessFlag(pendingCollection === 0 && pendingPayout === 0, 'No unreconciled money events', `${pendingCollection} pending collection checks, ${pendingPayout} pending payout checks`, 'Accounts/Finance should reconcile outstanding items before partner reviews.', 'finance', 1),
      _readinessFlag(openIncidents === 0, 'No open compliance incidents', `${openIncidents} open incidents`, 'Close or document incident action plans before external demos.', 'operations', 1),
      _readinessFlag(openDisputes === 0, 'No open disputes', `${openDisputes} open disputes`, 'Resolve or clearly document active cases before PSP/BoZ reviews.', 'risk', 1),
    ];
    const score = _readinessScore(controls);

    const gaps = controls
      .filter(c => !c.ok)
      .map(c => ({ label:c.label, category:c.category, detail:c.detail, action:c.action, weight:c.weight }))
      .sort((a,b)=> (b.weight||1)-(a.weight||1));

    return {
      readinessScore: score,
      readinessBand: score >= 85 ? 'Strong partner-demo readiness' : (score >= 70 ? 'Moderate readiness' : (score >= 50 ? 'Early readiness' : 'Needs major cleanup')),
      generatedAt: nowIso(),
      stage: APP_STAGE,
      paymentsMode: PAYMENTS_MODE,
      demoMode: DEMO_MODE,
      database: { ready: dbReady, enabled: dbEnabled(), strict: STRICT_DB_MODE },
      counts: Object.assign({}, counts, { pendingCollectionReconciliation: pendingCollection, pendingPayoutReconciliation: pendingPayout, openComplianceIncidents: openIncidents, openDisputes }),
      kycBreakdown: kyc,
      staffBreakdown: staff,
      controls,
      gaps,
      policyDocs: complianceDocs.map(d => ({ id:d.id, title:d.title, version:d.version, path:d.path, updatedAt:d.updatedAt })),
      envSnapshot: {
        appStage: APP_STAGE || '',
        paymentMode: PAYMENTS_MODE,
        publicSignup: ALLOW_PUBLIC_SIGNUP,
        mtnCollection: _envAny(['MTN_COLLECTION_SUB_KEY','MTN_COLLECTION_APIUSER','MTN_COLLECTION_APIKEY']),
        mtnDisbursement: _envAny(['MTN_DISBURSEMENT_SUB_KEY','MTN_DISBURSEMENT_APIUSER','MTN_DISBURSEMENT_APIKEY']),
        airtelCollection: _envAny(['AIRTEL_CLIENT_ID','AIRTEL_CLIENT_SECRET']),
        callbackSecrets: callbackSecretConfigured,
        cloudinary: cloudinaryConfigured,
      },
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
    if (!isComplianceRole(req.user.role)) return res.status(403).json({ error:'Compliance only' });
    res.json(_complianceOverview());
  });
  app.get('/api/admin/compliance/incidents', requireAuth, (req,res)=> {
    if (!isComplianceRole(req.user.role)) return res.status(403).json({ error:'Compliance only' });
    const limit = Math.max(1, Math.min(500, Number(req.query.limit)||100));
    res.json({ ok:true, incidents: complianceIncidents.slice(-limit).reverse() });
  });
  app.post('/api/admin/compliance/incidents', requireAuth, async (req,res)=> {
    if (!isComplianceRole(req.user.role)) return res.status(403).json({ error:'Compliance only' });
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

  app.post('/api/admin/compliance/incidents/:incidentId/status', requireAuth, (req,res)=> {
    if (!isComplianceRole(req.user.role)) return res.status(403).json({ error:'Compliance only' });
    const id = String(req.params.incidentId || '').trim();
    const incident = complianceIncidents.find(i => String(i.id) === id);
    if (!incident) return res.status(404).json({ error:'Incident not found' });
    const status = String((req.body||{}).status || '').trim().toLowerCase();
    const allowed = ['open','in_review','monitoring','closed'];
    if (!allowed.includes(status)) return res.status(400).json({ error:'Invalid status' });
    incident.status = status;
    incident.updatedAt = nowIso();
    incident.updatedBy = req.user.phone;
    if ((req.body||{}).note) {
      incident.notes = incident.notes || [];
      incident.notes.push({ at: incident.updatedAt, by: req.user.phone, note: String((req.body||{}).note).trim() });
    }
    logAudit(req, 'compliance_incident_status_update', { incidentId: id, status });
    res.json({ ok:true, incident });
  });

  app.get('/api/admin/compliance/users', requireAuth, (req,res)=> {
    if (!isComplianceRole(req.user.role)) return res.status(403).json({ error:'Compliance only' });
    const status = String(req.query.status || '').trim().toLowerCase();
    const role = String(req.query.role || '').trim().toLowerCase();
    const q = String(req.query.q || '').trim().toLowerCase();
    const limit = Math.max(1, Math.min(500, Number(req.query.limit)||100));
    let rows = users.filter(u => u && u.role !== 'admin');
    if (status) rows = rows.filter(u => String(u.kycStatus || 'unsubmitted').toLowerCase() === status);
    if (role) rows = rows.filter(u => String(u.role || '').toLowerCase() === role);
    if (q) rows = rows.filter(u => `${u.phone||''} ${u.name||''} ${u.businessName||''} ${u.role||''} ${u.kycStatus||''}`.toLowerCase().includes(q));
    rows = rows.slice(-limit).reverse().map(u => ({
      id: u.id,
      phone: u.phone,
      name: u.name || u.fullName || '',
      businessName: u.businessName || '',
      role: u.role,
      kycLevel: u.kycLevel || 'basic',
      kycStatus: u.kycStatus || 'unsubmitted',
      disabled: !!u.disabled,
      complianceRestricted: !!u.complianceRestricted,
      restrictionReason: u.restrictionReason || '',
      restrictedAt: u.restrictedAt || null,
      createdAt: u.createdAt || null,
      updatedAt: u.updatedAt || null,
      hasNrc: !!u.nrc,
      hasSelfie: !!(u.selfieUrl || u.selfie || u.selfieDataUrl),
      hasBusinessDocs: !!(u.businessDocUrl || u.businessDocs || u.logoUrl),
    }));
    res.json({ ok:true, users: rows });
  });

  app.post('/api/admin/compliance/users/:phone/restrict', requireAuth, async (req,res)=> {
    if (!isComplianceRole(req.user.role)) return res.status(403).json({ error:'Compliance only' });
    const phone = String(req.params.phone || '').trim();
    const user = findUserByPhone(phone);
    if (!user) return res.status(404).json({ error:'User not found' });
    if (user.role === 'admin') return res.status(400).json({ error:'Admin accounts cannot be restricted here' });
    const restricted = !!(req.body||{}).restricted;
    const reason = String((req.body||{}).reason || '').trim();
    user.complianceRestricted = restricted;
    user.restrictionReason = restricted ? reason : '';
    user.restrictedAt = restricted ? nowIso() : null;
    user.restrictedBy = restricted ? req.user.phone : '';
    user.updatedAt = nowIso();
    try { if (dbEnabled()) await dbUpsertUser(user); } catch(e){}
    logAudit(req, 'compliance_user_restriction', { phone:user.phone, restricted, reason });
    res.json({ ok:true, user:{ phone:user.phone, role:user.role, complianceRestricted:!!user.complianceRestricted, restrictionReason:user.restrictionReason||'' } });
  });

// ---- Step 8A exports (CSV) ----



function normalizeOutcome(raw){
  const v = String(raw || '').trim().toLowerCase();
  if (!v) return '';
  const map = {
    refund: 'refund',
    refunded: 'refund',
    approve_refund: 'refund',
    approved_refund: 'refund',
    admin_execute_refund: 'refund',
    recommend_refund: 'refund',
    reject: 'reject',
    rejected: 'reject',
    decline: 'reject',
    declined: 'reject',
    deny: 'reject',
    denied: 'reject',
    approve_reject: 'reject',
    approved_reject: 'reject',
    admin_execute_reject: 'reject',
    recommend_reject: 'reject',
    close: 'close',
    closed: 'close',
    close_case: 'close',
    resolved: 'close'
  };
  return map[v] || v;
}
function parseFromTo(req){
  const fromRaw = req.query.from ? String(req.query.from).trim() : '';
  const toRaw = req.query.to ? String(req.query.to).trim() : '';
  let fromD = null, toD = null;
  if (fromRaw){
    fromD = new Date(fromRaw.length===10 ? (fromRaw+'T00:00:00.000Z') : fromRaw);
    if (isNaN(fromD.getTime())) fromD = null;
  }
  if (toRaw){
    toD = new Date(toRaw.length===10 ? (toRaw+'T23:59:59.999Z') : toRaw);
    if (isNaN(toD.getTime())) toD = null;
  }
  return { fromD, toD };
}
function inRange(ts, fromD, toD){
  const ms = Date.parse(ts || "");
  if (!Number.isFinite(ms)) return false;
  if (fromD && ms < fromD.getTime()) return false;
  if (toD && ms > toD.getTime()) return false;
  return true;
}
function toMs(val){
  const ms = Date.parse(val || '');
  return Number.isFinite(ms) ? ms : 0;
}
function uniqueBy(rows, keyFn){
  const out = [];
  const seen = new Set();
  for (const row of (rows || [])){
    const key = String(keyFn(row) || '').trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}
function csvEscape(v){
  return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
}
function normalizeCaseRow(x){
  const d = (x && x.data) ? x.data : (x || {});
  const docs = Array.isArray(d.docs) ? d.docs : (Array.isArray(d.evidenceDocs) ? d.evidenceDocs : []);
  return {
    caseId: d.caseId || d.case_id || x.case_id || '',
    txId: d.txId || d.tx_id || x.tx_id || '',
    status: d.status || '',
    priority: d.priority || '',
    assignedTo: d.assignedTo || d.assigned_to || '',
    assignedAt: d.assignedAt || d.assigned_at || '',
    slaHours: d.slaHours ?? d.sla_hours ?? '',
    slaDeadlineAt: d.slaDeadlineAt || d.sla_deadline_at || '',
    slaRemainingMs: d.slaRemainingMs ?? d.sla_remaining_ms ?? '',
    slaOverdue: d.slaOverdue ?? d.sla_overdue ?? '',
    buyerPhone: d.buyerPhone || d.buyer_phone || '',
    sellerPhone: d.sellerPhone || d.seller_phone || '',
    amount: d.amount ?? 0,
    currency: d.currency || '',
    reasonCode: d.reasonCode || d.reason_code || '',
    docsCount: d.docsCount ?? d.docs_count ?? docs.length ?? 0,
    executedOutcome: normalizeOutcome(d.executedOutcome || d.executed_outcome || ''),
    closedAt: d.closedAt || d.closed_at || '',
    createdAt: d.createdAt || d.created_at || x.created_at || x.updated_at || '',
    updatedAt: d.updatedAt || d.updated_at || x.updated_at || d.createdAt || d.created_at || ''
  };
}
function normalizeActionRow(a){
  const d = (a && a.data) ? a.data : (a || {});
  return {
    id: a.id || d.id || '',
    timestamp: d.timestamp || d.ts || d.createdAt || d.updatedAt || a.ts || a.timestamp || a.created_at || a.updated_at || '',
    caseId: d.caseId || d.case_id || a.case_id || a.caseId || '',
    txId: d.txId || d.tx_id || a.tx_id || a.txId || '',
    actionType: d.actionType || d.action_type || a.action_type || a.actionType || '',
    policyCode: d.policyCode || d.policy_code || a.policy_code || a.policyCode || '',
    nextStatus: d.nextStatus || d.next_status || a.next_status || a.nextStatus || '',
    actorPhone: d.actorPhone || d.actor_phone || d.byPhone || d.by_phone || a.actor_phone || a.by_phone || '',
    actorRole: d.actorRole || d.actor_role || d.byRole || d.by_role || a.actor_role || a.by_role || '',
    note: d.note || d.summary || ''
  };
}
function normalizeIncidentRow(x){
  const d = (x && x.data) ? x.data : (x || {});
  return {
    id: d.id || x.id || '',
    ts: d.ts || d.timestamp || d.createdAt || x.ts || x.timestamp || '',
    category: d.category || '',
    severity: d.severity || '',
    title: d.title || d.eventType || d.type || '',
    summary: d.summary || d.note || d.message || '',
    linkedCaseId: d.caseId || d.case_id || '',
    linkedTxId: d.txId || d.tx_id || ''
  };
}

app.get('/api/admin/export/issues.csv', requireAuth, requireIssuesDesk, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only');

  const { fromD, toD } = parseFromTo(req);
  const statusQ = String(req.query.status || '').trim().toLowerCase();
  const assignedQ = String(req.query.assignedTo || '').trim();
  const priorityQ = String(req.query.priority || '').trim().toLowerCase();
  const outcomeQ = normalizeOutcome(req.query.outcome);

  let rows = [];
  try{
    const merged = [];
    if (_pgPool){
      const r = await _pgPool.query(`
        SELECT case_id, tx_id, updated_at, data
        FROM tutopay_issue_cases
        ORDER BY updated_at DESC
        LIMIT 5000
      `);
      merged.push(...(r.rows || []).map(normalizeCaseRow));
    }
    merged.push(...issueCaseList().map(normalizeCaseRow));

    rows = uniqueBy(merged, r => r.caseId || `${r.txId}|${r.updatedAt}`)
      .filter(r => {
        if (!inRange(r.updatedAt || r.createdAt, fromD, toD)) return false;
        if (statusQ && String(r.status||'').toLowerCase() !== statusQ) return false;
        if (assignedQ && String(r.assignedTo||'') !== assignedQ) return false;
        if (priorityQ && String(r.priority||'').toLowerCase() !== priorityQ) return false;
        if (outcomeQ && normalizeOutcome(r.executedOutcome||'') !== outcomeQ) return false;
        return true;
      })
      .sort((a,b)=> toMs(b.updatedAt||b.createdAt)-toMs(a.updatedAt||a.createdAt));
  }catch(e){
    console.error('[export issues] failed', e);
    return res.status(500).json({ error: 'Export issues failed' });
  }

  const header = ['caseId','txId','status','priority','assignedTo','assignedAt','slaHours','slaDeadlineAt','slaRemainingMs','slaOverdue','createdAt','updatedAt','buyerPhone','sellerPhone','amount','currency','reasonCode','docsCount','executedOutcome','closedAt'].join(',');
  const csv = [header].concat(rows.map(r => [
    r.caseId, r.txId, r.status, r.priority, r.assignedTo||'', r.assignedAt||'',
    r.slaHours||'', r.slaDeadlineAt||'', (r.slaRemainingMs ?? ''), (r.slaOverdue ?? ''),
    r.createdAt||'', r.updatedAt||'',
    r.buyerPhone||'', r.sellerPhone||'', r.amount||0, r.currency||'',
    (r.reasonCode||'').replace(/,/g,' '), r.docsCount||0,
    r.executedOutcome||'', r.closedAt||''
  ].map(csvEscape).join(','))).join('\n');

  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tutopay-issues.csv"');
  res.end(csv);
});


app.get('/api/admin/export/issues-actions.csv', requireAuth, requireIssuesDesk, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only');

  const { fromD, toD } = parseFromTo(req);
  const caseIdQ = String(req.query.caseId || '').trim();
  const actorQ = String(req.query.actorPhone || req.query.assignedTo || '').trim();

  let rows = [];
  try{
    const merged = [];
    if (_pgPool){
      const r = await _pgPool.query(`
        SELECT id, ts, case_id, tx_id, action_type, policy_code, data
        FROM tutopay_issue_actions
        ORDER BY ts DESC
        LIMIT 20000
      `);
      merged.push(...(r.rows || []).map(normalizeActionRow));
    }
    merged.push(...((issueActions||[]).slice()).map(normalizeActionRow));

    rows = uniqueBy(merged, a => a.id || `${a.caseId}|${a.txId}|${a.timestamp}|${a.actionType}|${a.note}`)
      .filter(a => {
        const ts = a.timestamp || a.createdAt;
        if (!inRange(ts, fromD, toD)) return false;
        if (caseIdQ && String(a.caseId||'') !== caseIdQ) return false;
        if (actorQ && String(a.actorPhone||'') !== actorQ) return false;
        return true;
      })
      .sort((a,b)=> toMs(b.timestamp)-toMs(a.timestamp));
  }catch(e){
    console.error('[export actions] failed', e);
    return res.status(500).json({ error: 'Export actions failed' });
  }

  const header = ['id','caseId','txId','timestamp','actionType','policyCode','nextStatus','actorPhone','actorRole','note'].join(',');
  const csv = [header].concat(rows.map(a => [
    a.id||'', a.caseId||'', a.txId||'', a.timestamp||'',
    a.actionType||'', a.policyCode||'', a.nextStatus||'',
    a.actorPhone||'', a.actorRole||'', (a.note||'').replace(/\s+/g,' ').trim()
  ].map(csvEscape).join(','))).join('\n');

  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tutopay-issues-actions.csv"');
  res.end(csv);
});


app.get('/api/admin/export/incidents.csv', requireAuth, requireIssuesDesk, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only');

  const { fromD, toD } = parseFromTo(req);
  const severityQ = String(req.query.severity || '').trim().toLowerCase();
  const categoryQ = String(req.query.category || '').trim().toLowerCase();
  const incidentsArr = globalThis.__tpComplianceIncidents || [];
  const complianceIncidents = globalThis.__tpComplianceIncidents || [];

  let rows = [];
  try{
    const merged = [];
    if (_pgPool){
      const r = await _pgPool.query(`
        SELECT id, ts, data
        FROM tutopay_incidents
        ORDER BY ts DESC
        LIMIT 20000
      `);
      merged.push(...(r.rows || []).map(normalizeIncidentRow));
    }
    merged.push(...(incidentsArr.slice()).map(normalizeIncidentRow));
    merged.push(...(complianceIncidents.slice()).map(normalizeIncidentRow));

    rows = uniqueBy(merged, x => x.id || `${x.ts}|${x.category}|${x.title}|${x.linkedTxId}`)
      .filter(x => {
        if (!inRange(x.ts, fromD, toD)) return false;
        if (severityQ && String(x.severity||'').toLowerCase() !== severityQ) return false;
        if (categoryQ && String(x.category||'').toLowerCase() !== categoryQ) return false;
        return true;
      })
      .sort((a,b)=> toMs(b.ts)-toMs(a.ts));
  }catch(e){
    console.error('[export incidents] failed', e);
    return res.status(500).json({ error: 'Export incidents failed' });
  }

  const header = ['id','ts','category','severity','title','summary','linkedCaseId','linkedTxId'].join(',');
  const csv = [header].concat(rows.map(x => [
    x.id||'', x.ts||'', x.category||'', x.severity||'',
    (x.title||'').replace(/,/g,' '),
    (x.summary||'').replace(/\s+/g,' ').replace(/,/g,' ').trim(),
    x.linkedCaseId||'', x.linkedTxId||''
  ].map(csvEscape).join(','))).join('\n');

  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tutopay-incidents.csv"');
  res.end(csv);
});

app.get('/api/admin/export/issues-approvals.csv', requireAuth, requireIssuesDesk, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Admin only');

  const { fromD, toD } = parseFromTo(req);
  const outcomeQ = normalizeOutcome(req.query.outcome);
  const byPhoneQ = String(req.query.byPhone || req.query.assignedTo || '').trim();

  let rows = [];
  try{
    const merged = [];
    if (_pgPool){
      const r = await _pgPool.query(`
        SELECT ts, case_id, tx_id, action_type, policy_code, data
        FROM tutopay_issue_actions
        ORDER BY ts DESC
        LIMIT 20000
      `);
      merged.push(...(r.rows || []).map(a => {
        const n = normalizeActionRow(a);
        return {
          timestamp: n.timestamp,
          caseId: n.caseId,
          txId: n.txId,
          outcome: normalizeOutcome(n.actionType),
          policyCode: n.policyCode,
          adminPhone: n.actorPhone,
          note: n.note,
          rawActionType: n.actionType
        };
      }));
    }
    merged.push(...((issueActions||[]).slice()).map(a => {
      const n = normalizeActionRow(a);
      return {
        timestamp: n.timestamp,
        caseId: n.caseId,
        txId: n.txId,
        outcome: normalizeOutcome(n.actionType),
        policyCode: n.policyCode,
        adminPhone: n.actorPhone,
        note: n.note,
        rawActionType: n.actionType
      };
    }));

    rows = uniqueBy(merged, r => `${r.caseId}|${r.txId}|${r.timestamp}|${r.rawActionType}|${r.note}`)
      .filter(r => {
        if (!String(r.rawActionType||'').startsWith('admin_execute_')) return false;
        if (!inRange(r.timestamp, fromD, toD)) return false;
        if (outcomeQ && normalizeOutcome(r.outcome||'') !== outcomeQ) return false;
        if (byPhoneQ && String(r.adminPhone||'') !== byPhoneQ) return false;
        return true;
      })
      .sort((a,b)=> toMs(b.timestamp)-toMs(a.timestamp));
  }catch(e){
    console.error('[export approvals] failed', e);
    return res.status(500).json({ error: 'Export approvals failed' });
  }

  const header = ['timestamp','caseId','txId','outcome','policyCode','adminPhone','note'].join(',');
  const csv = [header].concat(rows.map(a => [
    a.timestamp||'', a.caseId||'', a.txId||'', a.outcome||'',
    a.policyCode||'', a.adminPhone||'', (a.note||'').replace(/\s+/g,' ').replace(/,/g,' ').trim()
  ].map(csvEscape).join(','))).join('\n');

  res.setHeader('Content-Type','text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="tutopay-issues-approvals.csv"');
  res.end(csv);
});



  app.get('/api/admin/compliance/export', requireAuth, (req,res)=> {
    if (!isComplianceRole(req.user.role)) return res.status(403).json({ error:'Compliance only' });
    const pkg = {
      exportedAt: nowIso(),
      by: req.user.phone,
      overview: _complianceOverview(),
      incidents: complianceIncidents.slice(-500),
      docs: complianceDocs,
      notes: 'Partner Demo v1.3 PSP/BoZ readiness export package (JSON)'
    };
    res.json({ ok:true, package: pkg });
  });



  /* ===== TutoPay v1.6: PSP/BoZ Partner Pack backend ===== */
  function _partnerPackAllowed(role){
    const r = String(role || '').toLowerCase();
    return r === 'admin' || isComplianceRole(r) || r === 'compliance_agent' || r === 'compliance_officer';
  }
  function _partnerPackGate(req,res,next){
    if (!req.user || !_partnerPackAllowed(req.user.role)) return res.status(403).json({ error:'Admin/Compliance only' });
    next();
  }
  function _ppMoney(v){
    const n = Number(v || 0);
    return Number.isFinite(n) ? Math.round(n * 100) / 100 : 0;
  }
  function _txLifecycleStatus(t){
    const s = String((t && t.status) || '').toLowerCase();
    if (s === 'completed' || s === 'released' || s === 'seller_paid') return 'completed';
    if (s === 'disputed' || (t && t.disputeActive)) return 'disputed';
    if (s === 'pending_payment') return 'pending_payment';
    if (s === 'pending' || s === 'held' || s === 'in_escrow' || String((t&&t.paymentStatus)||'').toLowerCase() === 'paid') return 'held_or_in_progress';
    return s || 'created';
  }
  function _partnerPackPilotMetrics(){
    const txs = (transactions || []).map(t => ensureTxReconDefaults(t || {}));
    const total = txs.length;
    const completed = txs.filter(t => _txLifecycleStatus(t) === 'completed').length;
    const disputed = txs.filter(t => _txLifecycleStatus(t) === 'disputed').length;
    const paid = txs.filter(t => String(t.paymentStatus || '').toLowerCase() === 'paid' || t.paidAt).length;
    const unreconciledCollections = txs.filter(t => (String(t.paymentStatus || '').toLowerCase() === 'paid' || t.paidAt) && !t.collectionReconciled).length;
    const unreconciledPayouts = txs.filter(t => (_txLifecycleStatus(t) === 'completed' || (t.disbursement && String(t.disbursement.status||'').toLowerCase()==='successful')) && !t.payoutReconciled).length;
    const totalValue = _ppMoney(txs.reduce((s,t)=>s+Number(t.amount||0),0));
    const completedValue = _ppMoney(txs.filter(t=>_txLifecycleStatus(t)==='completed').reduce((s,t)=>s+Number(t.amount||0),0));
    const buyerPhones = new Set(txs.map(t=>String(t.buyerPhone||t.fromPhone||'').trim()).filter(Boolean));
    const sellerPhones = new Set(txs.map(t=>String(t.sellerPhone||t.toPhone||'').trim()).filter(Boolean));
    return {
      users: {
        total: users.length,
        buyers: users.filter(u=>String(u.role||'').toLowerCase()==='buyer').length,
        sellers: users.filter(u=>String(u.role||'').toLowerCase()==='seller').length,
        activeBuyers: buyerPhones.size,
        activeSellers: sellerPhones.size,
      },
      transactions: {
        total,
        paid,
        completed,
        disputed,
        completionRate: total ? Math.round((completed/total)*100) : 0,
        disputeRate: total ? Math.round((disputed/total)*100) : 0,
        totalValue,
        completedValue,
        unreconciledCollections,
        unreconciledPayouts,
      }
    };
  }
  function _partnerPackRiskControls(){
    return [
      'Non-custodial model: licensed PSP/mobile-money/bank partner handles collection, settlement, payout, refund and reversal movement.',
      'Role separation: admin, risk, accounts/finance and compliance roles operate separately.',
      'KYC/CDD workflow: user verification levels, manual review, restrictions and limits are supported.',
      'Issues Desk: disputes are linked to transaction records with evidence, policy actions, SLA handling and maker-checker outcomes.',
      'Ledger/reconciliation: collection and payout events can be reconciled against partner statements.',
      'Audit trail: staff account creation, KYC actions, restrictions, incidents, evidence access and financial workflow actions are logged.',
      'Privacy controls: consent records, data request register, evidence access log and privacy incident register are available.',
      'Callback security: partner callbacks can be protected using shared callback secrets and idempotency handling.',
    ];
  }
  function _partnerPackPriorityGaps(overview){
    const controls = Array.isArray(overview.controls) ? overview.controls : [];
    return controls.filter(c=>!c.ok).sort((a,b)=>(Number(b.weight||1)-Number(a.weight||1))).slice(0,8).map(c=>({ label:c.label, category:c.category, detail:c.detail, action:c.action, weight:c.weight }));
  }
  function _buildPartnerPack(req){
    const overview = _complianceOverview();
    const pilot = _partnerPackPilotMetrics();
    const gaps = _partnerPackPriorityGaps(overview);
    const docs = complianceDocs.map(d=>({ id:d.id, title:d.title, version:d.version, path:d.path, updatedAt:d.updatedAt }));
    const staff = _staffBreakdown();
    const kyc = _kycBreakdown();
    const incidents = (globalThis.__tpComplianceIncidents || []).slice(-200);
    const openIncidents = incidents.filter(i=>String(i.status||'open').toLowerCase()!=='closed').length;
    return {
      ok:true,
      packageVersion:'1.6-partner-pack',
      generatedAt: nowIso(),
      generatedBy: { phone: req.user.phone, role: req.user.role },
      product: {
        name:'TutoPay',
        legalWorkingName:'TutoPay Escrow Services / SafePay Zambia',
        stage: APP_STAGE,
        model:'Non-custodial marketplace transaction workflow over licensed PSP rails',
        oneLine:'TutoPay helps buyers and sellers trade more safely by recording evidence, confirmations, disputes, release/refund decisions and reconciliation while licensed partners move funds.'
      },
      regulatoryPositioning: {
        fundsCustody:'TutoPay does not custody customer funds.',
        partnerRole:'Licensed PSP/mobile-money/bank partners process collections, settlement, payouts, refunds and reversals.',
        tutopayRole:'TutoPay manages transaction workflow, verification, evidence capture, delivery/collection confirmation, dispute handling, audit records and reconciliation references.',
        recommendedLanguage:'TutoPay operates as a non-custodial transaction workflow and trust layer using licensed payment partners for money movement.'
      },
      deployment: {
        appStage: APP_STAGE,
        demoMode: DEMO_MODE,
        paymentsMode: PAYMENTS_MODE,
        publicApiBase: PUBLIC_API_BASE,
        dbReady,
        dbEnabled: dbEnabled(),
        strictDbMode: STRICT_DB_MODE,
        cloudStorageConfigured: !!(process.env.CLOUDINARY_URL || (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET)),
        callbackSecretConfigured: !!(process.env.MTN_CALLBACK_SECRET || process.env.AIRTEL_CALLBACK_SECRET || process.env.CALLBACK_SHARED_SECRET),
      },
      readiness: {
        score: overview.readinessScore,
        band: overview.readinessBand,
        counts: overview.counts,
        staff,
        kyc,
        priorityGaps: gaps,
        controls: overview.controls,
      },
      pilotEvidence: pilot,
      governanceAndControls: _partnerPackRiskControls(),
      documents: docs,
      incidents: { recent: incidents, openCount: openIncidents },
      exports: [
        { label:'Full JSON partner pack', endpoint:'/api/admin/partner-pack/export' },
        { label:'Concept note text', endpoint:'/api/admin/partner-pack/concept-note.txt' },
        { label:'PSP introduction letter text', endpoint:'/api/admin/partner-pack/psp-letter.txt' },
        { label:'Readiness checklist CSV', endpoint:'/api/admin/partner-pack/checklist.csv' }
      ],
      nextSteps: [
        'Keep the pilot controlled and documented before any real-money scale-up.',
        'Get a written PSP/merchant partnership pathway before live public launch.',
        'Use Postgres/strict DB mode and private evidence storage before production money movement.',
        'Resolve or document open disputes, incidents and unreconciled money events before partner reviews.',
        'Prepare formal AML/CFT, data protection, consumer complaints and settlement procedures for legal/PSP review.'
      ],
      note:'Generated for PSP, investor and BoZ pre-engagement discussions. Review with legal/compliance advisers before external submission.'
    };
  }
  function _conceptNoteText(pkg){
    const gaps = (pkg.readiness.priorityGaps || []).map((g,i)=>`${i+1}. ${g.label}: ${g.action}`).join('\n') || 'No major priority gaps returned by the readiness console.';
    const docs = (pkg.documents || []).map(d=>`- ${d.title} (${d.version})`).join('\n');
    return `TUTOPAY CONCEPT NOTE\nGenerated: ${pkg.generatedAt}\n\n1. Product Summary\n${pkg.product.oneLine}\n\n2. Regulatory Positioning\n${pkg.regulatoryPositioning.recommendedLanguage}\nFunds custody: ${pkg.regulatoryPositioning.fundsCustody}\nPartner role: ${pkg.regulatoryPositioning.partnerRole}\nTutoPay role: ${pkg.regulatoryPositioning.tutopayRole}\n\n3. Current Readiness\nReadiness score: ${pkg.readiness.score}%\nReadiness band: ${pkg.readiness.band}\nDeployment stage: ${pkg.deployment.appStage}\nPayments mode: ${pkg.deployment.paymentsMode}\nDatabase ready: ${pkg.deployment.dbReady}\nCallback secret configured: ${pkg.deployment.callbackSecretConfigured}\n\n4. Pilot Evidence Snapshot\nRegistered users: ${pkg.pilotEvidence.users.total}\nBuyers: ${pkg.pilotEvidence.users.buyers}\nSellers: ${pkg.pilotEvidence.users.sellers}\nTransactions: ${pkg.pilotEvidence.transactions.total}\nCompleted transactions: ${pkg.pilotEvidence.transactions.completed}\nDisputed transactions: ${pkg.pilotEvidence.transactions.disputed}\nTotal value represented: ZMW ${pkg.pilotEvidence.transactions.totalValue}\n\n5. Key Controls\n${pkg.governanceAndControls.map(x=>'- '+x).join('\n')}\n\n6. Policy Pack\n${docs}\n\n7. Priority Gaps / Action Plan\n${gaps}\n\n8. Requested Engagement\nTutoPay seeks discussion with licensed PSP/payment partners on a controlled pilot model where the partner executes money movement while TutoPay manages the marketplace workflow, verification, evidence, disputes, records and reconciliation references.\n\nNote: This concept note is generated from the live TutoPay partner-pack console and should be reviewed before external submission.\n`;
  }
  function _pspLetterText(pkg){
    return `Dear PSP Partnership Team,\n\nRE: Request for Partnership Discussion - TutoPay Non-Custodial Marketplace Transaction Workflow\n\nI am writing to request a partnership discussion regarding TutoPay, a Zambian marketplace transaction workflow platform designed to help buyers and sellers trade more safely over licensed payment rails.\n\nTutoPay's intended model is non-custodial. Customer funds would be collected, settled, refunded, reversed and/or paid out by a licensed PSP/mobile-money/banking partner. TutoPay would manage the transaction workflow around those rails, including buyer/seller records, evidence capture, collection or delivery confirmation, dispute handling, audit trails, reconciliation references and compliance escalation.\n\nCurrent readiness snapshot:\n- Readiness score: ${pkg.readiness.score}% (${pkg.readiness.band})\n- Deployment stage: ${pkg.deployment.appStage}\n- Payments mode: ${pkg.deployment.paymentsMode}\n- Registered users: ${pkg.pilotEvidence.users.total}\n- Transactions recorded: ${pkg.pilotEvidence.transactions.total}\n- Total transaction value represented: ZMW ${pkg.pilotEvidence.transactions.totalValue}\n\nTutoPay has internal consoles for admin, risk, compliance, accounts/finance reconciliation, privacy/data protection and pilot metrics. The platform also maintains policy documents covering terms, privacy, KYC/CDD, AML/CFT controls, disputes, data retention, incident response and PSP settlement/reconciliation procedures.\n\nI would appreciate an opportunity to present the workflow and discuss how TutoPay could run a controlled pilot using your licensed payment rails, settlement rules, compliance expectations and technical integration requirements.\n\nYours faithfully,\n\nMaxwell Sambo\nFounder / Promoter, TutoPay\n`;
  }

  app.get('/api/admin/partner-pack/overview', requireAuth, _partnerPackGate, (req,res)=>{
    const pkg = _buildPartnerPack(req);
    logAudit(req, 'partner_pack_overview_viewed', { readinessScore: pkg.readiness.score, stage: pkg.deployment.appStage });
    res.json({ ok:true, generatedAt:pkg.generatedAt, product:pkg.product, deployment:pkg.deployment, readiness:pkg.readiness, pilotEvidence:pkg.pilotEvidence, documents:pkg.documents, exports:pkg.exports, nextSteps:pkg.nextSteps, note:pkg.note });
  });
  app.get('/api/admin/partner-pack/export', requireAuth, _partnerPackGate, (req,res)=>{
    const pkg = _buildPartnerPack(req);
    logAudit(req, 'partner_pack_exported', { readinessScore: pkg.readiness.score, format:'json' });
    res.json(pkg);
  });
  app.get('/api/admin/partner-pack/concept-note.txt', requireAuth, _partnerPackGate, (req,res)=>{
    const pkg = _buildPartnerPack(req);
    logAudit(req, 'partner_pack_concept_note_downloaded', { readinessScore: pkg.readiness.score });
    res.setHeader('Content-Type','text/plain; charset=utf-8');
    res.setHeader('Content-Disposition','attachment; filename="tutopay-concept-note.txt"');
    res.end(_conceptNoteText(pkg));
  });
  app.get('/api/admin/partner-pack/psp-letter.txt', requireAuth, _partnerPackGate, (req,res)=>{
    const pkg = _buildPartnerPack(req);
    logAudit(req, 'partner_pack_psp_letter_downloaded', { readinessScore: pkg.readiness.score });
    res.setHeader('Content-Type','text/plain; charset=utf-8');
    res.setHeader('Content-Disposition','attachment; filename="tutopay-psp-introduction-letter.txt"');
    res.end(_pspLetterText(pkg));
  });
  app.get('/api/admin/partner-pack/checklist.csv', requireAuth, _partnerPackGate, (req,res)=>{
    const pkg = _buildPartnerPack(req);
    const rows = [['category','control','status','detail','action','weight']];
    (pkg.readiness.controls || []).forEach(c => rows.push([c.category||'', c.label||'', c.ok?'READY':'GAP', c.detail||'', c.action||'', c.weight||1]));
    const csv = rows.map(r=>r.map(csvEscape).join(',')).join('\n');
    logAudit(req, 'partner_pack_checklist_downloaded', { readinessScore: pkg.readiness.score });
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition','attachment; filename="tutopay-readiness-checklist.csv"');
    res.end(csv);
  });

  // ---- Issues Desk foundation (Step 7A) ----
  const ISSUE_POLICIES = [
    { code:'RISK-01', label:'Request More Evidence', actionType:'request_more_evidence', nextStatus:'awaiting_customer', template:'Please upload clearer proof (photos, chats, receipts, delivery evidence) within the requested timeframe.' },
    { code:'RISK-02', label:'Freeze & Investigate', actionType:'freeze_transaction', nextStatus:'in_review', template:'Transaction held pending fraud/risk checks. Parties are notified while review is in progress.' },
    { code:'RISK-03', label:'Refund Recommended', actionType:'recommend_refund', nextStatus:'awaiting_admin_approval', template:'Evidence supports refund recommendation. Escalate for authorization and payout reversal handling.' },
    { code:'RISK-04', label:'Reject Complaint Recommended', actionType:'recommend_reject', nextStatus:'awaiting_admin_approval', template:'Evidence does not support complaint claim. Prepare a structured rejection response.' },
    { code:'RISK-05', label:'Escalate to Supervisor', actionType:'escalate_supervisor', nextStatus:'escalated', template:'Case escalated due to severity, repeat pattern, or policy trigger.' },
    { code:'RISK-06', label:'Close Case', actionType:'close_case', nextStatus:'resolved', template:'Issue is resolved and case can be closed with final notes recorded.' }
    ,{ code:'ADM-01', label:'ADMIN: Approve Refund (Execute)', actionType:'admin_execute_refund', nextStatus:'resolved', template:'Admin approval: execute refund outcome (money-moving). Records authorization + closes case.' }
    ,{ code:'ADM-02', label:'ADMIN: Approve Reject (Close)', actionType:'admin_execute_reject', nextStatus:'resolved', template:'Admin approval: reject complaint outcome (money-moving decision) + close case.' }
    ];
  const issueCaseStore = globalThis.__tpIssueCaseStore || (globalThis.__tpIssueCaseStore = new Map()); // caseId -> state/meta

  // ==========================
  // Step 8.4: SLA timers + auto escalation (BoZ ops maturity)
  // ==========================
  function pickSlaHoursFromPriority(priority){
    const p = String(priority||'').toLowerCase().trim();
    if (p === 'critical') return 12;
    if (p === 'high') return 24;
    if (p === 'medium') return 48;
    if (p === 'low') return 72;
    return 24;
  }
  function computeSlaMeta(deadlineIso){
    const now = Date.now();
    const dl = Date.parse(deadlineIso || '') || 0;
    const remainingMs = dl - now;
    return {
      slaRemainingMs: remainingMs,
      slaOverdue: remainingMs < 0,
      slaRemainingHuman: remainingMs < 0
        ? `overdue ${Math.ceil(Math.abs(remainingMs)/60000)}m`
        : `${Math.floor(remainingMs/3600000)}h ${Math.floor((remainingMs%3600000)/60000)}m`
    };
  }
  async function logSystemIssueAction(caseId, txId, actionType, note, extra){
    const entry = {
      id: uuid(),
      timestamp: nowIso(),
      caseId,
      txId,
      actionType,
      policyCode: 'SYS-SLA',
      nextStatus: (extra && extra.nextStatus) ? extra.nextStatus : undefined,
      note: note || '',
      actorPhone: 'SYSTEM',
      actorRole: 'system'
    };
    try { issueActions.push(entry); } catch(e){}
    try { await dbInsertIssueAction(entry); } catch(e){}
    return entry;
  }
  async function runSlaEscalationSweep(){
    try{
      const now = Date.now();
      for (const [caseId, st] of issueCaseStore.entries()){
        if (!st) continue;
        const status = String(st.status||'').toLowerCase();
        if (status === 'resolved' || status === 'closed') continue;

        if (!st.slaHours) st.slaHours = pickSlaHoursFromPriority(st.priority);
        if (!st.slaDeadlineAt){
          const createdMs = Date.parse(st.createdAt||'') || now;
          st.slaDeadlineAt = new Date(createdMs + (Number(st.slaHours)||24)*3600000).toISOString();
        }

        const deadline = Date.parse(st.slaDeadlineAt) || 0;
        if (!deadline) continue;

        const overdueMs = Math.max(0, now - deadline);
        const prevLevel = Number(st.slaEscalationLevel || 0);
        let nextLevel = prevLevel;
        let nextPriority = st.priority;

        if (overdueMs > 0 && prevLevel < 1){
          nextLevel = 1;
          nextPriority = 'high';
        }
        if (overdueMs > 24*3600000 && prevLevel < 2){
          nextLevel = 2;
          nextPriority = 'critical';
        }

        st.slaEscalationLevel = nextLevel;
        const meta = computeSlaMeta(st.slaDeadlineAt);
        st.slaRemainingMs = meta.slaRemainingMs;
        st.slaOverdue = meta.slaOverdue;

        if (nextLevel !== prevLevel){
          st.priority = nextPriority;
          st.escalatedAt = nowIso();
          st.tags = Array.isArray(st.tags) ? st.tags : [];
          if (!st.tags.includes('sla_escalated')) st.tags.push('sla_escalated');
          const txId = st.txId || (caseId.startsWith('CASE-') ? caseId.slice(5) : null);

          await logSystemIssueAction(caseId, txId, 'auto_escalate_overdue',
            `Auto escalated to ${nextPriority} (level ${nextLevel}) due to SLA overdue.`,
            { nextStatus: st.status }
          );
        }

        try { await dbUpsertIssueCase(st); } catch(e){}
      }
    }catch(e){}
  }

  // Run every 5 minutes (lightweight)
  setInterval(runSlaEscalationSweep, 5*60*1000);
  setTimeout(runSlaEscalationSweep, 15*1000);


  const issueActions = globalThis.__tpIssueActions || (globalThis.__tpIssueActions = []); // append-only action log

  function issuesTxs(){ return (typeof transactions !== 'undefined' && Array.isArray(transactions)) ? transactions : (globalThis.transactions||[]); }

  function isIssuesDeskRole(role) {
    return isIssuesDeskRoleGlobal(role);
  }
  
  function isAccountingRole(role) {
    const r = String(role || '').toLowerCase();
    return r === 'admin' || r === 'accounts_agent' || r === 'accounts' || r === 'finance_agent';
  }
  function requireAccounting(req,res,next){
    if (!req.user || !isAccountingRole(req.user.role)) return res.status(403).json({ error:'Accounting only' });
    return next();
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
        txId: tx.id,
        createdAt: openedAt,
        updatedAt: openedAt,
        status: 'new',
        priority: calcPriority(tx),
        assignedTo: null,
        assignedAt: null,
        assignedRole: null,
        complaintCategory: String(tx?.dispute?.type || tx?.dispute?.reasonCode || 'general').toLowerCase(),
        severity: calcPriority(tx),
        slaHours: pickSlaHoursFromPriority(calcPriority(tx)),
        slaDeadlineAt: new Date(createdTs + 24*60*60*1000).toISOString(),
        partnerActionRequired: false,
        partnerActionType: null,
        outcomeCode: null,
        appealStatus: 'none',
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
      complaintCategory: st.complaintCategory || String(tx?.dispute?.type || tx?.dispute?.reasonCode || 'general').toLowerCase(),
      severity: st.severity || st.priority || calcPriority(tx),
      sourceType: st.sourceType,
      sourceRef: st.sourceRef,
      status: latestAction?.nextStatus || st.status || 'new',
      priority: st.priority || calcPriority(tx),
      assignedTo: st.assignedTo || null,
      assignedAt: st.assignedAt || null,
      assignedRole: st.assignedRole || null,
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
      partnerActionRequired: !!st.partnerActionRequired,
      partnerActionType: st.partnerActionType || null,
      outcomeCode: st.outcomeCode || null,
      appealStatus: st.appealStatus || 'none',
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
    const evidence = Array.isArray(tx.disputeDocs) ? tx.disputeDocs.map((d, idx) => {
      const docId = d.id || `${c.caseId}-doc-${idx+1}`;
      const urlPath = d.urlPath || (d.url && String(d.url).startsWith('/uploads/') ? d.url : null) || null;
      const directUrl = d.url
        ? (String(d.url).startsWith('http') ? String(d.url) : `${PUBLIC_API_BASE}${String(d.url)}`)
        : (urlPath ? `${PUBLIC_API_BASE}${urlPath}` : null);

      // Future-proof: authenticated streaming endpoint (UI can use fetch + Authorization if desired)
      const apiUrl = `${PUBLIC_API_BASE}/api/issues/cases/${encodeURIComponent(String(c.caseId))}/evidence/${encodeURIComponent(String(docId))}`;

      return {
        id: docId,
        name: d.name || d.originalname || d.filename || `evidence-${idx+1}`,
        // Keep 'url' as direct URL so clicking "Open file" works in a new tab (no auth headers)
        url: directUrl,
        directUrl,
        apiUrl,
        uploadedAt: d.uploadedAt || d.createdAt || null,
        uploadedBy: d.uploadedByPhone || d.uploadedBy || d.byPhone || d.by || null,
        mimeType: d.mimetype || d.mimeType || null,
        size: d.size || null,
      };
    }) : [];
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
    st.assignedRole = String(req.user.role || '').toLowerCase();
    st.updatedAt = nowIso();
    try { await dbUpsertIssueCase(st); } catch(e){}
    logAudit(req, 'issues_case_assign', { caseId: got.c.caseId, txId: got.tx.id, assignedTo: toPhone });
    res.json({ ok:true, case: ensureIssueCaseForTx(got.tx) });
  });

  
  function applyAdminIssueOutcome(req, tx, outcome, note) {
    const now = nowIso();
    tx.dispute = tx.dispute || {};
    tx.dispute.adminDecision = {
      outcome,
      note: note || '',
      decidedAt: now,
      byPhone: req.user.phone,
    };
    // Freeze lifted once decision executed
    tx.riskHold = false;
    tx.riskHoldAt = tx.riskHoldAt || null;

    if (outcome === 'refund') {
      tx.dispute.status = 'admin_approved_refund';
      tx.dispute.resolvedAt = now;
      tx.disputeActive = false;
      tx.status = 'refunded';
      tx.payoutReconciled = true;
      markPartnerProcessing(tx, {
        outcome: 'refund',
        partnerActionRequired: true,
        refundStatus: 'authorized_pending_partner_execution',
        lastOutcomeAt: now,
      });
      recordLedger(req, tx, 'refund_completed', { notes: 'Admin authorized refund outcome; partner execution required' });
    } else if (outcome === 'reject') {
      tx.dispute.status = 'admin_rejected_complaint';
      tx.dispute.resolvedAt = now;
      tx.disputeActive = false;
      // Keep tx.status unchanged; complaint closed
      markPartnerProcessing(tx, {
        outcome: 'reject',
        partnerActionRequired: false,
        lastOutcomeAt: now,
      });
      recordLedger(req, tx, 'dispute_rejected', { notes: 'Admin rejected complaint via Issues Desk' });
    }
  }

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
    // Separation of duties: only admin can execute money-moving outcomes
    if (String(actionType).startsWith('admin_execute_') && String(req.user.role) !== 'admin') {
      return res.status(403).json({ error:'Only admin can execute approvals.' });
    }

    const allowed = new Set(ISSUE_POLICIES.map(p=>p.actionType));
    if (!allowed.has(actionType)) return res.status(400).json({ error:'Unsupported actionType' });
    const st = issueCaseStore.get(got.c.caseId);
    if (String(actionType).startsWith('admin_execute_') && st && st.recommendation && String(st.recommendation.byPhone || '') === String(req.user.phone || '')) {
      return res.status(403).json({ error:'Maker-checker control: the same staff member cannot both recommend and execute the final outcome.' });
    }
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

    // Apply state transition before persisting
    st.status = nextStatus;
    st.updatedAt = entry.timestamp;
    st.lastActionType = actionType;
    st.lastActionAt = entry.timestamp;
    st.lastActionBy = req.user.phone;

    // Store recommendation/approval metadata for governance
    if (actionType === 'recommend_refund') {
      st.pendingAdminApproval = true;
      st.partnerActionRequired = true;
      st.partnerActionType = 'refund';
      st.outcomeCode = 'refund_recommended';
      st.recommendation = { outcome:'refund', policyCode, note: entry.note, at: entry.timestamp, byPhone: req.user.phone, byRole: req.user.role };
    } else if (actionType === 'recommend_reject') {
      st.pendingAdminApproval = true;
      st.partnerActionRequired = false;
      st.partnerActionType = null;
      st.outcomeCode = 'reject_recommended';
      st.recommendation = { outcome:'reject', policyCode, note: entry.note, at: entry.timestamp, byPhone: req.user.phone, byRole: req.user.role };
    }
    if (String(actionType).startsWith('admin_execute_')) {
      st.pendingAdminApproval = false;
      st.approval = { actionType, policyCode, note: entry.note, at: entry.timestamp, byPhone: req.user.phone, byRole: req.user.role };
      st.outcomeCode = actionType === 'admin_execute_refund' ? 'refund_authorized' : 'complaint_rejected';
      st.partnerActionRequired = actionType === 'admin_execute_refund';
      st.partnerActionType = actionType === 'admin_execute_refund' ? 'refund' : null;
    }

    try { await dbInsertIssueAction(entry); } catch(e){}
    try { await dbUpsertIssueCase(st); } catch(e){}

    if (String(actionType).startsWith('admin_execute_')) {
      const outcome = actionType === 'admin_execute_refund' ? 'refund' : (actionType === 'admin_execute_reject' ? 'reject' : null);
      if (outcome) {
        applyAdminIssueOutcome(req, got.tx, outcome, entry.note);
        st.executedOutcome = outcome;
        st.executedAt = entry.timestamp;
        st.closedAt = entry.timestamp;
        st.status = 'resolved';
      }
    }

        if (actionType === 'freeze_transaction') {
      got.tx.riskHold = true;
      got.tx.riskHoldAt = entry.timestamp;
    }
    if (actionType === 'close_case') {
      st.closedAt = entry.timestamp;
      if (got.tx.dispute && !got.tx.dispute.resolvedAt) got.tx.dispute.resolvedAt = entry.timestamp;
    }
    if (dbEnabled()) { dbUpsertTransaction(got.tx).catch(()=>{}); }

    logAudit(req, 'issues_case_action', { caseId: got.c.caseId, txId: got.tx.id, actionType, policyCode, nextStatus });
    res.json({ ok:true, action: entry, case: ensureIssueCaseForTx(got.tx) });
  });

  // --- Evidence streaming endpoint (optional, safer than public /uploads) ---
  // NOTE: Frontend currently uses directUrl in evidence.url, but this endpoint allows future auth-based viewing.
  app.get('/api/issues/cases/:caseId/evidence/:docId', requireAuth, requireIssuesDesk, (req,res)=>{
    const got = getIssueCaseAndTx(req.params.caseId);
    if (got.err) return res.status(404).json({ error: got.err });
    const tx = got.tx;
    const docId = String(req.params.docId || '').trim();
    const docs = Array.isArray(tx.disputeDocs) ? tx.disputeDocs : [];
    const doc = docs.find((d, idx) => String(d.id || `${got.c.caseId}-doc-${idx+1}`) === docId) || null;
    if (!doc) return res.status(404).json({ error: 'Evidence file not found' });

    try {
      if (globalThis.__tpLogEvidenceAccess) {
        globalThis.__tpLogEvidenceAccess(req, {
          evidenceType: 'dispute',
          source: 'issues_case_evidence',
          txId: tx.id,
          caseId: got.c.caseId,
          docId,
          docName: doc.name || doc.originalname || doc.filename || null,
          mimetype: doc.mimetype || null,
        });
      }
    } catch (_) {}

    if (doc.url && String(doc.url).startsWith('http')) {
      return res.redirect(String(doc.url));
    }

    const filename = String(doc.filename || '').trim();
    if (!filename) return res.status(404).json({ error: 'Evidence filename missing' });

    const fp = path.join(uploadDir, filename);
    if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Evidence file missing on server' });

    res.setHeader('Content-Type', doc.mimetype || 'application/octet-stream');
    // Inline view for images/pdf; download for others
    const disp = (String(doc.mimetype||'').startsWith('image/') || String(doc.mimetype||'').includes('pdf')) ? 'inline' : 'attachment';
    res.setHeader('Content-Disposition', `${disp}; filename="${(doc.originalname||doc.name||filename).replace(/"/g,'')}"`);
    return res.sendFile(fp);
  });

  // --- Admin approval helpers (so the UI can show explicit Approve/Reject buttons) ---
  function requireAdmin(req,res,next){
    if (!req.user || String(req.user.role) !== 'admin') return res.status(403).json({ error:'Admin only' });
    return next();
  }

  // List pending admin approvals
  app.get('/api/issues/approvals', requireAuth, requireAdmin, (req,res)=>{
    const rows = issueCaseList().filter(r => !!r.pendingAdminApproval || String(r.status||'') === 'awaiting_admin_approval');
    res.json({ ok:true, total: rows.length, cases: rows.slice(0, 500) });
  });

  // Approve the RA recommendation and execute outcome (refund/reject)
  app.post('/api/issues/cases/:caseId/admin/approve', requireAuth, requireAdmin, async (req,res)=>{
    const got = getIssueCaseAndTx(req.params.caseId);
    if (got.err) return res.status(404).json({ error: got.err });
    const st = issueCaseStore.get(got.c.caseId) || got.c;
    const note = String((req.body||{}).note || '').trim();

    const rec = st && st.recommendation ? st.recommendation : null;
    if (!rec || !rec.outcome) return res.status(400).json({ error:'No recommendation found to approve' });

    const outcome = String(rec.outcome).toLowerCase();
    if (String(rec.byPhone || '') === String(req.user.phone || '')) {
      return res.status(403).json({ error:'Maker-checker control: the recommending officer cannot approve the same case.' });
    }
    const actionType = outcome === 'refund' ? 'admin_execute_refund' : (outcome === 'reject' ? 'admin_execute_reject' : '');
    const policyCode = outcome === 'refund' ? 'ADM-01' : (outcome === 'reject' ? 'ADM-02' : '');
    if (!actionType) return res.status(400).json({ error:'Unsupported recommendation outcome' });

    // Reuse the same internal action recorder logic by simulating an action entry
    const entry = {
      id: uuid(),
      timestamp: nowIso(),
      caseId: got.c.caseId,
      txId: got.tx.id,
      actionType,
      policyCode,
      nextStatus: 'resolved',
      note: note || `Admin approved RA recommendation: ${outcome}`,
      byPhone: req.user.phone,
      byRole: req.user.role,
    };
    issueActions.push(entry);

    st.pendingAdminApproval = false;
    st.approval = { actionType, policyCode, note: entry.note, at: entry.timestamp, byPhone: req.user.phone, byRole: req.user.role };
    st.partnerActionRequired = outcome === 'refund';
    st.partnerActionType = outcome === 'refund' ? 'refund' : null;
    st.outcomeCode = outcome === 'refund' ? 'refund_authorized' : 'complaint_rejected';
    st.executedOutcome = outcome;
    st.executedAt = entry.timestamp;
    st.closedAt = entry.timestamp;
    st.status = 'resolved';
    st.updatedAt = entry.timestamp;

    applyAdminIssueOutcome(req, got.tx, outcome, entry.note);

    try { await dbInsertIssueAction(entry); } catch(e){}
    try { await dbUpsertIssueCase(st); } catch(e){}
    if (dbEnabled()) { dbUpsertTransaction(got.tx).catch(()=>{}); }

    logAudit(req, 'issues_admin_approved', { caseId: got.c.caseId, txId: got.tx.id, outcome });
    return res.json({ ok:true, action: entry, case: ensureIssueCaseForTx(got.tx) });
  });

  // Reject the RA recommendation (send back to RA review)
  app.post('/api/issues/cases/:caseId/admin/reject', requireAuth, requireAdmin, async (req,res)=>{
    const got = getIssueCaseAndTx(req.params.caseId);
    if (got.err) return res.status(404).json({ error: got.err });
    const st = issueCaseStore.get(got.c.caseId) || got.c;
    const note = String((req.body||{}).note || '').trim();

    const entry = {
      id: uuid(),
      timestamp: nowIso(),
      caseId: got.c.caseId,
      txId: got.tx.id,
      actionType: 'admin_reject_recommendation',
      policyCode: 'ADM-00',
      nextStatus: 'in_review',
      note: note || 'Admin rejected recommendation; return to RA for further review.',
      byPhone: req.user.phone,
      byRole: req.user.role,
    };
    issueActions.push(entry);

    st.pendingAdminApproval = false;
    st.approvalRejected = { note: entry.note, at: entry.timestamp, byPhone: req.user.phone, byRole: req.user.role };
    st.outcomeCode = 'recommendation_rejected';
    st.status = 'in_review';
    st.updatedAt = entry.timestamp;

    try { await dbInsertIssueAction(entry); } catch(e){}
    try { await dbUpsertIssueCase(st); } catch(e){}

    logAudit(req, 'issues_admin_rejected', { caseId: got.c.caseId, txId: got.tx.id });
    return res.json({ ok:true, action: entry, case: ensureIssueCaseForTx(got.tx) });
  });


})();

/* ===== TutoPay v1.4: Controlled Pilot Metrics backend ===== */
(function TP_PILOT_METRICS_BACKEND_V14(){
  if (globalThis.__tpPilotMetricsBackendV14) return;
  globalThis.__tpPilotMetricsBackendV14 = true;
  function allowed(req){ const r=String((req.user&&req.user.role)||'').toLowerCase(); return r==='admin'||isInternalStaffRole(r); }
  function gate(req,res,next){ if(!req.user||!allowed(req)) return res.status(403).json({error:'Internal staff only'}); next(); }
  const num=v=>{ const n=Number(v); return Number.isFinite(n)?n:0; };
  const money=v=>Math.round(num(v)*100)/100;
  const ms=v=>{ const x=Date.parse(v||''); return Number.isFinite(x)?x:0; };
  const txTime=t=>t.createdAt||t.paidAt||t.updatedAt||t.completedAt||t.releasedAt||'';
  function range(req){
    const f=String((req.query&&req.query.from)||'').trim(), to=String((req.query&&req.query.to)||'').trim();
    let fm=null,tm=null;
    if(f){ const d=new Date(f.length===10?f+'T00:00:00.000Z':f); if(!isNaN(d.getTime())) fm=d.getTime(); }
    if(to){ const d=new Date(to.length===10?to+'T23:59:59.999Z':to); if(!isNaN(d.getTime())) tm=d.getTime(); }
    return {from:fm,to:tm,fromRaw:f||null,toRaw:to||null};
  }
  function inRange(t,r){ const x=ms(t); if(!x) return true; if(r.from&&x<r.from) return false; if(r.to&&x>r.to) return false; return true; }
  function pct(a,b){ b=Math.max(1,num(b)); return Math.max(0,Math.min(100,Math.round(num(a)/b*100))); }
  function roleCount(role){ return users.filter(u=>String((u&&u.role)||'').toLowerCase()===role).length; }
  function active(txs,field){ const s=new Set(); txs.forEach(t=>{ const v=String((t&&t[field])||'').trim(); if(v) s.add(v); }); return s.size; }
  function pilotStatus(t){
    const s=String((t&&t.status)||'').toLowerCase(), p=String((t&&t.paymentStatus)||'').toLowerCase(), d=String((t&&t.disbursement&&t.disbursement.status)||'').toLowerCase();
    if(t&&t.disputeActive) return 'disputed';
    if(s==='completed'||s==='released'||d==='successful') return 'completed';
    if(s.includes('refund')) return 'refund';
    if(s.includes('cancel')) return 'cancelled';
    if(p==='failed'||s==='failed') return 'failed';
    if(p==='paid'||s==='pending'||s==='held') return 'held';
    if(s==='pending_payment'||!p||p==='pending') return 'pending_payment';
    return s||p||'unknown';
  }
  function safeTx(tx){ const t=ensureTxReconDefaults(tx||{}); return {id:t.id,itemCode:t.itemCode||'',buyerPhone:t.buyerPhone||'',sellerPhone:t.sellerPhone||'',amount:money(t.amount),currency:t.currency||'ZMW',status:t.status||'',pilotStatus:pilotStatus(t),paymentStatus:t.paymentStatus||'',paymentProvider:t.paymentProvider||'',collectionReconciled:!!t.collectionReconciled,payoutReconciled:!!t.payoutReconciled,disputeActive:!!t.disputeActive,createdAt:t.createdAt||'',paidAt:t.paidAt||'',updatedAt:t.updatedAt||''}; }
  function flag(ok,label,detail,action,weight){ return {ok:!!ok,label,detail:String(detail||''),action:String(action||''),weight:Number(weight||1)||1}; }
  function score(flags){ const total=flags.reduce((s,f)=>s+(f.weight||1),0)||1, got=flags.reduce((s,f)=>s+(f.ok?(f.weight||1):0),0); return Math.round(got/total*100); }
  function topCats(){ const m=new Map(); (items||[]).forEach(i=>{ const c=String((i&&(i.category||i.itemCategory||i.type))||'Other').trim()||'Other'; m.set(c,(m.get(c)||0)+1); }); return Array.from(m.entries()).map(([category,count])=>({category,count})).sort((a,b)=>b.count-a.count).slice(0,10); }
  function overview(req){
    const r=range(req), txs=(transactions||[]).map(ensureTxReconDefaults).filter(t=>inRange(txTime(t),r));
    const buyers=roleCount('buyer'), sellers=roleCount('seller'), total=txs.length;
    const statuses=txs.reduce((m,t)=>{const s=pilotStatus(t); m[s]=(m[s]||0)+1; return m;},{});
    const completed=statuses.completed||0, openDisputes=txs.filter(t=>t.disputeActive||String(t.status||'').toLowerCase()==='disputed').length;
    const paid=txs.filter(t=>String(t.paymentStatus||'').toLowerCase()==='paid'||['completed','released'].includes(String(t.status||'').toLowerCase()));
    const held=txs.filter(t=>String(t.paymentStatus||'').toLowerCase()==='paid'&&!['completed','released','refunded'].includes(String(t.status||'').toLowerCase()));
    const collectionUnreconciled=paid.filter(t=>!t.collectionReconciled).length;
    const payoutUnreconciled=txs.filter(t=>(String(t.status||'').toLowerCase()==='completed'||String((t.disbursement&&t.disbursement.status)||'').toLowerCase()==='successful')&&!t.payoutReconciled).length;
    const incidents=globalThis.__tpComplianceIncidents||[], openIncidents=incidents.filter(i=>String((i&&i.status)||'open').toLowerCase()!=='closed').length;
    const totalValue=money(txs.reduce((s,t)=>s+num(t.amount),0)), collectedValue=money(paid.reduce((s,t)=>s+num(t.amount),0)), heldValue=money(held.reduce((s,t)=>s+num(t.amount),0)), completedValue=money(txs.filter(t=>pilotStatus(t)==='completed').reduce((s,t)=>s+num(t.amount),0));
    const successRate=total?Math.round(completed/total*100):0, disputeRate=total?Math.round(openDisputes/total*100):0;
    const targetBuyers=num((req.query&&req.query.targetBuyers)||process.env.PILOT_TARGET_BUYERS||100), targetSellers=num((req.query&&req.query.targetSellers)||process.env.PILOT_TARGET_SELLERS||20), targetTransactions=num((req.query&&req.query.targetTransactions)||process.env.PILOT_TARGET_TRANSACTIONS||100), targetValue=num((req.query&&req.query.targetValue)||process.env.PILOT_TARGET_VALUE||50000);
    const progress=[{label:'Registered buyers',current:buyers,target:targetBuyers,percent:pct(buyers,targetBuyers),note:'Public users who can initiate transactions.'},{label:'Registered sellers',current:sellers,target:targetSellers,percent:pct(sellers,targetSellers),note:'Sellers able to list catalogue items.'},{label:'Pilot transactions',current:total,target:targetTransactions,percent:pct(total,targetTransactions),note:'Transactions created in the selected period.'},{label:'Transaction value',current:totalValue,target:targetValue,percent:pct(totalValue,targetValue),note:'Total ZMW value represented by pilot records.'}];
    const flags=[flag(buyers>=Math.min(10,targetBuyers),'Minimum buyer pool started',`${buyers}/${targetBuyers} buyers`,'Register controlled pilot buyers.',1),flag(sellers>=Math.min(5,targetSellers),'Minimum seller pool started',`${sellers}/${targetSellers} sellers`,'Recruit pilot sellers in one narrow category first.',1),flag(total>0,'Transaction workflow has evidence',`${total} transactions`,'Run controlled pilot transactions.',2),flag(successRate>=70||total<5,'Completion rate acceptable',`${successRate}% completed`,'Improve handover, confirmation and payout/release journey.',2),flag(disputeRate<=15,'Dispute rate under watch threshold',`${disputeRate}% open disputes`,'Investigate repeat disputes and friction.',1),flag(collectionUnreconciled===0,'Collections reconciled',`${collectionUnreconciled} unreconciled collections`,'Accounts should reconcile paid transactions against PSP records.',2),flag(payoutUnreconciled===0,'Payout/settlement checks clear',`${payoutUnreconciled} unreconciled payouts`,'Finance should reconcile completed payouts/settlements.',2),flag(openIncidents===0,'No open compliance incidents',`${openIncidents} open incidents`,'Close or document action plans before external reviews.',1),flag(auditLog.length>0,'Audit trail has activity',`${auditLog.length} audit events`,'Continue recording staff and system actions.',1),flag(ledgerEntries.length>0||total===0,'Ledger evidence available',`${ledgerEntries.length} ledger entries`,'Ensure money events write ledger entries.',2)];
    const sc=score(flags);
    return {ok:true,generatedAt:nowIso(),period:{from:r.fromRaw,to:r.toRaw,mode:(r.fromRaw||r.toRaw)?'filtered':'all_time'},targets:{buyers:targetBuyers,sellers:targetSellers,transactions:targetTransactions,value:targetValue},score:sc,band:sc>=85?'Pilot evidence strong':sc>=70?'Pilot evidence moderate':sc>=50?'Pilot evidence early':'Pilot evidence weak',participants:{buyers,sellers,activeBuyers:active(txs,'buyerPhone'),activeSellers:active(txs,'sellerPhone'),verifiedUsers:users.filter(u=>String((u&&u.kycStatus)||'').toLowerCase()==='verified').length,pendingKyc:users.filter(u=>['pending','under_review','needs_more_info'].includes(String((u&&u.kycStatus)||'').toLowerCase())).length},transactions:{total,statuses,completed,openDisputes,successRate,disputeRate},value:{totalValue,collectedValue,heldValue,completedValue,avgTxValue:total?money(totalValue/total):0,currency:'ZMW'},operations:{collectionUnreconciled,payoutUnreconciled,openIncidents,auditEvents:auditLog.length,ledgerEvents:ledgerEntries.length},progress,flags,actionPlan:flags.filter(f=>!f.ok).sort((a,b)=>(b.weight||1)-(a.weight||1)).map(f=>({issue:f.label,action:f.action,detail:f.detail})),topCategories:topCats(),recentTransactions:txs.slice().sort((a,b)=>ms(txTime(b))-ms(txTime(a))).slice(0,20).map(safeTx),note:'Pilot metrics are generated from TutoPay workflow records. Payment processing, settlement, refunds and reversals remain the responsibility of licensed PSP/mobile-money/banking partners.'};
  }
  app.get('/api/admin/pilot/overview', requireAuth, gate, (req,res)=>res.json(overview(req)));
  app.get('/api/admin/pilot/export', requireAuth, gate, (req,res)=>res.json({ok:true,title:'TutoPay Controlled Pilot Evidence Pack',generatedAt:nowIso(),generatedBy:{phone:req.user.phone,role:req.user.role},nonCustodialStatement:'TutoPay manages transaction workflow, evidence, confirmations, disputes, audit records and reconciliation metadata. Customer funds are processed, held, settled, refunded or reversed by licensed PSP/mobile-money/banking partners.',overview:overview(req),controls:{staffSegregation:'Admin, Risk, Accounts, Finance and Compliance roles are separated.',reconciliation:'Collections and payouts can be marked reconciled/unreconciled by authorised accounting/finance staff.',compliance:'Compliance console tracks readiness gaps, KYC review, restrictions and incidents.',audit:'Staff and system actions are captured in audit logs where implemented.'},nextRecommendedEvidence:['Run 20-100 controlled pilot transactions with real sellers and buyers.','Export reconciliation CSV and match records against PSP sandbox/partner statements.','Resolve or document every open dispute and incident before external review.','Attach the compliance policy pack, system architecture and transaction flow diagram to PSP/BoZ submissions.']}));
  const csv=v=>'"'+String(v==null?'':v).replace(/"/g,'""')+'"';
  app.get('/api/admin/pilot/metrics.csv', requireAuth, gate, (req,res)=>{ const o=overview(req); const rows=[['metric','value','note'],['readiness_score',o.score,o.band],['buyers',o.participants.buyers,'Registered buyer accounts'],['sellers',o.participants.sellers,'Registered seller accounts'],['active_buyers',o.participants.activeBuyers,'Buyers appearing in pilot transactions'],['active_sellers',o.participants.activeSellers,'Sellers appearing in pilot transactions'],['transactions_total',o.transactions.total,'Total transaction records'],['success_rate_percent',o.transactions.successRate,'Completed / total transactions'],['dispute_rate_percent',o.transactions.disputeRate,'Open disputes / total transactions'],['total_value_zmw',o.value.totalValue,'Total pilot value'],['collected_value_zmw',o.value.collectedValue,'Paid/collected value'],['held_value_zmw',o.value.heldValue,'Paid but not completed/refunded'],['completed_value_zmw',o.value.completedValue,'Completed/released value'],['unreconciled_collections',o.operations.collectionUnreconciled,'Paid transactions needing collection reconciliation'],['unreconciled_payouts',o.operations.payoutUnreconciled,'Completed payouts needing finance reconciliation'],['open_incidents',o.operations.openIncidents,'Compliance incidents not closed'],['audit_events',o.operations.auditEvents,'Audit log count'],['ledger_events',o.operations.ledgerEvents,'Ledger event count']]; res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition','attachment; filename="tutopay-pilot-metrics.csv"'); res.end(rows.map(r=>r.map(csv).join(',')).join('\n')); });
})();


/* ===== Data Protection + Evidence Privacy Console v1.5 =====
   Adds consent records, data subject request register, evidence access logs,
   privacy incident capture, user export pack, and authenticated evidence routes.
*/
(function(){
  const DATA_RETENTION_DAYS = Number(process.env.DATA_RETENTION_DAYS || 2555); // ~7 years default
  const dataRequests = globalThis.__tpDataRequests || (globalThis.__tpDataRequests = []);
  const evidenceAccessLog = globalThis.__tpEvidenceAccessLog || (globalThis.__tpEvidenceAccessLog = []);

  function roleName(req){ return String((req && req.user && req.user.role) || '').toLowerCase(); }
  function isPrivacyStaffRole(role){
    const r = String(role || '').toLowerCase();
    return r === 'admin' || r === 'compliance_agent' || r === 'compliance_officer';
  }
  function isEvidenceStaffRole(role){
    const r = String(role || '').toLowerCase();
    return r === 'admin' || r === 'risk_agent' || r === 'fraud_agent' || r === 'compliance_agent' || r === 'compliance_officer';
  }
  function requirePrivacyStaff(req,res,next){
    if (!req.user || !isPrivacyStaffRole(req.user.role)) return res.status(403).json({ error:'Admin or Compliance Agent only' });
    return next();
  }
  function sanitizePhone(v){ return String(v || '').trim(); }
  function reqIp(req){ return (req && (req.ip || (req.headers && req.headers['x-forwarded-for']))) || null; }
  function safeUserForPrivacy(u){
    if (!u) return null;
    const profile = u.profile || {};
    const kyc = u.kycProfile || {};
    return {
      id: u.id || null,
      phone: u.phone,
      role: u.role,
      disabled: !!u.disabled,
      kycLevel: getEffectiveKycLevel(u),
      kycStatus: u.kycStatus || 'unsubmitted',
      createdAt: u.createdAt || null,
      profile: {
        displayName: profile.displayName || profile.fullName || profile.firstName || null,
        businessName: profile.businessName || null,
        email: profile.email || null,
        accountKind: profile.accountKind || null,
      },
      kycSummary: {
        fullName: kyc.fullName || null,
        idType: kyc.idType || null,
        idNumber: kyc.idNumber ? maskId(kyc.idNumber) : null,
        businessName: kyc.businessName || null,
        submittedAt: u.kycSubmittedAt || null,
        reviewedAt: u.kycReviewedAt || null,
        reviewedBy: u.kycReviewedBy || null,
        attachmentCount: kycAttachmentEntriesFromProfile(kyc).length,
      },
      consents: normalizeConsentRecord(u),
      complianceRestricted: !!u.complianceRestricted,
      restrictionReason: u.restrictionReason || null,
    };
  }
  function maskId(v){
    const s = String(v || '');
    if (s.length <= 4) return '****';
    return `${s.slice(0,2)}***${s.slice(-2)}`;
  }
  function normalizeConsentRecord(u){
    const c = (u && u.consents) || {};
    const acceptedAt = c.acceptedAt || c.termsAcceptedAt || c.dataProcessingAcceptedAt || (u && u.createdAt) || null;
    return {
      termsAccepted: !!(c.termsAccepted || c.terms || c.termsOfUseAccepted),
      dataProcessingAccepted: !!(c.dataProcessingAccepted || c.privacyAccepted || c.dataConsent),
      nonCustodialModelAcknowledged: !!(c.nonCustodialModelAcknowledged || c.nonCustodialAccepted),
      acceptedAt,
      policyVersion: c.policyVersion || '1.0-partner-demo',
    };
  }
  function countSensitiveEvidence(){
    const kycCount = users.reduce((acc,u)=> acc + kycAttachmentEntriesFromProfile((u && u.kycProfile) || {}).length, 0);
    const disputeCount = transactions.reduce((acc,t)=> acc + (Array.isArray(t && t.disputeDocs) ? t.disputeDocs.length : 0), 0);
    const legacyPublicEvidence = transactions.reduce((acc,t)=>{
      const docs = Array.isArray(t && t.disputeDocs) ? t.disputeDocs : [];
      return acc + docs.filter(d => String(d.urlPath||'').startsWith('/uploads/') || String(d.url||'').includes('/uploads/')).length;
    }, 0);
    return { kycCount, disputeCount, total: kycCount + disputeCount, legacyPublicEvidence };
  }
  function privacyScore(flags){
    const max = flags.reduce((a,f)=>a+(f.weight||1),0) || 1;
    const got = flags.reduce((a,f)=>a+(f.ok ? (f.weight||1) : 0),0);
    return Math.round((got/max)*100);
  }
  async function dbEnsurePrivacySchema(){
    if (!dbEnabled()) return false;
    await _pgPool.query(`
      CREATE TABLE IF NOT EXISTS tutopay_data_requests (
        id TEXT PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        data JSONB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tutopay_evidence_access (
        id TEXT PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        data JSONB NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tutopay_data_requests_ts_idx ON tutopay_data_requests(ts);
      CREATE INDEX IF NOT EXISTS tutopay_evidence_access_ts_idx ON tutopay_evidence_access(ts);
    `);
    return true;
  }
  async function dbInsertDataRequest(row){
    if (!dbEnabled()) return;
    await dbEnsurePrivacySchema();
    await _pgPool.query(`INSERT INTO tutopay_data_requests(id, ts, data) VALUES ($1, $2, $3::jsonb) ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data`, [row.id, new Date(row.createdAt || nowIso()), JSON.stringify(row)]);
  }
  async function dbUpdateDataRequest(row){ return dbInsertDataRequest(row); }
  async function dbListDataRequests(limit=200){
    if (!dbEnabled()) return dataRequests.slice().sort((a,b)=>String(b.createdAt||'').localeCompare(String(a.createdAt||''))).slice(0,limit);
    await dbEnsurePrivacySchema();
    const r = await _pgPool.query(`SELECT data FROM tutopay_data_requests ORDER BY ts DESC LIMIT $1`, [limit]);
    return (r.rows || []).map(x=>x.data);
  }
  async function dbInsertEvidenceAccess(row){
    if (!dbEnabled()) return;
    await dbEnsurePrivacySchema();
    await _pgPool.query(`INSERT INTO tutopay_evidence_access(id, ts, data) VALUES ($1, $2, $3::jsonb) ON CONFLICT (id) DO NOTHING`, [row.id, new Date(row.accessedAt || nowIso()), JSON.stringify(row)]);
  }
  async function dbListEvidenceAccess(limit=300){
    if (!dbEnabled()) return evidenceAccessLog.slice().sort((a,b)=>String(b.accessedAt||'').localeCompare(String(a.accessedAt||''))).slice(0,limit);
    await dbEnsurePrivacySchema();
    const r = await _pgPool.query(`SELECT data FROM tutopay_evidence_access ORDER BY ts DESC LIMIT $1`, [limit]);
    return (r.rows || []).map(x=>x.data);
  }
  function logEvidenceAccess(req, details={}){
    const entry = {
      id: uuid(),
      accessedAt: nowIso(),
      actorPhone: (req && req.user && req.user.phone) || 'system',
      actorRole: (req && req.user && req.user.role) || 'system',
      ip: reqIp(req),
      ...details,
    };
    evidenceAccessLog.push(entry);
    if (evidenceAccessLog.length > 1000) evidenceAccessLog.splice(0, evidenceAccessLog.length - 1000);
    dbInsertEvidenceAccess(entry).catch(()=>{});
    try { logAudit(req, 'privacy_evidence_access', { evidenceType: entry.evidenceType, source: entry.source, txId: entry.txId || null, docId: entry.docId || null, targetPhone: entry.targetPhone || null }); } catch(_){ }
    return entry;
  }
  globalThis.__tpLogEvidenceAccess = logEvidenceAccess;

  function userIsTxParticipant(req, tx){
    if (!req.user || !tx) return false;
    const p = String(req.user.phone || '');
    return p && (String(tx.fromPhone || '') === p || String(tx.toPhone || '') === p || String(tx.buyerPhone || '') === p || String(tx.sellerPhone || '') === p);
  }
  function findTxDoc(txId, docId){
    const tx = transactions.find(t => String(t.id || '') === String(txId || '')) || null;
    if (!tx) return { err:'Transaction not found' };
    const docs = Array.isArray(tx.disputeDocs) ? tx.disputeDocs : [];
    const doc = docs.find((d,idx)=> String(d.id || `${tx.id}-doc-${idx+1}`) === String(docId || '')) || null;
    if (!doc) return { err:'Evidence file not found', tx };
    return { tx, doc };
  }
  function serveEvidenceDoc(req,res,doc){
    if (doc.url && String(doc.url).startsWith('http')) return res.redirect(String(doc.url));
    const filename = String(doc.filename || '').trim();
    if (!filename) return res.status(404).json({ error:'Evidence filename missing' });
    const fp = path.join(uploadDir, filename);
    if (!fs.existsSync(fp)) return res.status(404).json({ error:'Evidence file missing on server' });
    res.setHeader('Content-Type', doc.mimetype || 'application/octet-stream');
    const disp = (String(doc.mimetype||'').startsWith('image/') || String(doc.mimetype||'').includes('pdf')) ? 'inline' : 'attachment';
    res.setHeader('Content-Disposition', `${disp}; filename="${String(doc.originalname||doc.name||filename).replace(/"/g,'')}"`);
    return res.sendFile(fp);
  }

  app.get('/api/privacy/me', requireAuth, async (req,res)=>{
    const user = findUserByPhone(req.user.phone);
    if (!user) return res.status(404).json({ error:'User not found' });
    const mine = (await dbListDataRequests(300)).filter(r => String(r.userPhone||'') === String(req.user.phone||''));
    res.json({ ok:true, user: safeUserForPrivacy(user), dataRequests: mine });
  });

  app.post('/api/privacy/request', requireAuth, async (req,res)=>{
    const body = req.body || {};
    const type = String(body.type || 'access').toLowerCase();
    if (!['access','correction','deletion','export','restriction','objection','other'].includes(type)) return res.status(400).json({ error:'Invalid request type' });
    const row = {
      id: uuid(),
      createdAt: nowIso(),
      updatedAt: nowIso(),
      status: 'open',
      type,
      userPhone: req.user.phone,
      submittedBy: req.user.phone,
      submittedByRole: req.user.role,
      description: String(body.description || '').trim(),
      assignedTo: null,
      notes: [],
    };
    dataRequests.push(row);
    await dbInsertDataRequest(row).catch(()=>{});
    logAudit(req, 'privacy_data_request_created', { id: row.id, type: row.type, userPhone: row.userPhone });
    res.json({ ok:true, request: row });
  });

  app.get('/api/admin/privacy/overview', requireAuth, requirePrivacyStaff, async (req,res)=>{
    const requests = await dbListDataRequests(500).catch(()=>dataRequests);
    const access = await dbListEvidenceAccess(500).catch(()=>evidenceAccessLog);
    const consents = users.map(normalizeConsentRecord);
    const evidence = countSensitiveEvidence();
    const openReqs = requests.filter(r=>!['closed','resolved','rejected'].includes(String(r.status||'open').toLowerCase())).length;
    const privacyIncidents = (globalThis.__tpComplianceIncidents || []).filter(i=>String(i.category||'').toLowerCase().includes('data') || String(i.type||'').toLowerCase().includes('privacy'));
    const openPrivacyIncidents = privacyIncidents.filter(i=>String(i.status||'open').toLowerCase() !== 'closed').length;
    const flags = [
      { label:'Consent captured at signup', ok: users.length === 0 || consents.some(c=>c.termsAccepted && c.dataProcessingAccepted && c.nonCustodialModelAcknowledged), detail:`${consents.filter(c=>c.termsAccepted&&c.dataProcessingAccepted&&c.nonCustodialModelAcknowledged).length}/${users.length} users have full consent record`, action:'Keep terms, privacy and non-custodial acknowledgement mandatory during onboarding.', weight:2 },
      { label:'Data request register active', ok:true, detail:`${requests.length} data requests recorded`, action:'Use the register for correction, deletion, export or restriction requests.', weight:1 },
      { label:'Evidence access logging active', ok:true, detail:`${access.length} sensitive evidence access events logged`, action:'Open evidence through authenticated routes so access is recorded.', weight:2 },
      { label:'Sensitive evidence inventory visible', ok:evidence.total >= 0, detail:`KYC ${evidence.kycCount}, dispute evidence ${evidence.disputeCount}`, action:'Keep KYC and dispute evidence restricted to authorised staff.', weight:1 },
      { label:'Legacy public evidence exposure under control', ok:evidence.legacyPublicEvidence === 0, detail:`${evidence.legacyPublicEvidence} evidence links still reference public /uploads`, action:'Use authenticated evidence routes for dispute/KYC documents. Catalogue images may remain public.', weight:2 },
      { label:'Privacy incident register active', ok:openPrivacyIncidents === 0, detail:`${openPrivacyIncidents} open privacy/data incidents`, action:'Document and close privacy incidents with action taken.', weight:1 },
      { label:'Retention policy defined', ok:DATA_RETENTION_DAYS > 0, detail:`Default retention setting: ${DATA_RETENTION_DAYS} days`, action:'Confirm the period with legal/PSP guidance before live launch.', weight:1 },
    ];
    const score = privacyScore(flags);
    res.json({ ok:true, generatedAt: nowIso(), stage: APP_STAGE, score, band: score>=85?'Privacy posture strong':score>=70?'Privacy posture moderate':score>=50?'Privacy posture early':'Privacy posture weak', retentionDays: DATA_RETENTION_DAYS, counts:{ users: users.length, consentFull: consents.filter(c=>c.termsAccepted&&c.dataProcessingAccepted&&c.nonCustodialModelAcknowledged).length, dataRequests: requests.length, openDataRequests: openReqs, evidenceAccessEvents: access.length, sensitiveEvidenceTotal: evidence.total, kycEvidence: evidence.kycCount, disputeEvidence: evidence.disputeCount, legacyPublicEvidence: evidence.legacyPublicEvidence, privacyIncidents: privacyIncidents.length, openPrivacyIncidents }, flags, recentAccess: access.slice(0,10), recentRequests: requests.slice(0,10), note:'TutoPay should use authenticated evidence access, record consent, maintain a data-request register, and restrict sensitive files to authorised staff.' });
  });

  app.get('/api/admin/privacy/requests', requireAuth, requirePrivacyStaff, async (req,res)=>{
    const limit = Math.max(1, Math.min(500, Number(req.query.limit || 200)));
    const rows = await dbListDataRequests(limit).catch(()=>dataRequests.slice(-limit).reverse());
    res.json({ ok:true, requests: rows });
  });

  app.post('/api/admin/privacy/requests', requireAuth, requirePrivacyStaff, async (req,res)=>{
    const body = req.body || {};
    const userPhone = sanitizePhone(body.userPhone || body.phone);
    if (!userPhone) return res.status(400).json({ error:'userPhone is required' });
    const type = String(body.type || 'access').toLowerCase();
    const row = { id:uuid(), createdAt:nowIso(), updatedAt:nowIso(), status:String(body.status||'open'), type, userPhone, submittedBy:req.user.phone, submittedByRole:req.user.role, description:String(body.description||'').trim(), assignedTo:String(body.assignedTo||req.user.phone||''), notes:[{ at:nowIso(), by:req.user.phone, note:String(body.note||body.description||'Created by staff').trim() }] };
    dataRequests.push(row);
    await dbInsertDataRequest(row).catch(()=>{});
    logAudit(req, 'privacy_staff_data_request_created', { id:row.id, type:row.type, userPhone });
    res.json({ ok:true, request: row });
  });

  app.post('/api/admin/privacy/requests/:id/status', requireAuth, requirePrivacyStaff, async (req,res)=>{
    const id = String(req.params.id||'').trim();
    const rows = await dbListDataRequests(1000).catch(()=>dataRequests);
    const row = rows.find(r=>String(r.id)===id) || dataRequests.find(r=>String(r.id)===id);
    if (!row) return res.status(404).json({ error:'Data request not found' });
    const status = String((req.body||{}).status || '').toLowerCase();
    if (!['open','in_progress','resolved','closed','rejected'].includes(status)) return res.status(400).json({ error:'Invalid status' });
    row.status = status;
    row.updatedAt = nowIso();
    row.closedAt = ['resolved','closed','rejected'].includes(status) ? nowIso() : null;
    row.notes = Array.isArray(row.notes) ? row.notes : [];
    const note = String((req.body||{}).note || '').trim();
    if (note) row.notes.push({ at: nowIso(), by:req.user.phone, note });
    await dbUpdateDataRequest(row).catch(()=>{});
    logAudit(req, 'privacy_data_request_status', { id, status, userPhone: row.userPhone });
    res.json({ ok:true, request: row });
  });

  app.get('/api/admin/privacy/evidence-access', requireAuth, requirePrivacyStaff, async (req,res)=>{
    const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 300)));
    const rows = await dbListEvidenceAccess(limit).catch(()=>evidenceAccessLog.slice(-limit).reverse());
    res.json({ ok:true, access: rows });
  });

  app.get('/api/admin/privacy/users/:phone/export', requireAuth, requirePrivacyStaff, async (req,res)=>{
    const phone = sanitizePhone(req.params.phone);
    const user = findUserByPhone(phone);
    if (!user) return res.status(404).json({ error:'User not found' });
    const userTxs = transactions.filter(t => String(t.fromPhone||t.buyerPhone||'') === phone || String(t.toPhone||t.sellerPhone||'') === phone).map(t => ({ id:t.id, itemCode:t.itemCode||t.code||null, amount:t.amount||0, status:t.status||null, paymentStatus:t.paymentStatus||null, createdAt:t.createdAt||t.startedAt||null }));
    const userReqs = (await dbListDataRequests(500).catch(()=>dataRequests)).filter(r=>String(r.userPhone||'')===phone);
    const access = (await dbListEvidenceAccess(500).catch(()=>evidenceAccessLog)).filter(a=>String(a.targetPhone||'')===phone || String(a.actorPhone||'')===phone);
    logAudit(req, 'privacy_user_export', { targetPhone: phone, txCount: userTxs.length });
    res.json({ ok:true, generatedAt: nowIso(), generatedBy:{ phone:req.user.phone, role:req.user.role }, user: safeUserForPrivacy(user), transactions: userTxs, dataRequests:userReqs, relatedEvidenceAccess:access, retentionDays:DATA_RETENTION_DAYS, note:'This export is an internal data-protection pack for responding to access/correction/export requests. Review before sharing externally.' });
  });

  app.post('/api/admin/privacy/incidents', requireAuth, requirePrivacyStaff, async (req,res)=>{
    const body = req.body || {};
    const incident = { id:uuid(), createdAt:nowIso(), updatedAt:nowIso(), title:String(body.title||'Data protection incident').trim(), severity:String(body.severity||'medium').toLowerCase(), category:'data_protection', type:'privacy', status:'open', description:String(body.description||body.note||'').trim(), createdBy:req.user.phone, createdByRole:req.user.role };
    const incArr = globalThis.__tpComplianceIncidents || (globalThis.__tpComplianceIncidents = []);
    incArr.push(incident);
    if (dbEnabled()) { try { await dbInsertIncident(incident); } catch(_){} }
    logAudit(req, 'privacy_incident_created', { id:incident.id, severity:incident.severity, title:incident.title });
    res.json({ ok:true, incident });
  });

  app.get('/api/evidence/transactions/:txId/:docId', requireAuth, (req,res)=>{
    const got = findTxDoc(req.params.txId, req.params.docId);
    if (got.err) return res.status(404).json({ error: got.err });
    if (!isEvidenceStaffRole(roleName(req)) && !userIsTxParticipant(req, got.tx)) return res.status(403).json({ error:'Not authorised to view this evidence' });
    logEvidenceAccess(req, { evidenceType:'dispute', source:'transaction_evidence', txId:got.tx.id, docId:req.params.docId, docName:got.doc.name||got.doc.originalname||got.doc.filename||null, mimetype:got.doc.mimetype||null });
    return serveEvidenceDoc(req,res,got.doc);
  });

  app.get('/api/admin/privacy/users/:phone/kyc-attachment/:key', requireAuth, requirePrivacyStaff, (req,res)=>{
    const phone = sanitizePhone(req.params.phone);
    const key = String(req.params.key || '').trim();
    const user = findUserByPhone(phone);
    if (!user) return res.status(404).json({ error:'User not found' });
    const kyc = user.kycProfile || {};
    const entries = kycAttachmentEntriesFromProfile(kyc);
    const entry = entries.find(e => String(e.key||'') === key || String(e.label||'') === key);
    if (!entry || !entry.url) return res.status(404).json({ error:'KYC attachment not found' });
    logEvidenceAccess(req, { evidenceType:'kyc', source:'kyc_attachment', targetPhone:phone, docId:key, docName:entry.label||key });
    const u = String(entry.url || '');
    if (u.startsWith('http')) return res.redirect(u);
    if (u.startsWith('/uploads/')) {
      const fp = path.join(uploadDir, path.basename(u));
      if (!fs.existsSync(fp)) return res.status(404).json({ error:'KYC file missing on server' });
      return res.sendFile(fp);
    }
    return res.status(400).json({ error:'Attachment is not viewable through this route' });
  });
})();



/* ===== TutoPay v1.7: Controlled Pilot Onboarding backend =====
   Adds invite-code onboarding, participant tracking, feedback capture,
   and exportable pilot evidence without changing the core payment flow.
*/
(function TP_CONTROLLED_PILOT_ONBOARDING_V17(){
  if (globalThis.__tpControlledPilotOnboardingV17) return;
  globalThis.__tpControlledPilotOnboardingV17 = true;

  const PILOT_INVITES_REQUIRED = String(process.env.PILOT_INVITES_REQUIRED || "false").toLowerCase() === "true";
  const PILOT_DEFAULT_MAX_USES = Math.max(1, Number(process.env.PILOT_DEFAULT_INVITE_USES || 1));
  const pilotInvites = globalThis.__tpPilotInvites || (globalThis.__tpPilotInvites = []);
  const pilotParticipants = globalThis.__tpPilotParticipants || (globalThis.__tpPilotParticipants = []);
  const pilotFeedback = globalThis.__tpPilotFeedback || (globalThis.__tpPilotFeedback = []);
  let pilotDbReady = false;
  let pilotDbLoaded = false;

  function r(req){ return String((req && req.user && req.user.role) || '').toLowerCase().trim(); }
  function isPilotStaff(req){ const role = r(req); return role === 'admin' || role === 'risk_agent' || role === 'fraud_agent' || role === 'compliance_agent' || role === 'compliance_officer' || role === 'accounts_agent' || role === 'finance_agent'; }
  function canWritePilot(req){ const role = r(req); return role === 'admin' || role === 'risk_agent' || role === 'fraud_agent' || role === 'compliance_agent' || role === 'compliance_officer'; }
  function requirePilotStaff(req,res,next){ if(!req.user) return res.status(401).json({error:'Authentication required'}); if(!isPilotStaff(req)) return res.status(403).json({error:'Pilot staff access required'}); next(); }
  function requirePilotWrite(req,res,next){ if(!req.user) return res.status(401).json({error:'Authentication required'}); if(!canWritePilot(req)) return res.status(403).json({error:'Admin, Risk or Compliance access required'}); next(); }
  function clean(v){ return String(v == null ? '' : v).trim(); }
  function phone(v){ return clean(v); }
  function code(v){ return clean(v).toUpperCase().replace(/\s+/g,'-'); }
  function lc(v){ return clean(v).toLowerCase(); }
  function n(v,d=0){ const x=Number(v); return Number.isFinite(x)?x:d; }
  function pct(a,b){ b=n(b); return b>0?Math.round((n(a)/b)*100):0; }
  function arr(x){ return Array.isArray(x) ? x : []; }
  function csvCell(v){ const s=String(v == null ? '' : v); return /[",\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s; }
  function statusOpen(s){ return !['closed','completed','suspended','cancelled','expired','revoked'].includes(lc(s)); }

  function participantName(profile){
    profile = profile || {};
    return clean(profile.fullName || profile.displayName || profile.businessName || profile.firstName || '');
  }
  function participantArea(profile){ return clean(profile.pilotArea || profile.area || profile.location || profile.marketLocation || ''); }
  function participantCategory(profile){ return clean(profile.pilotCategory || profile.category || profile.itemCategory || ''); }

  async function pilotDbEnsure(){
    if (!dbEnabled() || !_pgPool) return false;
    if (pilotDbReady) return true;
    await _pgPool.query(`
      CREATE TABLE IF NOT EXISTS tutopay_pilot_records (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        code TEXT,
        phone TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        data JSONB NOT NULL
      );
      CREATE INDEX IF NOT EXISTS tutopay_pilot_records_kind_idx ON tutopay_pilot_records(kind);
      CREATE INDEX IF NOT EXISTS tutopay_pilot_records_code_idx ON tutopay_pilot_records(code);
      CREATE INDEX IF NOT EXISTS tutopay_pilot_records_phone_idx ON tutopay_pilot_records(phone);
    `);
    pilotDbReady = true;
    return true;
  }
  async function pilotDbLoad(force=false){
    if (!dbEnabled() || !_pgPool) return false;
    await pilotDbEnsure();
    if (pilotDbLoaded && !force) return true;
    const out = await _pgPool.query("SELECT kind, data FROM tutopay_pilot_records ORDER BY updated_at ASC");
    const inv=[], part=[], fb=[];
    for (const row of out.rows || []) {
      if (row.kind === 'invite') inv.push(row.data);
      else if (row.kind === 'participant') part.push(row.data);
      else if (row.kind === 'feedback') fb.push(row.data);
    }
    if (inv.length) { pilotInvites.length = 0; pilotInvites.push(...inv); }
    if (part.length) { pilotParticipants.length = 0; pilotParticipants.push(...part); }
    if (fb.length) { pilotFeedback.length = 0; pilotFeedback.push(...fb); }
    pilotDbLoaded = true;
    return true;
  }
  async function pilotDbUpsert(kind, obj){
    if (!obj || !obj.id || !dbEnabled() || !_pgPool) return;
    await pilotDbEnsure();
    await _pgPool.query(
      "INSERT INTO tutopay_pilot_records (id, kind, code, phone, data, updated_at) VALUES ($1,$2,$3,$4,$5,NOW()) ON CONFLICT (id) DO UPDATE SET kind=EXCLUDED.kind, code=EXCLUDED.code, phone=EXCLUDED.phone, data=EXCLUDED.data, updated_at=NOW()",
      [String(obj.id), kind, obj.code || obj.inviteCode || null, obj.phone || obj.userPhone || null, JSON.stringify(obj)]
    );
  }

  function findInviteByCode(raw){ const c=code(raw); return pilotInvites.find(i => code(i.code) === c) || null; }
  function inviteValid(inv, role, userPhone){
    if (!inv) return { ok:false, error:'Invalid pilot invite code.' };
    if (lc(inv.status || 'active') !== 'active') return { ok:false, error:'This pilot invite is not active.' };
    if (inv.expiresAt && Date.now() > Date.parse(inv.expiresAt)) return { ok:false, error:'This pilot invite has expired.' };
    const maxUses = Math.max(1, n(inv.maxUses, 1));
    const used = Math.max(0, n(inv.usedCount, 0));
    const existingForPhone = pilotParticipants.find(p => code(p.inviteCode) === code(inv.code) && phone(p.phone) === phone(userPhone));
    if (!existingForPhone && used >= maxUses) return { ok:false, error:'This pilot invite has already been used.' };
    const inviteRole = lc(inv.role || 'any');
    const wantedRole = lc(role || 'buyer');
    if (inviteRole !== 'any' && inviteRole !== wantedRole) return { ok:false, error:`This invite is for ${inviteRole} accounts only.` };
    if (inv.targetPhone && phone(inv.targetPhone) !== phone(userPhone)) return { ok:false, error:'This invite is reserved for a different phone number.' };
    return { ok:true };
  }
  function buildParticipant({ req, invite, role, userPhone, profile }){
    const existing = pilotParticipants.find(p => phone(p.phone) === phone(userPhone)) || null;
    const now = nowIso();
    const base = existing || { id: uuid(), createdAt: now };
    base.updatedAt = now;
    base.phone = phone(userPhone);
    base.role = lc(role || (invite && invite.role) || 'buyer');
    base.status = lc(base.status || 'active') === 'pending' ? 'active' : (base.status || 'active');
    base.name = participantName(profile) || base.name || '';
    base.area = participantArea(profile) || base.area || invite.location || '';
    base.category = participantCategory(profile) || base.category || invite.category || '';
    base.businessName = clean((profile || {}).businessName || base.businessName || '');
    base.inviteId = invite ? invite.id : (base.inviteId || null);
    base.inviteCode = invite ? code(invite.code) : (base.inviteCode || null);
    base.consentAccepted = !!((profile || {}).pilotConsentAccepted || base.consentAccepted || (invite && invite.consentAccepted));
    base.consentAcceptedAt = base.consentAcceptedAt || ((profile || {}).pilotConsentAcceptedAt || now);
    base.createdBy = base.createdBy || (req && req.user ? req.user.phone : 'self_signup');
    base.source = base.source || 'invite_signup';
    return base;
  }

  function consumeInviteForSignup({ req, code: rawCode, role, phone: userPhone, profile }){
    const c = code(rawCode || '');
    if (!c) {
      if (PILOT_INVITES_REQUIRED) return { error:'A valid pilot invite code is required for this controlled pilot.', statusCode:403 };
      return { participant:null };
    }
    const invite = findInviteByCode(c);
    const valid = inviteValid(invite, role, userPhone);
    if (!valid.ok) return { error: valid.error, statusCode:400 };
    const existed = pilotParticipants.find(p => phone(p.phone) === phone(userPhone));
    const participant = buildParticipant({ req, invite, role, userPhone, profile });
    if (!existed) {
      pilotParticipants.push(participant);
      invite.usedCount = Math.max(0, n(invite.usedCount, 0)) + 1;
      invite.updatedAt = nowIso();
      invite.lastUsedAt = nowIso();
      invite.lastUsedBy = phone(userPhone);
    } else {
      Object.assign(existed, participant);
    }
    pilotDbUpsert('invite', invite).catch(()=>{});
    pilotDbUpsert('participant', participant).catch(()=>{});
    try { logAudit(req || { ip:null }, 'pilot_invite_consumed', { code:c, phone:phone(userPhone), role, participantId:participant.id }); } catch(_){ }
    return { participant };
  }
  globalThis.__tpPilotConsumeInviteForSignup = consumeInviteForSignup;
  globalThis.__tpPilotInvitesRequired = () => PILOT_INVITES_REQUIRED;

  function makeInviteCode(role, seq){
    const prefix = lc(role) === 'seller' ? 'SELLER' : (lc(role) === 'buyer' ? 'BUYER' : 'PILOT');
    const num = String(seq || (pilotInvites.length + 1)).padStart(3,'0');
    return `${prefix}-PILOT-${num}`;
  }
  function inviteSafe(inv){
    return {
      id: inv.id, code: inv.code, role: inv.role || 'any', label: inv.label || '', status: inv.status || 'active',
      maxUses: n(inv.maxUses, 1), usedCount: n(inv.usedCount, 0), remainingUses: Math.max(0, n(inv.maxUses,1)-n(inv.usedCount,0)),
      targetPhone: inv.targetPhone || '', category: inv.category || '', location: inv.location || '', expiresAt: inv.expiresAt || null,
      createdAt: inv.createdAt || null, createdBy: inv.createdBy || '', lastUsedAt: inv.lastUsedAt || null, lastUsedBy: inv.lastUsedBy || null,
      notes: inv.notes || ''
    };
  }
  function txForPhone(ph){ const p=phone(ph); return transactions.filter(t => phone(t.buyerPhone || t.fromPhone) === p || phone(t.sellerPhone || t.toPhone) === p); }
  function feedbackForPhone(ph){ const p=phone(ph); return pilotFeedback.filter(f => phone(f.phone || f.userPhone) === p); }
  function participantSafe(p){
    const txs = txForPhone(p.phone);
    const fb = feedbackForPhone(p.phone);
    return Object.assign({}, p, { txCount: txs.length, feedbackCount: fb.length, totalValue: txs.reduce((s,t)=>s+n(t.amount,0),0), lastTxAt: txs.map(t=>t.createdAt||t.updatedAt||t.paidAt).filter(Boolean).sort().pop() || null, avgFeedback: fb.length ? Math.round(fb.reduce((s,x)=>s+n(x.overallRating || x.trustRating || x.easeRating,0),0) / fb.length * 10)/10 : null });
  }
  function allParticipants(){
    const byPhone = new Map();
    for (const p of pilotParticipants) byPhone.set(phone(p.phone), Object.assign({}, p));
    for (const u of users) {
      if (u && u.pilotOnboarding && u.pilotOnboarding.phone) {
        const p = Object.assign({}, u.pilotOnboarding, { phone:u.phone, role:u.role, name:(u.profile && (u.profile.displayName || u.profile.fullName || u.profile.businessName)) || u.pilotOnboarding.name || '' });
        byPhone.set(phone(p.phone), Object.assign(byPhone.get(phone(p.phone)) || {}, p));
      }
    }
    return Array.from(byPhone.values()).map(participantSafe);
  }
  function overview(){
    const participants = allParticipants();
    const invites = pilotInvites.map(inviteSafe);
    const sellers = participants.filter(p => lc(p.role)==='seller');
    const buyers = participants.filter(p => lc(p.role)==='buyer');
    const active = participants.filter(p => ['active','pending'].includes(lc(p.status || 'active')));
    const consent = participants.filter(p => !!p.consentAccepted);
    const phones = new Set(participants.map(p=>phone(p.phone)));
    const pilotTxs = transactions.filter(t => phones.has(phone(t.buyerPhone || t.fromPhone)) || phones.has(phone(t.sellerPhone || t.toPhone)));
    const completed = pilotTxs.filter(t => ['completed','released','successful'].includes(lc(t.status || t.pilotStatus || ''))).length;
    const disputed = pilotTxs.filter(t => t.disputeActive || ['disputed','refund_requested'].includes(lc(t.status || ''))).length;
    const fb = pilotFeedback.slice();
    const flags = [
      { label:'Invite-code onboarding active', ok:invites.length>0, detail:`${invites.length} invite codes created`, action:'Generate buyer and seller pilot invite codes.', weight:2 },
      { label:'Pilot seller pool started', ok:sellers.length>=1, detail:`${sellers.length} sellers enrolled`, action:'Recruit at least 5 sellers in one high-trust category.', weight:2 },
      { label:'Pilot buyer pool started', ok:buyers.length>=3, detail:`${buyers.length} buyers enrolled`, action:'Recruit at least 10 controlled buyers.', weight:1 },
      { label:'Pilot consent captured', ok:participants.length===0 || consent.length===participants.length, detail:`${consent.length}/${participants.length} participants have pilot consent`, action:'Require pilot consent when invite codes are used.', weight:2 },
      { label:'Pilot transaction evidence exists', ok:pilotTxs.length>0, detail:`${pilotTxs.length} participant-linked transactions`, action:'Run controlled pilot transactions with invited users.', weight:2 },
      { label:'Feedback evidence collected', ok:fb.length>0 || pilotTxs.length===0, detail:`${fb.length} feedback responses`, action:'Ask participants to submit feedback after transactions.', weight:1 },
      { label:'Disputes under control', ok:disputed<=Math.max(1, Math.ceil(pilotTxs.length*0.2)), detail:`${disputed} disputed/open issue transactions`, action:'Track and resolve pilot disputes before partner review.', weight:1 },
    ];
    const totalWeight = flags.reduce((s,f)=>s+n(f.weight,1),0) || 1;
    const score = Math.round(flags.filter(f=>f.ok).reduce((s,f)=>s+n(f.weight,1),0)*100/totalWeight);
    const avgFeedback = fb.length ? Math.round(fb.reduce((s,x)=>s+n(x.overallRating || x.trustRating || x.easeRating,0),0)/fb.length*10)/10 : null;
    return { ok:true, generatedAt:nowIso(), stage:APP_STAGE, inviteRequired:PILOT_INVITES_REQUIRED, score, band:score>=85?'Pilot onboarding strong':score>=70?'Pilot onboarding moderate':score>=50?'Pilot onboarding early':'Pilot onboarding weak', counts:{ invites:invites.length, activeInvites:invites.filter(i=>i.status==='active').length, participants:participants.length, activeParticipants:active.length, buyers:buyers.length, sellers:sellers.length, consentAccepted:consent.length, feedback:fb.length, participantTransactions:pilotTxs.length, completedTransactions:completed, disputedTransactions:disputed }, feedback:{ total:fb.length, average:avgFeedback, wouldUseAgain:fb.filter(x=>!!x.wouldUseAgain).length, latest:fb.slice(-10).reverse() }, flags, actionPlan:flags.filter(f=>!f.ok).sort((a,b)=>n(b.weight,1)-n(a.weight,1)).map(f=>({ issue:f.label, detail:f.detail, action:f.action })), participants, invites };
  }

  app.get('/api/pilot/invites/:code/validate', async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const inv = findInviteByCode(req.params.code);
    const valid = inviteValid(inv, (req.query && req.query.role) || 'any', (req.query && req.query.phone) || '');
    if (!valid.ok) return res.status(400).json({ ok:false, error:valid.error });
    res.json({ ok:true, invite:inviteSafe(inv), message:'Pilot invite is valid.' });
  });

  app.get('/api/pilot/me', requireAuth, async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const participants = allParticipants();
    const me = participants.find(p=>phone(p.phone)===phone(req.user.phone)) || null;
    res.json({ ok:true, participant:me, feedback: feedbackForPhone(req.user.phone).slice(-10).reverse(), inviteRequired:PILOT_INVITES_REQUIRED });
  });

  app.post('/api/pilot/feedback', requireAuth, async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const body=req.body||{};
    const participant = allParticipants().find(p=>phone(p.phone)===phone(req.user.phone)) || null;
    if (!participant) return res.status(403).json({ error:'Pilot feedback is available to invited pilot participants only.' });
    const entry={ id:uuid(), createdAt:nowIso(), updatedAt:nowIso(), phone:req.user.phone, role:req.user.role, participantId:participant.id || null, transactionId:clean(body.transactionId || body.txId || ''), easeRating:Math.max(1,Math.min(5,n(body.easeRating,0))), trustRating:Math.max(1,Math.min(5,n(body.trustRating,0))), paymentConfidence:Math.max(1,Math.min(5,n(body.paymentConfidence,0))), overallRating:Math.max(1,Math.min(5,n(body.overallRating,0))), wouldUseAgain:!!body.wouldUseAgain, comments:clean(body.comments || body.comment || '').slice(0,2000) };
    pilotFeedback.push(entry);
    if (pilotFeedback.length>5000) pilotFeedback.splice(0,pilotFeedback.length-5000);
    await pilotDbUpsert('feedback', entry).catch(()=>{});
    logAudit(req, 'pilot_feedback_submitted', { feedbackId:entry.id, phone:req.user.phone, overallRating:entry.overallRating, wouldUseAgain:entry.wouldUseAgain });
    res.json({ ok:true, feedback:entry });
  });

  app.get('/api/admin/pilot/onboarding/overview', requireAuth, requirePilotStaff, async (req,res)=>{ await pilotDbLoad().catch(()=>{}); res.json(overview()); });
  app.get('/api/admin/pilot/invites', requireAuth, requirePilotStaff, async (req,res)=>{ await pilotDbLoad().catch(()=>{}); res.json({ ok:true, invites: pilotInvites.map(inviteSafe).reverse() }); });
  app.post('/api/admin/pilot/invites', requireAuth, requirePilotWrite, async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const body=req.body||{};
    const role = ['buyer','seller','any'].includes(lc(body.role)) ? lc(body.role) : 'buyer';
    const custom = code(body.code || '');
    const c = custom || makeInviteCode(role, pilotInvites.length + 1);
    if (findInviteByCode(c)) return res.status(400).json({ error:'Invite code already exists.' });
    const inv={ id:uuid(), code:c, role, label:clean(body.label || `${role} pilot invite`), status:'active', maxUses:Math.max(1,n(body.maxUses,PILOT_DEFAULT_MAX_USES)), usedCount:0, targetPhone:phone(body.targetPhone||''), category:clean(body.category||''), location:clean(body.location||''), expiresAt:body.expiresAt?new Date(body.expiresAt).toISOString():null, notes:clean(body.notes||''), createdAt:nowIso(), updatedAt:nowIso(), createdBy:req.user.phone };
    pilotInvites.push(inv);
    await pilotDbUpsert('invite', inv).catch(()=>{});
    logAudit(req,'pilot_invite_created',{code:inv.code, role:inv.role, maxUses:inv.maxUses});
    res.json({ ok:true, invite:inviteSafe(inv) });
  });
  app.post('/api/admin/pilot/invites/:id/status', requireAuth, requirePilotWrite, async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const inv=pilotInvites.find(i=>String(i.id)===String(req.params.id) || code(i.code)===code(req.params.id));
    if(!inv) return res.status(404).json({ error:'Invite not found' });
    const status=lc((req.body||{}).status || 'active');
    if(!['active','paused','revoked','expired'].includes(status)) return res.status(400).json({ error:'Invalid invite status' });
    inv.status=status; inv.updatedAt=nowIso(); inv.updatedBy=req.user.phone;
    await pilotDbUpsert('invite', inv).catch(()=>{});
    logAudit(req,'pilot_invite_status_update',{code:inv.code,status});
    res.json({ ok:true, invite:inviteSafe(inv) });
  });

  app.get('/api/admin/pilot/participants', requireAuth, requirePilotStaff, async (req,res)=>{ await pilotDbLoad().catch(()=>{}); res.json({ ok:true, participants: allParticipants().sort((a,b)=>String(b.updatedAt||b.createdAt||'').localeCompare(String(a.updatedAt||a.createdAt||''))) }); });
  app.post('/api/admin/pilot/participants', requireAuth, requirePilotWrite, async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const body=req.body||{}; const ph=phone(body.phone||body.userPhone);
    if(!ph) return res.status(400).json({ error:'Phone is required.' });
    const role=['buyer','seller'].includes(lc(body.role))?lc(body.role):'buyer';
    let p=pilotParticipants.find(x=>phone(x.phone)===ph);
    if(!p){ p={ id:uuid(), createdAt:nowIso(), phone:ph, source:'staff_added' }; pilotParticipants.push(p); }
    Object.assign(p,{ updatedAt:nowIso(), role, status:lc(body.status||p.status||'active'), name:clean(body.name||p.name||''), area:clean(body.area||body.location||p.area||''), category:clean(body.category||p.category||''), businessName:clean(body.businessName||p.businessName||''), consentAccepted:!!(body.consentAccepted || p.consentAccepted), consentAcceptedAt:p.consentAcceptedAt || (body.consentAccepted?nowIso():null), createdBy:p.createdBy||req.user.phone, notes:clean(body.notes||p.notes||'') });
    await pilotDbUpsert('participant', p).catch(()=>{});
    const user=findUserByPhone(ph); if(user){ user.pilotOnboarding=p; if(dbEnabled()) dbUpsertUser(user).catch(()=>{}); }
    logAudit(req,'pilot_participant_added',{phone:ph,role,status:p.status});
    res.json({ ok:true, participant:participantSafe(p) });
  });
  app.post('/api/admin/pilot/participants/:id/status', requireAuth, requirePilotWrite, async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const id=String(req.params.id||'');
    const p=pilotParticipants.find(x=>String(x.id)===id || phone(x.phone)===phone(id));
    if(!p) return res.status(404).json({ error:'Participant not found' });
    const status=lc((req.body||{}).status || 'active');
    if(!['pending','active','suspended','completed','withdrawn'].includes(status)) return res.status(400).json({ error:'Invalid participant status' });
    p.status=status; p.updatedAt=nowIso(); p.statusReason=clean((req.body||{}).reason||''); p.updatedBy=req.user.phone;
    await pilotDbUpsert('participant', p).catch(()=>{});
    const user=findUserByPhone(p.phone); if(user){ user.pilotOnboarding=p; if(dbEnabled()) dbUpsertUser(user).catch(()=>{}); }
    logAudit(req,'pilot_participant_status_update',{phone:p.phone,status});
    res.json({ ok:true, participant:participantSafe(p) });
  });

  app.get('/api/admin/pilot/feedback', requireAuth, requirePilotStaff, async (req,res)=>{ await pilotDbLoad().catch(()=>{}); res.json({ ok:true, feedback: pilotFeedback.slice().reverse().slice(0,500) }); });
  app.post('/api/admin/pilot/feedback', requireAuth, requirePilotWrite, async (req,res)=>{
    await pilotDbLoad().catch(()=>{});
    const body=req.body||{}; const ph=phone(body.phone||body.userPhone);
    if(!ph) return res.status(400).json({ error:'Phone is required.' });
    const entry={ id:uuid(), createdAt:nowIso(), updatedAt:nowIso(), phone:ph, role:lc(body.role||''), source:'staff_entered', transactionId:clean(body.transactionId||''), easeRating:n(body.easeRating,0), trustRating:n(body.trustRating,0), paymentConfidence:n(body.paymentConfidence,0), overallRating:n(body.overallRating,0), wouldUseAgain:!!body.wouldUseAgain, comments:clean(body.comments||'').slice(0,2000), createdBy:req.user.phone };
    pilotFeedback.push(entry); await pilotDbUpsert('feedback',entry).catch(()=>{}); logAudit(req,'pilot_feedback_staff_added',{phone:ph,feedbackId:entry.id}); res.json({ ok:true, feedback:entry });
  });

  app.get('/api/admin/pilot/onboarding/export', requireAuth, requirePilotStaff, async (req,res)=>{ await pilotDbLoad().catch(()=>{}); const o=overview(); logAudit(req,'pilot_onboarding_exported',{participants:o.counts.participants,invites:o.counts.invites}); res.json({ ok:true, title:'TutoPay Controlled Pilot Onboarding Evidence Pack', generatedAt:nowIso(), generatedBy:{phone:req.user.phone,role:req.user.role}, nonCustodialStatement:'TutoPay manages participant onboarding, transaction workflow, evidence, confirmations, disputes, audit records and reconciliation metadata. Customer funds remain processed, held, settled, refunded or reversed by licensed PSP/mobile-money/banking partners.', overview:o, invites:o.invites, participants:o.participants, feedback:pilotFeedback.slice(-1000), nextRecommendedEvidence:['Recruit a balanced pool of buyer and seller participants through invite codes.','Collect pilot consent and feedback from every participant.','Run controlled transactions and reconcile against PSP records.','Export pilot onboarding and pilot metrics packs for PSP/investor discussions.'] }); });
  app.get('/api/admin/pilot/onboarding.csv', requireAuth, requirePilotStaff, async (req,res)=>{ await pilotDbLoad().catch(()=>{}); const rows=[['type','phone_or_code','role','status','name_or_label','area','category','consent','uses_or_tx','feedback_count','created_at']]; for(const i of pilotInvites.map(inviteSafe)) rows.push(['invite',i.code,i.role,i.status,i.label,i.location,i.category,'',`${i.usedCount}/${i.maxUses}`,'',i.createdAt||'']); for(const p of allParticipants()) rows.push(['participant',p.phone,p.role,p.status,p.name||'',p.area||'',p.category||'',p.consentAccepted?'yes':'no',p.txCount||0,p.feedbackCount||0,p.createdAt||'']); res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition','attachment; filename="tutopay-pilot-onboarding.csv"'); res.end(rows.map(row=>row.map(csvCell).join(',')).join('\n')); });
})();


/* ===== TutoPay v1.8: PSP Integration Test Console + Settlement Simulation backend ===== */
(function TP_PSP_INTEGRATION_BACKEND_V18(){
  const pspTestRuns = [];

  function pspRoleAllowed(role){
    const r = String(role || '').toLowerCase();
    return r === 'admin' || r === 'accounts_agent' || r === 'accounts' || r === 'finance_agent' || r === 'compliance_agent' || r === 'compliance_officer';
  }
  function requirePspStaff(req, res, next){
    if (!req.user || !pspRoleAllowed(req.user.role)) return res.status(403).json({ error: 'Admin, Accounts, Finance or Compliance access required.' });
    return next();
  }
  function clean(v, max=500){ return String(v == null ? '' : v).trim().slice(0, max); }
  function num(v, fallback=0){ const n = Number(v); return Number.isFinite(n) ? n : fallback; }
  function money(v){ const n = Number(v || 0); return Math.round(n * 100) / 100; }
  function boolEnv(name){ return !!String(process.env[name] || '').trim(); }
  function statusText(ok){ return ok ? 'configured' : 'missing'; }
  function csvCell(v){ const s=String(v == null ? '' : v); return /[",\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s; }
  function latestRuns(limit=15){ return pspTestRuns.slice().reverse().slice(0, limit); }
  function safeTxMini(tx){
    if(!tx) return null;
    ensureTxReconDefaults(tx);
    return {
      id: tx.id,
      itemCode: tx.itemCode || tx.code || '',
      amount: money(tx.amount),
      currency: tx.currency || MOMO_CURRENCY || 'ZMW',
      buyerPhone: tx.buyerPhone || tx.fromPhone || '',
      sellerPhone: tx.sellerPhone || tx.toPhone || '',
      status: tx.status || '',
      paymentStatus: tx.paymentStatus || '',
      paymentProvider: tx.paymentProvider || '',
      paymentRef: tx.paymentRef || '',
      collectionReconciled: !!tx.collectionReconciled,
      payoutReconciled: !!tx.payoutReconciled,
      disbursementStatus: tx.disbursement && tx.disbursement.status || '',
      createdAt: tx.createdAt || tx.startedAt || null,
      updatedAt: tx.updatedAt || tx.reconUpdatedAt || null
    };
  }
  function txTimeMs(t){ return Date.parse(t.updatedAt || t.createdAt || t.startedAt || t.paidAt || 0) || 0; }
  function envOverview(){
    const mtnCollection = boolEnv('MTN_COLLECTION_SUB_KEY') && boolEnv('MTN_COLLECTION_APIUSER') && boolEnv('MTN_COLLECTION_APIKEY');
    const mtnDisbursement = boolEnv('MTN_DISBURSEMENT_SUB_KEY') && boolEnv('MTN_DISBURSEMENT_APIUSER') && boolEnv('MTN_DISBURSEMENT_APIKEY');
    const airtelCollection = boolEnv('AIRTEL_CLIENT_ID') && boolEnv('AIRTEL_CLIENT_SECRET');
    const callbackSecret = !!(String(MTN_CALLBACK_SECRET || '').trim() || String(AIRTEL_CALLBACK_SECRET || '').trim() || String(process.env.CALLBACK_SHARED_SECRET || '').trim());
    const publicHttps = !!PUBLIC_API_BASE && /^https:\/\//i.test(String(PUBLIC_API_BASE));
    const strictDb = !!STRICT_DB_MODE;
    const railMode = String(PAYMENTS_MODE || 'demo').toLowerCase();
    return {
      appStage: APP_STAGE || 'unset',
      demoMode: !!DEMO_MODE,
      paymentsMode: railMode,
      currency: MOMO_CURRENCY || 'ZMW',
      publicApiBase: PUBLIC_API_BASE || '',
      publicApiHttps: publicHttps,
      dbReady: !!dbReady,
      dbEnabled: dbEnabled(),
      strictDbMode: strictDb,
      callbackUrls: {
        mtnCollection: `${PUBLIC_API_BASE}/api/callbacks/mtn/collection`,
        mtnDisbursement: `${PUBLIC_API_BASE}/api/callbacks/mtn/disbursement`,
        airtelCollection: `${PUBLIC_API_BASE}/api/callbacks/airtel/collection`
      },
      railStatus: {
        mtnCollection: { ready: mtnCollection, status: statusText(mtnCollection), baseUrl: MOMO_BASE_URL || '', subscriptionKey: statusText(boolEnv('MTN_COLLECTION_SUB_KEY')), apiUser: statusText(boolEnv('MTN_COLLECTION_APIUSER')), apiKey: statusText(boolEnv('MTN_COLLECTION_APIKEY')) },
        mtnDisbursement: { ready: mtnDisbursement, status: statusText(mtnDisbursement), baseUrl: MOMO_BASE_URL || '', subscriptionKey: statusText(boolEnv('MTN_DISBURSEMENT_SUB_KEY')), apiUser: statusText(boolEnv('MTN_DISBURSEMENT_APIUSER')), apiKey: statusText(boolEnv('MTN_DISBURSEMENT_APIKEY')) },
        airtelCollection: { ready: airtelCollection, status: statusText(airtelCollection), baseUrl: AIRTEL_BASE_URL || '', clientId: statusText(boolEnv('AIRTEL_CLIENT_ID')), clientSecret: statusText(boolEnv('AIRTEL_CLIENT_SECRET')), country: AIRTEL_COUNTRY || 'ZM', currency: AIRTEL_CURRENCY || 'ZMW' },
        callbackSecurity: { ready: callbackSecret, status: callbackSecret ? 'protected' : 'missing secret', mtnSecret: statusText(!!String(MTN_CALLBACK_SECRET || '').trim()), airtelSecret: statusText(!!String(AIRTEL_CALLBACK_SECRET || '').trim()), sharedSecret: statusText(boolEnv('CALLBACK_SHARED_SECRET')) }
      }
    };
  }
  function financeSnapshot(){
    const txs = (transactions || []).map(t => ensureTxReconDefaults(t || {}));
    const paid = txs.filter(t => ['paid','successful','success'].includes(String(t.paymentStatus || '').toLowerCase()) || !!t.paidAt);
    const completed = txs.filter(t => ['completed','released','seller_paid'].includes(String(t.status || '').toLowerCase()) || ['successful','success'].includes(String(t.disbursement && t.disbursement.status || '').toLowerCase()));
    const unreconciledCollections = paid.filter(t => !t.collectionReconciled).length;
    const unreconciledPayouts = completed.filter(t => !t.payoutReconciled).length;
    const totalValue = txs.reduce((a,t)=>a+num(t.amount,0),0);
    const paidValue = paid.reduce((a,t)=>a+num(t.amount,0),0);
    const completedValue = completed.reduce((a,t)=>a+num(t.amount,0),0);
    const recent = txs.slice().sort((a,b)=>txTimeMs(b)-txTimeMs(a)).slice(0,10).map(safeTxMini);
    return { transactions: txs.length, paid: paid.length, completed: completed.length, totalValue: money(totalValue), paidValue: money(paidValue), completedValue: money(completedValue), unreconciledCollections, unreconciledPayouts, ledgerEvents: ledgerEntries.length, recentTransactions: recent };
  }
  function readinessFlags(){
    const env = envOverview();
    const fin = financeSnapshot();
    const flags = [
      { key:'public_https', label:'HTTPS public API base', ok:!!env.publicApiHttps, detail:env.publicApiBase || 'unset', action:'Set PUBLIC_API_BASE to your HTTPS API domain.' },
      { key:'callback_secret', label:'Callback security configured', ok:!!env.railStatus.callbackSecurity.ready, detail:env.railStatus.callbackSecurity.status, action:'Set MTN_CALLBACK_SECRET/AIRTEL_CALLBACK_SECRET or CALLBACK_SHARED_SECRET.' },
      { key:'collection_config', label:'At least one collection rail configured', ok:!!(env.railStatus.mtnCollection.ready || env.railStatus.airtelCollection.ready || env.paymentsMode === 'demo'), detail:`Mode=${env.paymentsMode}; MTN=${env.railStatus.mtnCollection.status}; Airtel=${env.railStatus.airtelCollection.status}`, action:'Configure MTN/Airtel sandbox credentials or keep demo mode clearly labelled.' },
      { key:'disbursement_config', label:'Payout/disbursement path configured or documented', ok:!!(env.railStatus.mtnDisbursement.ready || env.paymentsMode === 'demo'), detail:`MTN disbursement=${env.railStatus.mtnDisbursement.status}`, action:'Configure disbursement credentials or use documented PSP-led settlement procedure.' },
      { key:'database', label:'Database/startup readiness', ok:!!(env.dbReady && (env.dbEnabled || !env.strictDbMode)), detail:`dbReady=${env.dbReady}; dbEnabled=${env.dbEnabled}; strict=${env.strictDbMode}`, action:'Use Postgres + STRICT_DB_MODE=true before live money movement.' },
      { key:'ledger', label:'Ledger/reconciliation activity', ok:!!(fin.ledgerEvents > 0 || fin.transactions === 0), detail:`${fin.ledgerEvents} ledger events; ${fin.transactions} transactions`, action:'Run controlled transactions and reconcile them against PSP statements.' },
      { key:'unreconciled', label:'No unreconciled PSP money events', ok:fin.unreconciledCollections === 0 && fin.unreconciledPayouts === 0, detail:`${fin.unreconciledCollections} collection and ${fin.unreconciledPayouts} payout checks pending`, action:'Accounts/Finance should reconcile outstanding payment events.' },
      { key:'test_runs', label:'PSP test run history exists', ok:pspTestRuns.length > 0, detail:`${pspTestRuns.length} test/simulation events`, action:'Run at least one config, callback and settlement simulation.' }
    ];
    return flags;
  }
  function score(flags){ if(!flags.length) return 0; return Math.round(flags.filter(f=>f.ok).length / flags.length * 100); }
  function overview(){
    const flags = readinessFlags();
    const sc = score(flags);
    return {
      ok:true,
      generatedAt: nowIso(),
      score: sc,
      band: sc >= 85 ? 'PSP test posture strong' : sc >= 70 ? 'PSP test posture moderate' : sc >= 50 ? 'PSP test posture early' : 'PSP test posture weak',
      nonCustodialStatement:'TutoPay does not hold customer funds. Licensed PSP/mobile-money/bank partners execute collection, settlement, payout, refund and reversal movement; TutoPay tracks workflow, references, callbacks, evidence and reconciliation metadata.',
      environment: envOverview(),
      finance: financeSnapshot(),
      flags,
      gaps: flags.filter(f=>!f.ok).map(f=>({ label:f.label, detail:f.detail, action:f.action })),
      recentRuns: latestRuns(20)
    };
  }
  function addRun(req, type, status, details){
    const run = { id: uuid(), createdAt: nowIso(), type: clean(type,80), status: clean(status,40), actorPhone: req.user && req.user.phone, actorRole: req.user && req.user.role, details: details || {} };
    pspTestRuns.push(run);
    if (pspTestRuns.length > 500) pspTestRuns.splice(0, pspTestRuns.length - 500);
    logAudit(req, 'psp_integration_test_run', { type: run.type, status: run.status, runId: run.id, detailSummary: run.details && run.details.summary });
    return run;
  }
  function settlementStages(tx){
    const hasTx = !!tx;
    const paid = tx && (['paid','successful','success'].includes(String(tx.paymentStatus || '').toLowerCase()) || !!tx.paidAt);
    const payout = tx && (tx.disbursement || ['completed','released','seller_paid'].includes(String(tx.status || '').toLowerCase()));
    const disp = (tx && tx.disbursement) || {};
    return [
      { stage:'Collection initiated', status: hasTx ? (tx.paymentRef ? 'evidence present' : 'not evidenced') : 'simulated', reference: hasTx ? (tx.paymentRef || tx.id) : 'SIM-COLLECTION-REF' },
      { stage:'Collection confirmed by PSP callback/requery', status: paid ? 'confirmed' : 'simulated / pending', reference: hasTx ? (tx.paymentMeta && tx.paymentMeta.referenceId || tx.paymentRef || '') : 'SIM-CALLBACK' },
      { stage:'Workflow hold active', status: paid && !['completed','refunded','cancelled'].includes(String(tx.status||'').toLowerCase()) ? 'active' : (hasTx ? String(tx.status || 'not active') : 'simulated hold') },
      { stage:'Release/refund decision', status: hasTx ? (tx.decision || tx.releaseStatus || tx.status || 'not decided') : 'simulated release decision' },
      { stage:'Payout/refund instruction to licensed partner', status: payout ? (disp.status || 'instruction evidenced') : 'simulated / not initiated', reference: disp.referenceId || '' },
      { stage:'Payout/refund confirmed', status: ['successful','success'].includes(String(disp.status || '').toLowerCase()) ? 'confirmed' : 'simulated / pending', reference: disp.referenceId || '' },
      { stage:'Collection reconciled by Accounts', status: hasTx ? (tx.collectionReconciled ? 'reconciled' : 'pending reconciliation') : 'simulated reconciled' },
      { stage:'Payout reconciled by Finance', status: hasTx ? (tx.payoutReconciled ? 'reconciled' : 'pending reconciliation') : 'simulated reconciled' }
    ];
  }

  app.get('/api/admin/psp-integration/overview', requireAuth, requirePspStaff, (req,res)=>{ const o=overview(); logAudit(req, 'psp_integration_overview_viewed', { score:o.score }); res.json(o); });
  app.post('/api/admin/psp-integration/test/config', requireAuth, requirePspStaff, (req,res)=>{ const o=overview(); const run=addRun(req,'configuration_check', o.gaps.length ? 'gaps_found' : 'passed', { score:o.score, gaps:o.gaps, summary:`PSP config check score ${o.score}%` }); res.json({ ok:true, run, overview:o }); });
  app.post('/api/admin/psp-integration/test/callback', requireAuth, requirePspStaff, (req,res)=>{ const body=req.body||{}; const provider=clean(body.provider || 'mtn',30).toLowerCase(); const env=envOverview(); const url = provider === 'airtel' ? env.callbackUrls.airtelCollection : (provider === 'mtn_disbursement' ? env.callbackUrls.mtnDisbursement : env.callbackUrls.mtnCollection); const protectedRoute = !!env.railStatus.callbackSecurity.ready; const run=addRun(req,'callback_receiver_test','simulated_pass',{ provider, callbackUrl:url, protectedRoute, summary:`Callback receiver route mapped for ${provider}` }); res.json({ ok:true, run, callback:{ provider, callbackUrl:url, protectedRoute, message:'Synthetic callback receiver test passed. No external provider was called and no money moved.' } }); });
  app.post('/api/admin/psp-integration/test/collection-dry-run', requireAuth, requirePspStaff, (req,res)=>{ const body=req.body||{}; const provider=clean(body.provider || 'mtn',30).toLowerCase(); const amount=money(num(body.amount, 1)); const phone=clean(body.phone || '0970000000',30); const reference=`TP-DRY-${Date.now()}`; const env=envOverview(); const ready = provider === 'airtel' ? env.railStatus.airtelCollection.ready : env.railStatus.mtnCollection.ready; const payload = provider === 'airtel' ? { provider:'airtel', subscriber:{ country:AIRTEL_COUNTRY, currency:AIRTEL_CURRENCY, msisdn: airtelMsisdnFromPhone(phone) }, transaction:{ amount:String(amount), currency:AIRTEL_CURRENCY, id:reference } } : { provider:'mtn', amount:String(amount), currency:MOMO_CURRENCY, externalId:reference, payer:{ partyIdType:'MSISDN', partyId:String(phone).replace(/\D/g,'') }, callbackUrl:MOMO_CALLBACK_URL };
    const run=addRun(req,'collection_dry_run', ready ? 'ready' : 'config_gap', { provider, ready, amount, phone, reference, payload, summary:`Collection dry-run for ${provider}: ${ready?'ready':'missing config'}` });
    res.json({ ok:true, run, dryRun:{ provider, ready, reference, amount, currency: provider==='airtel' ? AIRTEL_CURRENCY : MOMO_CURRENCY, payloadPreview:payload, message:'Dry-run only. This did not call MTN/Airtel and did not request money from the phone.' } }); });
  app.post('/api/admin/psp-integration/test/settlement-simulation', requireAuth, requirePspStaff, (req,res)=>{ const body=req.body||{}; const txId=clean(body.txId || '',120); const tx = txId ? transactions.find(t => String(t.id) === txId || String(t.paymentRef||'') === txId) : null; if(txId && !tx) return res.status(404).json({ error:'Transaction/reference not found for simulation.' }); const stages=settlementStages(tx); const status = stages.some(s => /pending|not evidenced|not active|not initiated/i.test(String(s.status))) ? 'simulation_with_pending_steps' : 'simulation_complete'; const run=addRun(req,'settlement_simulation',status,{ txId:tx && tx.id || null, stages, tx:safeTxMini(tx), summary: tx ? `Settlement lifecycle simulated for transaction ${tx.id}` : 'Generic settlement lifecycle simulation completed' }); res.json({ ok:true, run, simulation:{ tx:safeTxMini(tx), stages, message:'Simulation only. No transaction, ledger, payout, refund or PSP record was changed.' } }); });
  app.get('/api/admin/psp-integration/report', requireAuth, requirePspStaff, (req,res)=>{ const o=overview(); logAudit(req,'psp_integration_report_exported',{score:o.score, runs:o.recentRuns.length}); res.json({ ok:true, title:'TutoPay PSP Integration Test + Settlement Simulation Report', generatedAt:nowIso(), generatedBy:{phone:req.user.phone, role:req.user.role}, overview:o, recommendedNextSteps:['Configure sandbox keys and callback secrets for the chosen PSP partner.','Run dry-run collection and callback receiver tests before external demos.','Run controlled sandbox transactions and reconcile collections/payouts against PSP statements.','Attach this report to the Partner Pack for PSP/BoZ pre-engagement.'] }); });
  app.get('/api/admin/psp-integration/report.csv', requireAuth, requirePspStaff, (req,res)=>{ const o=overview(); const rows=[['section','item','status','detail','action']]; for(const f of o.flags) rows.push(['readiness',f.label,f.ok?'ready':'gap',f.detail,f.action]); for(const r of o.recentRuns) rows.push(['test_run',r.type,r.status,r.createdAt, r.details && r.details.summary || '']); res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition','attachment; filename="tutopay-psp-integration-report.csv"'); res.end(rows.map(r=>r.map(csvCell).join(',')).join('\n')); });
})();


/* ===== TutoPay v1.9: User Trust + Ratings Backend ===== */
(function TP_TRUST_RATINGS_BACKEND_V19(){
  function trustStaffAllowed(role){
    const r = String(role || '').toLowerCase();
    return r === 'admin' || r === 'risk_agent' || r === 'fraud_agent' || r === 'compliance_agent' || r === 'compliance_officer' || r === 'accounts_agent' || r === 'finance_agent' || r === 'accounts';
  }
  function requireTrustStaff(req, res, next){
    if (!req.user || !trustStaffAllowed(req.user.role)) return res.status(403).json({ error: 'Internal staff access required.' });
    return next();
  }
  function cleanTrust(v, max=500){ return String(v == null ? '' : v).trim().slice(0, max); }
  function trustPhone(v){ return String(v || '').replace(/\D/g,'').replace(/^260/,'0'); }
  function trustNum(v, fallback=0){ const n = Number(v); return Number.isFinite(n) ? n : fallback; }
  function trustMoney(v){ const n = Number(v || 0); return Math.round(n * 100) / 100; }
  function trustCsv(v){ const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s; }
  function txBuyer(tx){ return trustPhone(tx && (tx.fromPhone || tx.buyerPhone)); }
  function txSeller(tx){ return trustPhone(tx && (tx.toPhone || tx.sellerPhone)); }
  function txIsCompleted(tx){
    const s = String((tx && tx.status) || '').toLowerCase();
    const ds = String((tx && tx.disbursement && tx.disbursement.status) || '').toLowerCase();
    return ['completed','released','seller_paid','closed'].includes(s) || ['successful','success'].includes(ds) || !!(tx && tx.completedAt);
  }
  function txIsDisputed(tx){ return !!(tx && (tx.disputeActive || String(tx.status || '').toLowerCase().includes('dispute'))); }
  function ensureRatings(tx){ if(!tx) return []; if(!Array.isArray(tx.trustRatings)) tx.trustRatings = []; return tx.trustRatings; }
  function allRatings(){
    const out = [];
    for (const tx of (transactions || [])) {
      for (const r of ensureRatings(tx)) out.push(Object.assign({ txId: tx.id, txAmount: tx.amount || 0, txStatus: tx.status || '' }, r));
    }
    return out;
  }
  function userByPhoneLoose(ph){ const p = trustPhone(ph); return (users || []).find(u => trustPhone(u && u.phone) === p) || null; }
  function publicUserLabel(ph){ const u = userByPhoneLoose(ph); return (u && (u.displayName || u.name || u.businessName || u.fullName)) || ''; }
  function statsForPhone(ph){
    const p = trustPhone(ph);
    const related = (transactions || []).filter(tx => txBuyer(tx) === p || txSeller(tx) === p);
    const completed = related.filter(txIsCompleted);
    const disputed = related.filter(txIsDisputed);
    const received = allRatings().filter(r => trustPhone(r.targetPhone) === p);
    const given = allRatings().filter(r => trustPhone(r.raterPhone) === p);
    const avg = received.length ? received.reduce((a,r)=>a+trustNum(r.rating,0),0) / received.length : 0;
    const trustAvg = received.length ? received.reduce((a,r)=>a+trustNum(r.trustLevel || r.rating,0),0) / received.length : 0;
    const wouldYes = received.filter(r => r.wouldTradeAgain === true || String(r.wouldTradeAgain).toLowerCase() === 'yes').length;
    const completionRate = related.length ? completed.length / related.length : 0;
    const disputePenalty = related.length ? Math.min(0.35, disputed.length / related.length) : 0;
    const tradeAgainRate = received.length ? wouldYes / received.length : 0;
    let score = 0;
    if (received.length) score += (avg / 5) * 55;
    score += completionRate * 25;
    score += tradeAgainRate * 15;
    if (completed.length >= 3) score += 5;
    score = Math.max(0, Math.min(100, Math.round(score - disputePenalty * 30)));
    const band = score >= 85 ? 'Strong trust record' : score >= 70 ? 'Good trust record' : score >= 50 ? 'Early trust record' : (received.length ? 'Needs more evidence' : 'No rating evidence yet');
    return {
      phone: p,
      role: userByPhoneLoose(p) && userByPhoneLoose(p).role || '',
      displayName: publicUserLabel(p),
      score,
      band,
      ratingCount: received.length,
      averageRating: received.length ? Math.round(avg * 10) / 10 : 0,
      averageTrustLevel: received.length ? Math.round(trustAvg * 10) / 10 : 0,
      wouldTradeAgainPercent: received.length ? Math.round(tradeAgainRate * 100) : 0,
      transactions: related.length,
      completedTransactions: completed.length,
      disputedTransactions: disputed.length,
      totalValue: trustMoney(related.reduce((a,t)=>a+trustNum(t.amount,0),0)),
      completedValue: trustMoney(completed.reduce((a,t)=>a+trustNum(t.amount,0),0)),
      ratingsGiven: given.length,
      lastRatingAt: received.slice().sort((a,b)=>Date.parse(b.createdAt||0)-Date.parse(a.createdAt||0))[0]?.createdAt || null
    };
  }
  function safeRating(r){
    return {
      id: r.id, txId: r.txId, createdAt: r.createdAt, raterPhone: r.raterPhone, raterRole: r.raterRole,
      targetPhone: r.targetPhone, targetRole: r.targetRole, rating: r.rating, trustLevel: r.trustLevel,
      wouldTradeAgain: r.wouldTradeAgain, comment: r.comment || '', txStatus: r.txStatus || '', txAmount: trustMoney(r.txAmount || 0)
    };
  }
  function eligibleForUser(req){
    const p = trustPhone(req.user && req.user.phone);
    return (transactions || [])
      .filter(tx => (txBuyer(tx) === p || txSeller(tx) === p) && txIsCompleted(tx) && !txIsDisputed(tx))
      .map(tx => {
        const ratings = ensureRatings(tx);
        const alreadyRated = ratings.some(r => trustPhone(r.raterPhone) === p);
        const targetPhone = txBuyer(tx) === p ? txSeller(tx) : txBuyer(tx);
        return { id: tx.id, itemCode: tx.itemCode || tx.code || (tx.itemSnapshot && tx.itemSnapshot.code) || '', amount: trustMoney(tx.amount || 0), status: tx.status || '', completedAt: tx.completedAt || tx.updatedAt || null, targetPhone, targetRole: txBuyer(tx) === p ? 'seller' : 'buyer', alreadyRated };
      });
  }
  function overviewTrust(){
    const marketUsers = (users || []).filter(u => ['buyer','seller'].includes(String(u && u.role || '').toLowerCase()));
    const profiles = marketUsers.map(u => statsForPhone(u.phone)).sort((a,b)=>b.score-a.score || b.ratingCount-a.ratingCount).slice(0,100);
    const ratings = allRatings().map(safeRating).sort((a,b)=>Date.parse(b.createdAt||0)-Date.parse(a.createdAt||0));
    const avgScore = profiles.length ? Math.round(profiles.reduce((a,p)=>a+(p.score||0),0)/profiles.length) : 0;
    const completed = (transactions || []).filter(txIsCompleted).length;
    const unratedCompleted = eligibleUnratedTransactionsCount();
    const flags = [
      { label:'Trust profiles exist', ok: profiles.some(p=>p.ratingCount>0), detail:`${ratings.length} rating records`, action:'Ask buyers/sellers to rate completed transactions.' },
      { label:'Completed transaction pool exists', ok: completed > 0, detail:`${completed} completed transactions`, action:'Run controlled transactions to create rating opportunities.' },
      { label:'Unrated completed transactions followed up', ok: unratedCompleted === 0 || ratings.length === 0, detail:`${unratedCompleted} rating opportunities still unused`, action:'Send reminders to users after successful completion.' },
      { label:'Low-dispute trust base', ok: profiles.filter(p=>p.disputedTransactions>0).length <= Math.max(1, Math.ceil(profiles.length*0.15)), detail:`${profiles.filter(p=>p.disputedTransactions>0).length} profiles have disputes`, action:'Risk team should review repeat disputes and poor ratings.' }
    ];
    const score = flags.length ? Math.round(flags.filter(f=>f.ok).length / flags.length * 100) : 0;
    return { ok:true, generatedAt: nowIso(), score, band: score>=85?'Trust evidence strong':score>=70?'Trust evidence moderate':score>=50?'Trust evidence early':'Trust evidence weak', counts:{ users: marketUsers.length, profiles: profiles.length, ratings: ratings.length, completedTransactions: completed, unratedCompletedTransactions: unratedCompleted, averageTrustScore: avgScore }, profiles, recentRatings: ratings.slice(0,30), flags, note:'Trust scores are internal pilot indicators, not credit scores. They support safer marketplace matching, risk review and pilot evidence.' };
  }
  function eligibleUnratedTransactionsCount(){
    let n = 0;
    for (const tx of (transactions || [])) {
      if (!txIsCompleted(tx) || txIsDisputed(tx)) continue;
      const ratings = ensureRatings(tx);
      const buyerRated = ratings.some(r => trustPhone(r.raterPhone) === txBuyer(tx));
      const sellerRated = ratings.some(r => trustPhone(r.raterPhone) === txSeller(tx));
      if (!buyerRated) n += 1;
      if (!sellerRated) n += 1;
    }
    return n;
  }

  app.get('/api/trust/me', requireAuth, (req,res)=>{
    if (!['buyer','seller'].includes(String(req.user.role||'').toLowerCase())) return res.status(403).json({ error:'Buyer/seller account required.' });
    const p = trustPhone(req.user.phone);
    const ratings = allRatings();
    res.json({ ok:true, generatedAt:nowIso(), profile:statsForPhone(p), eligibleTransactions:eligibleForUser(req), receivedRatings:ratings.filter(r=>trustPhone(r.targetPhone)===p).map(safeRating).slice(0,30), givenRatings:ratings.filter(r=>trustPhone(r.raterPhone)===p).map(safeRating).slice(0,30) });
  });

  app.get('/api/trust/profile/:phone', requireAuth, (req,res)=>{
    const target = trustPhone(req.params.phone || '');
    const mine = trustPhone(req.user.phone || '');
    const isStaff = trustStaffAllowed(req.user.role);
    const involved = (transactions || []).some(tx => (txBuyer(tx) === mine || txSeller(tx) === mine) && (txBuyer(tx) === target || txSeller(tx) === target));
    if (!isStaff && !involved && target !== mine) return res.status(403).json({ error:'You can only view trust profiles connected to your transactions.' });
    res.json({ ok:true, profile:statsForPhone(target) });
  });

  app.post('/api/trust/rate', requireAuth, async (req,res)=>{
    const role = String(req.user.role || '').toLowerCase();
    if (!['buyer','seller'].includes(role)) return res.status(403).json({ error:'Only buyer/seller accounts can rate transactions.' });
    const body = req.body || {};
    const txId = cleanTrust(body.txId, 120);
    const tx = (transactions || []).find(t => String(t.id) === txId);
    if (!tx) return res.status(404).json({ error:'Transaction not found.' });
    const me = trustPhone(req.user.phone);
    const isBuyer = txBuyer(tx) === me && role === 'buyer';
    const isSeller = txSeller(tx) === me && role === 'seller';
    if (!isBuyer && !isSeller) return res.status(403).json({ error:'You can only rate your own completed transactions.' });
    if (!txIsCompleted(tx)) return res.status(400).json({ error:'You can only rate after the transaction is completed.' });
    if (txIsDisputed(tx)) return res.status(400).json({ error:'Ratings are paused for disputed transactions until review is complete.' });
    const ratings = ensureRatings(tx);
    if (ratings.some(r => trustPhone(r.raterPhone) === me)) return res.status(400).json({ error:'You have already rated this transaction.' });
    const rating = Math.max(1, Math.min(5, Math.round(trustNum(body.rating, 0))));
    const trustLevel = Math.max(1, Math.min(5, Math.round(trustNum(body.trustLevel || body.rating, rating))));
    if (!rating) return res.status(400).json({ error:'Rating must be between 1 and 5.' });
    const targetPhone = isBuyer ? txSeller(tx) : txBuyer(tx);
    const targetRole = isBuyer ? 'seller' : 'buyer';
    const rec = { id: uuid(), createdAt: nowIso(), txId: tx.id, raterPhone: me, raterRole: role, targetPhone, targetRole, rating, trustLevel, wouldTradeAgain: !!body.wouldTradeAgain, comment: cleanTrust(body.comment || '', 500) };
    ratings.push(rec);
    tx.trustRatings = ratings;
    tx.trustSummary = { ratingCount: ratings.length, buyerRated: ratings.some(r=>r.raterRole==='buyer'), sellerRated: ratings.some(r=>r.raterRole==='seller'), updatedAt: nowIso() };
    logAudit(req, 'trust_rating_submitted', { txId: tx.id, targetPhone, targetRole, rating, trustLevel, wouldTradeAgain: rec.wouldTradeAgain });
    if (dbEnabled()) { try { await dbUpsertTransaction(tx); } catch(_) {} }
    res.json({ ok:true, rating:safeRating(Object.assign({ txAmount:tx.amount, txStatus:tx.status }, rec)), myProfile:statsForPhone(me), targetProfile:statsForPhone(targetPhone) });
  });

  app.get('/api/admin/trust/overview', requireAuth, requireTrustStaff, (req,res)=>{ const o=overviewTrust(); logAudit(req,'trust_overview_viewed',{score:o.score, ratings:o.counts.ratings}); res.json(o); });
  app.get('/api/admin/trust/export.csv', requireAuth, requireTrustStaff, (req,res)=>{
    const o = overviewTrust();
    const rows = [['phone','role','display_name','trust_score','band','rating_count','average_rating','would_trade_again_percent','transactions','completed_transactions','disputed_transactions','total_value_zmw','last_rating_at']];
    for (const p of o.profiles) rows.push([p.phone,p.role,p.displayName,p.score,p.band,p.ratingCount,p.averageRating,p.wouldTradeAgainPercent,p.transactions,p.completedTransactions,p.disputedTransactions,p.totalValue,p.lastRatingAt||'']);
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition','attachment; filename="tutopay-trust-ratings.csv"');
    res.end(rows.map(r=>r.map(trustCsv).join(',')).join('\n'));
  });
})();


/* ===== TutoPay v2.0: Notifications + Transaction Receipts + Activity Timelines ===== */
(function TP_NOTIFICATIONS_RECEIPTS_V20(){
  if (globalThis.__tpNotificationsReceiptsV20) return;
  globalThis.__tpNotificationsReceiptsV20 = true;

  const notifAcks = globalThis.__tpNotificationAcks || (globalThis.__tpNotificationAcks = []);

  function nrClean(v, max=500){ return String(v == null ? '' : v).trim().slice(0, max); }
  function nrRole(r){ return String(r || '').toLowerCase(); }
  function nrPhone(p){ return String(p || '').trim(); }
  function nrMoney(n){ const x = Number(n || 0); return Number.isFinite(x) ? Math.round(x * 100) / 100 : 0; }
  function nrDate(v){ try { return v ? new Date(v).toISOString() : null; } catch { return null; } }
  function nrIsStaff(role){ return nrRole(role) === 'admin' || (typeof isInternalStaffRole === 'function' && isInternalStaffRole(role)); }
  function nrTxBuyer(tx){ return nrPhone(tx && (tx.fromPhone || tx.buyerPhone || tx.buyer)); }
  function nrTxSeller(tx){ return nrPhone(tx && (tx.toPhone || tx.sellerPhone || tx.seller)); }
  function nrItemTitle(tx){ return nrClean((tx && tx.itemSnapshot && (tx.itemSnapshot.title || tx.itemSnapshot.name)) || tx.itemTitle || tx.title || tx.itemCode || 'Transaction', 160); }
  function nrTxAccess(req, tx){
    if (!req || !req.user || !tx) return false;
    if (nrIsStaff(req.user.role)) return true;
    const me = nrPhone(req.user.phone);
    return me && (me === nrTxBuyer(tx) || me === nrTxSeller(tx));
  }
  function nrCsv(v){ const s=String(v==null?'':v); return /[",\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s; }
  function nrAcked(phone, id){ return notifAcks.some(a => nrPhone(a.phone) === nrPhone(phone) && String(a.id) === String(id)); }
  function nrAck(phone, id){
    const p = nrPhone(phone); const k = nrClean(id, 220);
    if (!p || !k) return null;
    const old = notifAcks.find(a => nrPhone(a.phone) === p && String(a.id) === k);
    if (old) { old.readAt = old.readAt || nowIso(); return old; }
    const rec = { id:k, phone:p, readAt:nowIso() };
    notifAcks.push(rec);
    if (notifAcks.length > 10000) notifAcks.splice(0, notifAcks.length - 10000);
    return rec;
  }
  function nrNotif(id, audiencePhone, payload){
    const rec = Object.assign({
      id: nrClean(id, 220),
      audiencePhone: nrPhone(audiencePhone),
      title: 'TutoPay notification',
      message: '',
      severity: 'info',
      category: 'transaction',
      txId: null,
      createdAt: nowIso(),
      actionLabel: '',
      actionHint: '',
    }, payload || {});
    rec.read = nrAcked(audiencePhone, rec.id);
    return rec;
  }
  function nrTxStage(tx){
    const s = nrRole(tx && tx.status);
    if (s === 'pending_payment') return 'Payment pending';
    if (s === 'pending') return 'Payment confirmed / awaiting seller action';
    if (s === 'held') return 'Item held for collection';
    if (s === 'in_transit') return 'Delivery in progress';
    if (s === 'delivered') return 'Delivered / awaiting buyer confirmation';
    if (s === 'completed') return 'Completed';
    if (s === 'disputed') return 'Disputed';
    if (s === 'refunded') return 'Refunded';
    return s || 'Recorded';
  }
  function nrBaseTxNote(tx){ return `${nrItemTitle(tx)} · K${nrMoney(tx && tx.amount)} · ${nrTxStage(tx)}`; }

  function nrNotificationsFor(req){
    const role = nrRole(req.user && req.user.role);
    const me = nrPhone(req.user && req.user.phone);
    const list = [];

    for (const tx of (transactions || [])) {
      const buyer = nrTxBuyer(tx); const seller = nrTxSeller(tx);
      const isBuyer = me && me === buyer;
      const isSeller = me && me === seller;
      const staff = nrIsStaff(role);
      if (!isBuyer && !isSeller && !staff) continue;
      const txId = tx.id;
      const stage = nrTxStage(tx);

      if (isSeller && tx.status === 'pending_payment') {
        list.push(nrNotif(`tx:${txId}:seller:new`, me, { title:'New buyer transaction started', message:`A buyer started a transaction for ${nrBaseTxNote(tx)}. Wait for payment confirmation before holding/releasing the item.`, severity:'info', category:'transaction', txId, createdAt:tx.createdAt||nowIso(), actionLabel:'Open transaction' }));
      }
      if ((isBuyer || isSeller) && tx.paymentStatus === 'paid') {
        list.push(nrNotif(`tx:${txId}:payment:confirmed:${isBuyer?'buyer':'seller'}`, me, { title:'Payment confirmed on partner rail', message:`Payment is marked paid for ${nrBaseTxNote(tx)}. TutoPay is tracking workflow status; licensed partner rails handle the funds.`, severity:'ok', category:'payment', txId, createdAt:tx.paidAt||tx.createdAt||nowIso(), actionLabel:'View receipt' }));
      }
      if (isBuyer && ['held','in_transit','delivered'].includes(nrRole(tx.status))) {
        list.push(nrNotif(`tx:${txId}:buyer:action-needed:${tx.status}`, me, { title:'Transaction update', message:`${stage}: ${nrBaseTxNote(tx)}. Confirm only after you have received/collected the item, or raise an issue if something is wrong.`, severity:tx.status==='delivered'?'warn':'info', category:'transaction', txId, createdAt:tx.updatedAt||tx.holdStartedAt||tx.transitStartedAt||nowIso(), actionLabel:'View timeline' }));
      }
      if (isSeller && tx.status === 'completed') {
        list.push(nrNotif(`tx:${txId}:seller:completed`, me, { title:'Buyer confirmed completion', message:`The buyer has confirmed completion for ${nrBaseTxNote(tx)}. Finance/accounts can now review payout/reconciliation evidence.`, severity:'ok', category:'settlement', txId, createdAt:tx.completedAt||nowIso(), actionLabel:'View receipt' }));
      }
      if ((isBuyer || isSeller) && tx.status === 'completed') {
        const ratings = Array.isArray(tx.trustRatings) ? tx.trustRatings : [];
        const alreadyRated = ratings.some(r => nrPhone(r.raterPhone) === me);
        if (!alreadyRated) list.push(nrNotif(`tx:${txId}:rating:request:${isBuyer?'buyer':'seller'}`, me, { title:'Rate this completed trade', message:`Please rate your transaction experience for ${nrBaseTxNote(tx)}. This helps build TutoPay trust evidence during the pilot.`, severity:'info', category:'trust', txId, createdAt:tx.completedAt||nowIso(), actionLabel:'Rate transaction' }));
      }
      if ((isBuyer || isSeller) && tx.disputeActive) {
        list.push(nrNotif(`tx:${txId}:dispute:active:${isBuyer?'buyer':'seller'}`, me, { title:'Dispute/issue active', message:`An issue is active on ${nrBaseTxNote(tx)}. Normal release/refund actions may be frozen until review is complete.`, severity:'warn', category:'dispute', txId, createdAt:(tx.dispute && tx.dispute.openedAt)||nowIso(), actionLabel:'View issue' }));
      }

      if (staff) {
        if (tx.disputeActive && ['admin','risk_agent','fraud_agent','compliance_agent','compliance_officer'].includes(role)) {
          list.push(nrNotif(`staff:${role}:tx:${txId}:open-dispute`, me, { title:'Open dispute needs review', message:`Open issue: ${nrBaseTxNote(tx)}. Risk/compliance should review evidence and update the case.`, severity:'warn', category:'staff_alert', txId, createdAt:(tx.dispute && tx.dispute.openedAt)||nowIso(), actionLabel:'Open issues desk' }));
        }
        if (tx.paymentStatus === 'paid' && !tx.collectionReconciled && ['admin','accounts_agent','accounts','finance_agent'].includes(role)) {
          list.push(nrNotif(`staff:${role}:tx:${txId}:collection-unreconciled`, me, { title:'Collection needs reconciliation', message:`Paid collection not reconciled: ${nrBaseTxNote(tx)}. Match against PSP statement/reference.`, severity:'warn', category:'reconciliation', txId, createdAt:tx.paidAt||tx.createdAt||nowIso(), actionLabel:'Open accounts/finance' }));
        }
        if (tx.status === 'completed' && !tx.payoutReconciled && ['admin','finance_agent','accounts_agent','accounts'].includes(role)) {
          list.push(nrNotif(`staff:${role}:tx:${txId}:payout-unreconciled`, me, { title:'Payout/settlement needs finance review', message:`Completed transaction still needs payout/settlement reconciliation: ${nrBaseTxNote(tx)}.`, severity:'warn', category:'settlement', txId, createdAt:tx.completedAt||nowIso(), actionLabel:'Open finance console' }));
        }
      }
    }

    if (['admin','compliance_agent','compliance_officer'].includes(role)) {
      for (const u of (users || [])) {
        const st = nrRole(u.kycStatus || u.kycReviewStatus);
        if (['pending','submitted','under_review'].includes(st)) {
          list.push(nrNotif(`kyc:${u.phone}:pending`, me, { title:'KYC pending review', message:`User ${nrPhone(u.phone)} has KYC status ${st}. Compliance should review before higher limits or pilot scale-up.`, severity:'info', category:'kyc', txId:null, createdAt:u.kycSubmittedAt||u.updatedAt||u.createdAt||nowIso(), actionLabel:'Open compliance' }));
        }
        if (u.complianceRestricted || u.restrictedForCompliance) {
          list.push(nrNotif(`compliance:${u.phone}:restricted`, me, { title:'Restricted user under review', message:`User ${nrPhone(u.phone)} is restricted for compliance review. Keep restrictions documented and resolved.`, severity:'warn', category:'compliance', txId:null, createdAt:u.restrictedAt||u.updatedAt||nowIso(), actionLabel:'Open compliance' }));
        }
      }
    }

    list.sort((a,b)=>String(b.createdAt||'').localeCompare(String(a.createdAt||'')));
    return list;
  }

  function nrTimeline(tx){
    const rows = [];
    const add = (at, label, detail, source='system') => { if (at || label) rows.push({ at: nrDate(at) || nowIso(), label, detail:nrClean(detail, 400), source }); };
    add(tx.createdAt, 'Transaction created', `Buyer ${nrTxBuyer(tx)} started transaction with seller ${nrTxSeller(tx)} for K${nrMoney(tx.amount)}.`, 'transaction');
    if (tx.paymentRef) add((tx.paymentMeta && tx.paymentMeta.initiatedAt) || tx.createdAt, 'Payment initiated', `Provider/reference: ${tx.paymentProvider || 'partner rail'} / ${tx.paymentRef}.`, 'payment');
    if (tx.paidAt || tx.paymentStatus === 'paid') add(tx.paidAt || tx.createdAt, 'Payment confirmed', 'Collection/payment is marked confirmed by demo/sandbox/callback/re-query evidence.', 'payment');
    if (tx.holdStartedAt) add(tx.holdStartedAt, 'Seller held item', `Hold expires: ${tx.holdExpiresAt || 'not set'}.`, 'workflow');
    if (tx.transitStartedAt) add(tx.transitStartedAt, 'Delivery started', tx.deliveryPoint ? `Delivery point: ${tx.deliveryPoint}` : '', 'workflow');
    if (tx.status === 'delivered') add(tx.updatedAt || tx.transitStartedAt || nowIso(), 'Seller marked delivered', 'Awaiting buyer confirmation.', 'workflow');
    if (tx.completedAt || tx.status === 'completed') add(tx.completedAt || tx.updatedAt || nowIso(), 'Transaction completed', 'Buyer confirmed collection/delivery. Release/payout workflow can be reviewed.', 'workflow');
    if (tx.dispute && tx.dispute.openedAt) add(tx.dispute.openedAt, 'Dispute/issue opened', `${tx.dispute.type || 'issue'} · ${tx.dispute.reasonText || tx.dispute.reasonCode || ''}`, 'dispute');
    if (tx.dispute && tx.dispute.resolvedAt) add(tx.dispute.resolvedAt, 'Dispute/issue resolved', tx.dispute.status || '', 'dispute');
    if (tx.disbursement && tx.disbursement.initiatedAt) add(new Date(Number(tx.disbursement.initiatedAt)).toISOString(), 'Payout initiated', `Reference: ${tx.disbursement.referenceId || ''}`, 'payout');
    if (tx.disbursement && tx.disbursement.completedAt) add(new Date(Number(tx.disbursement.completedAt)).toISOString(), 'Payout completed', `Reference: ${tx.disbursement.referenceId || ''}`, 'payout');

    for (const le of (ledgerEntries || []).filter(e => String(e.txId) === String(tx.id))) {
      add(le.timestamp, `Ledger: ${le.eventType}`, `${le.provider || ''}${le.reference ? ' · ref '+le.reference : ''}${le.notes ? ' · '+le.notes : ''}`, 'ledger');
    }
    const seen = new Set();
    return rows.sort((a,b)=>String(a.at).localeCompare(String(b.at))).filter(r=>{ const k=`${r.at}|${r.label}|${r.detail}`; if(seen.has(k)) return false; seen.add(k); return true; });
  }

  function nrReceipt(tx){
    const timeline = nrTimeline(tx);
    const status = nrTxStage(tx);
    const receiptNo = `TP-RCPT-${String(tx.id || '').slice(0,8).toUpperCase()}`;
    const issuedAt = nowIso();
    const buyer = nrTxBuyer(tx); const seller = nrTxSeller(tx);
    const item = nrItemTitle(tx);
    const amount = nrMoney(tx.amount);
    const nonCustodialNote = 'TutoPay records the transaction workflow, evidence, confirmations, disputes, receipts and reconciliation metadata. Customer funds are processed, held, settled, refunded or reversed by licensed PSP/mobile-money/banking partners.';
    const text = [
      'TUTOPAY TRANSACTION RECEIPT',
      `Receipt No: ${receiptNo}`,
      `Issued At: ${issuedAt}`,
      `Transaction ID: ${tx.id}`,
      `Status: ${status}`,
      `Buyer: ${buyer}`,
      `Seller: ${seller}`,
      `Item: ${item}`,
      `Amount: ZMW ${amount}`,
      `Payment Rail/Provider: ${tx.paymentProvider || 'licensed partner rail'}`,
      `Payment Reference: ${tx.paymentRef || 'not assigned'}`,
      `Payment Status: ${tx.paymentStatus || 'unknown'}`,
      `Created: ${tx.createdAt || ''}`,
      `Paid/Confirmed: ${tx.paidAt || ''}`,
      `Completed: ${tx.completedAt || ''}`,
      `Collection Reconciled: ${tx.collectionReconciled ? 'Yes' : 'No'}`,
      `Payout Reconciled: ${tx.payoutReconciled ? 'Yes' : 'No'}`,
      '',
      'Timeline:',
      ...timeline.map(t => `- ${t.at} | ${t.label}${t.detail ? ' | '+t.detail : ''}`),
      '',
      `Non-custodial note: ${nonCustodialNote}`,
    ].join('\n');
    return { receiptNo, issuedAt, txId:tx.id, status, buyerPhone:buyer, sellerPhone:seller, item, amount, currency:tx.currency || 'ZMW', paymentProvider:tx.paymentProvider || 'licensed_partner', paymentRef:tx.paymentRef || null, paymentStatus:tx.paymentStatus || '', createdAt:tx.createdAt || null, paidAt:tx.paidAt || null, completedAt:tx.completedAt || null, collectionReconciled:!!tx.collectionReconciled, payoutReconciled:!!tx.payoutReconciled, nonCustodialNote, timeline, text };
  }

  function nrStaffOverview(req){
    const all = nrNotificationsFor(req);
    const unread = all.filter(n=>!n.read);
    const byCat = all.reduce((m,n)=>{m[n.category]=(m[n.category]||0)+1; return m;},{});
    const txs = transactions || [];
    return {
      ok:true,
      generatedAt:nowIso(),
      user:{phone:req.user.phone, role:req.user.role},
      counts:{total:all.length, unread:unread.length, openDisputes:txs.filter(t=>t.disputeActive).length, unreconciledCollections:txs.filter(t=>t.paymentStatus==='paid'&&!t.collectionReconciled).length, unreconciledPayouts:txs.filter(t=>t.status==='completed'&&!t.payoutReconciled).length},
      byCategory:byCat,
      alerts:all.slice(0,100),
      note:'Notifications are generated from live transaction, KYC, dispute, rating and reconciliation records. Receipts are evidence records, not proof that TutoPay held funds.'
    };
  }

  app.get('/api/notifications', requireAuth, (req,res)=>{
    const all = nrNotificationsFor(req);
    const unreadOnly = String((req.query && req.query.unread) || '') === '1';
    const limit = Math.max(1, Math.min(200, Number((req.query && req.query.limit) || 80)));
    res.json({ ok:true, generatedAt:nowIso(), unreadCount:all.filter(n=>!n.read).length, notifications:(unreadOnly?all.filter(n=>!n.read):all).slice(0,limit) });
  });

  app.post('/api/notifications/:id/read', requireAuth, (req,res)=>{
    const rec = nrAck(req.user.phone, req.params.id);
    logAudit(req, 'notification_mark_read', { id:req.params.id });
    res.json({ ok:true, ack:rec });
  });

  app.post('/api/notifications/read-all', requireAuth, (req,res)=>{
    const all = nrNotificationsFor(req);
    all.forEach(n => nrAck(req.user.phone, n.id));
    logAudit(req, 'notification_mark_all_read', { count:all.length });
    res.json({ ok:true, count:all.length });
  });

  app.get('/api/transactions/:id/timeline', requireAuth, (req,res)=>{
    const tx = (transactions || []).find(t => String(t.id) === String(req.params.id));
    if (!tx) return res.status(404).json({ error:'Transaction not found' });
    if (!nrTxAccess(req, tx)) return res.status(403).json({ error:'Not allowed to view this transaction timeline.' });
    res.json({ ok:true, txId:tx.id, status:nrTxStage(tx), timeline:nrTimeline(tx) });
  });

  app.get('/api/transactions/:id/receipt', requireAuth, (req,res)=>{
    const tx = (transactions || []).find(t => String(t.id) === String(req.params.id));
    if (!tx) return res.status(404).json({ error:'Transaction not found' });
    if (!nrTxAccess(req, tx)) return res.status(403).json({ error:'Not allowed to view this transaction receipt.' });
    const receipt = nrReceipt(tx);
    logAudit(req, 'transaction_receipt_viewed', { txId:tx.id, receiptNo:receipt.receiptNo });
    res.json({ ok:true, receipt });
  });

  app.get('/api/transactions/:id/receipt.txt', requireAuth, (req,res)=>{
    const tx = (transactions || []).find(t => String(t.id) === String(req.params.id));
    if (!tx) return res.status(404).send('Transaction not found');
    if (!nrTxAccess(req, tx)) return res.status(403).send('Not allowed to view this transaction receipt.');
    const receipt = nrReceipt(tx);
    logAudit(req, 'transaction_receipt_txt_downloaded', { txId:tx.id, receiptNo:receipt.receiptNo });
    res.setHeader('Content-Type','text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${receipt.receiptNo}.txt"`);
    res.end(receipt.text);
  });

  app.get('/api/admin/notifications/overview', requireAuth, (req,res)=>{
    if (!nrIsStaff(req.user.role)) return res.status(403).json({ error:'Internal staff only' });
    const o = nrStaffOverview(req);
    logAudit(req, 'notifications_overview_viewed', { unread:o.counts.unread, total:o.counts.total });
    res.json(o);
  });

  app.get('/api/admin/notifications/export.csv', requireAuth, (req,res)=>{
    if (!nrIsStaff(req.user.role)) return res.status(403).json({ error:'Internal staff only' });
    const o = nrStaffOverview(req);
    const rows = [['id','created_at','severity','category','tx_id','title','message','read']];
    for (const n of o.alerts) rows.push([n.id,n.createdAt,n.severity,n.category,n.txId||'',n.title,n.message,n.read?'yes':'no']);
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition','attachment; filename="tutopay-notifications-alerts.csv"');
    res.end(rows.map(r=>r.map(nrCsv).join(',')).join('\n'));
  });
})();


const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`TutoPay API running on port ${PORT} [stage=${APP_STAGE}]`);
});



app.post("/api/admin/staff-accounts", requireAuth, (req, res) => {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const { phone, pin, role } = req.body || {};
  const normalizedPhone = String(phone || "").trim();
  const pinVal = String(pin || "").trim();
  const roleNorm = String(role || "").trim().toLowerCase();

  if (!normalizedPhone || !pinVal) return res.status(400).json({ error: "Phone and PIN are required." });

  const allowed = ["risk_agent", "accounts_agent", "finance_agent", "compliance_agent"];
  if (!allowed.includes(roleNorm)) return res.status(400).json({ error: "Invalid staff role." });

  let user = findUserByPhone(normalizedPhone);
  if (user) return res.status(400).json({ error: "User already exists with this phone" });

  user = {
    id: uuid(),
    phone: normalizedPhone,
    role: roleNorm,
    pinHash: hashPin(pinVal),
    createdAt: nowIso(),
    createdBy: req.user.phone,
    kycLevel: "staff",
    kycStatus: "verified",
    kycHistory: [],
  };

  users.push(user);
  if (dbEnabled()) { dbUpsertUser(user).catch(() => {}); }

  logAudit(req, "staff_account_create", { phone: normalizedPhone, role: roleNorm });
  return res.json({ ok: true, user: { id: user.id, phone: user.phone, role: user.role } });
});

// Run DB init in background. In strict/production mode, exit if Postgres never becomes ready.
dbInit()
  .then((ok) => {
    dbReady = dbEnabled() || !STRICT_DB_MODE;
    console.log(`[DB] Ready. enabled=${dbEnabled()} strict=${STRICT_DB_MODE} mode=${dbEnabled() ? 'postgres+memory-cache' : 'memory-only'}`);
    if (STRICT_DB_MODE && !dbEnabled()) {
      console.error('[DB] Strict mode active and Postgres is not ready. Exiting.');
      process.exit(1);
    }
  })
  .catch((err) => {
    dbInitError = err;
    dbReady = !STRICT_DB_MODE;
    console.error('[DB] Init failed:', err);
    if (STRICT_DB_MODE) {
      console.error('[DB] Strict mode active. Exiting.');
      process.exit(1);
    }
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
