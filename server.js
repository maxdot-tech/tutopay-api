// server.js
// TutoPay demo backend — escrow logic + catalogue + buyer→seller requests with replies + live GPS

const express = require("express");
const cors = require("cors");
const { v4: uuid } = require("uuid");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const crypto = require("crypto");

const app = express();
app.set('trust proxy', 1); // so req.protocol works behind Railway
const PORT = process.env.PORT || 4000;

// Allow bigger JSON bodies (base64 images from frontend)
app.use(cors());
app.use(express.json({ limit: "50mb" }));  // ⬅️ change 5mb → 50mb

// (optional, but good for safety if you use urlencoded anywhere)
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Serve the frontend and uploaded dispute docs
app.use(express.static("public"));
app.use('/uploads', express.static(uploadDir)); // serve uploaded files/images

// ===== Dispute document uploads (Multer) =====
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);

// --- Helpers: store base64(data:) images as real files in /uploads and return public URLs ---
function _baseUrl(req) {
  // On Railway, trust proxy is enabled so req.protocol should be correct
  return `${req.protocol}://${req.get('host')}`;
}
function _storeMaybeDataImage(input, req) {
  if (!input || typeof input !== 'string') return '';
  if (!input.startsWith('data:image/')) return input; // already a URL
  const comma = input.indexOf(',');
  if (comma === -1) return '';
  const meta = input.slice(0, comma);
  const b64 = input.slice(comma + 1);
  const m = /data:image\/(png|jpeg|jpg|webp|gif);base64/i.exec(meta);
  const ext = m ? (m[1] === 'jpeg' ? 'jpg' : m[1]) : 'png';
  const name = `img_${Date.now()}_${Math.random().toString(16).slice(2)}.${ext}`;
  const filePath = path.join(uploadDir, name);
  try {
    fs.writeFileSync(filePath, Buffer.from(b64, 'base64'));
    return `${_baseUrl(req)}/uploads/${name}`;
  } catch (e) {
    console.error('Failed to write image file:', e);
    return '';
  }
}
function _migrateItemImages(item, req) {
  if (!item) return;
  const urls = [];
  const push = (u) => {
    const out = _storeMaybeDataImage(u, req);
    if (out) urls.push(out);
  };
  if (Array.isArray(item.imageUrls)) item.imageUrls.forEach(push);
  if (item.imageUrl) push(item.imageUrl);
  // De-dup and keep stable order
  const seen = new Set();
  item.imageUrls = urls.filter((u) => (seen.has(u) ? false : (seen.add(u), true)));
  item.imageUrl = item.imageUrls[0] || '';
}
function _migrateAllItems(req) {
  try { items.forEach((it) => _migrateItemImages(it, req)); } catch (e) {}
}

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

// -------- In-memory "database" --------
const items = [
  {
    code: "1000",
    title: "Laptop, Lenovo (Used)",
    price: 5000,
    sellerPhone: "0977623456",
    holdHours: 24,
    imageUrl: "https://via.placeholder.com/120x80.png?text=Lenovo+1",
    availability: "available",
    condition: "used",
  },
  {
    code: "1001",
    title: "Laptop, Lenovo (New)",
    price: 11500,
    sellerPhone: "0977100999",
    holdHours: 24,
    imageUrl: "https://via.placeholder.com/120x80.png?text=Lenovo+2",
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

let nextItemNumber = 1002;

// -------- Helpers --------
function findItem(code) {
  return items.find((i) => i.code === code);
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
  _migrateAllItems(req);
  res.json(items);
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

    const urlsArray = Array.isArray(imageUrls) ? imageUrls.slice(0, 15) : [];
  // Convert any base64 data URLs into real files so /api/items stays small
  const storedUrls = urlsArray.map(u => _storeMaybeDataImage(u, req)).filter(Boolean);
  const firstUrl = _storeMaybeDataImage(imageUrl, req) || storedUrls[0] || "";

const item = {
  code: itemNumber,
  title,
  details: details || "",
  price: Number(price),
  sellerPhone,
  holdHours: holdHours ? Number(holdHours) : 24,
  imageUrl: firstUrl || "",
  imageUrls: storedUrls,
  availability: availability || "available",
  condition: condition || "used",
};

  items.push(item);
  res.status(201).json(item);
});

// Public: catalogue for a given seller
app.get("/api/public/seller/:sellerPhone", (req, res) => {
  _migrateAllItems(req);
  const phone = req.params.sellerPhone;
  const sellerItems = items.filter((i) => i.sellerPhone === phone);
  res.json(sellerItems);
});

// Public: fetch item by code
app.get("/api/public/item/:code", (req, res) => {
  _migrateAllItems(req);
  const code = req.params.code;
  const item = items.find((it) => it.code === code);

  if (!item) {
    return res.status(404).json({ error: "Item not found." });
  }

  res.json({
  code: item.code,
  title: item.title,
  details: item.details || "",
  price: item.price,
          holdHours: holdDurationHours,
  imageUrl: item.imageUrl,
  imageUrls: Array.isArray(item.imageUrls)
    ? item.imageUrls
    : (item.imageUrl ? [item.imageUrl] : []),
  availability: item.availability,
  holdHours: item.holdHours,
  sellerPhone: item.sellerPhone,
});
});

// -------- Transactions (escrow) --------
app.post("/api/transactions", requireAuth, (req, res) => {
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
    status: "pending",
    createdAt: nowIso(),
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
app.post("/api/transactions/:id/action", requireAuth, (req, res) => {
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
app.listen(PORT, () => {
  console.log(`TutoPay backend listening on port ${PORT}`);
});
