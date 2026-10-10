
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const COOKIE_SECRET = process.env.COOKIE_SECRET;

if (!COOKIE_SECRET || COOKIE_SECRET.length < 32) {
  throw new Error("Set COOKIE_SECRET to a random secret of at least 32 characters.");
}

app.use(express.json({ limit: "10kb" }));
app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, "public")));

const DB_FILE = path.join(__dirname, "keys.json");
const DAY = 24 * 60 * 60 * 1000;

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ visitors: {} }, null, 2));
}

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function writeDB(db) {
  const temp = DB_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(db, null, 2));
  fs.renameSync(temp, DB_FILE);
}

function makeKey() {
  return "SOV-" + crypto.randomBytes(18).toString("hex").toUpperCase();
}

// Give each browser a signed visitor identifier.
app.use((req, res, next) => {
  let visitor = req.signedCookies.visitor;

  if (!visitor || !/^[a-f0-9]{64}$/.test(visitor)) {
    visitor = crypto.randomBytes(32).toString("hex");

    res.cookie("visitor", visitor, {
      signed: true,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 365 * DAY,
      path: "/"
    });
  }

  req.visitorId = visitor;
  next();
});

// Get current key status.
app.get("/api/status", (req, res) => {
  const db = readDB();
  const record = db.visitors[req.visitorId];

  if (!record) {
    return res.json({ generated: false });
  }

  return res.json({
    generated: true,
    key: record.key,
    expiresAt: record.expiresAt,
    expired: Date.now() >= record.expiresAt
  });
});

// Generate one key per visitor identifier.
app.post("/api/generate", (req, res) => {
  const db = readDB();

  if (db.visitors[req.visitorId]) {
    return res.status(409).json({
      error: "A key has already been generated. Generation is locked."
    });
  }

  const now = Date.now();
  const key = makeKey();

  db.visitors[req.visitorId] = {
    key,
    createdAt: now,
    expiresAt: now + DAY
  };

  writeDB(db);

  res.json({
    key,
    createdAt: now,
    expiresAt: now + DAY
  });
});

// Verify a key from your hub.
app.post("/api/verify", (req, res) => {
  const key = typeof req.body.key === "string"
    ? req.body.key.trim()
    : "";

  if (!/^SOV-[A-F0-9]{36}$/.test(key)) {
    return res.json({ valid: false, reason: "invalid" });
  }

  const db = readDB();

  const record = Object.values(db.visitors)
    .find(entry => entry.key === key);

  if (!record) {
    return res.json({ valid: false, reason: "invalid" });
  }

  if (Date.now() >= record.expiresAt) {
    return res.json({ valid: false, reason: "expired" });
  }

  res.json({
    valid: true,
    expiresAt: record.expiresAt
  });
});

app.listen(PORT, () => {
  console.log(`Sovereign Hub Key System running on port ${PORT}`);
});
