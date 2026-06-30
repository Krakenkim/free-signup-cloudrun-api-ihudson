// index.js (Node 20+)
import express from "express";
import { google } from "googleapis";
import admin from "firebase-admin";

const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "200kb" }));

// ---------- Firestore init ----------
if (!admin.apps.length) admin.initializeApp();
const db = admin.firestore();

// ---------- ENV ----------
const ENV = {
  GOOGLE_SA_JSON: process.env.GOOGLE_SA_JSON,
  GOOGLE_ADMIN_SUBJECT: process.env.GOOGLE_ADMIN_SUBJECT,

  // ✅ Cloud Run 서비스마다 이 값만 다르게 넣으면 됨
  // 예:
  // free-signup-tax      → GOOGLE_GROUP_EMAIL=tax-free@calvestor.com
  // free-signup-semi     → GOOGLE_GROUP_EMAIL=semi-free@calvestor.com
  // free-signup-visa     → GOOGLE_GROUP_EMAIL=visa-free@calvestor.com
  GOOGLE_GROUP_EMAIL: process.env.GOOGLE_GROUP_EMAIL,

  TURNSTILE_SECRET: process.env.TURNSTILE_SECRET,

  // 예: "https://ihudson.mycafe24.com,https://calvestor.com"
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  RATE_IP_PER_HOUR: Number(process.env.RATE_IP_PER_HOUR || 20),
  RATE_EMAIL_PER_DAY: Number(process.env.RATE_EMAIL_PER_DAY || 3),

  // 선택값: Cloud Run 서비스 구분용. 없어도 동작함.
  SERVICE_NAME: process.env.SERVICE_NAME || "free-signup-api",
};

function must(name, v) {
  if (!v || String(v).trim() === "") throw new Error(`Missing env: ${name}`);
}

must("GOOGLE_SA_JSON", ENV.GOOGLE_SA_JSON);
must("GOOGLE_ADMIN_SUBJECT", ENV.GOOGLE_ADMIN_SUBJECT);
must("GOOGLE_GROUP_EMAIL", ENV.GOOGLE_GROUP_EMAIL);
must("TURNSTILE_SECRET", ENV.TURNSTILE_SECRET);

// ---------- Helpers ----------
function stripOuterQuotes(s) {
  const t = String(s ?? "").trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1).trim();
  }
  return t;
}

const EMAIL_REGEX =
  /^(?!.*\.\.)[A-Za-z0-9_%+-](?:[A-Za-z0-9._%+-]*[A-Za-z0-9_%+-])?@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;

function normalizeEmail(raw) {
  const email = String(raw || "").trim().toLowerCase();
  if (!EMAIL_REGEX.test(email)) return null;
  return email;
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.ip;
}

function isGmailAddress(email) {
  const e = String(email || "").toLowerCase();
  return e.endsWith("@gmail.com") || e.endsWith("@googlemail.com");
}

// ---------- CORS ----------
const allowedSet = new Set(ENV.ALLOWED_ORIGINS);

function applyCors(req, res) {
  const origin = req.headers.origin;

  if (origin && allowedSet.size > 0) {
    if (allowedSet.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }
  }

  if (origin && allowedSet.size === 0) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "3600");
}

app.use((req, res, next) => {
  applyCors(req, res);
  if (req.method === "OPTIONS") return res.status(204).send();
  next();
});

// ---------- Turnstile verify ----------
async function verifyTurnstile(token, ip) {
  const body = new URLSearchParams();
  body.set("secret", ENV.TURNSTILE_SECRET);
  body.set("response", token);
  if (ip) body.set("remoteip", ip);

  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });

  const data = await r.json().catch(() => ({}));
  return { ok: !!data.success, data };
}

// ---------- Rate limit (Firestore) ----------
async function rateLimitOrThrow({ ip, email }) {
  const now = new Date();

  const hourKey = `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-${now.getUTCDate()}-${now.getUTCHours()}`;
  const dayKey = `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-${now.getUTCDate()}`;

  // ✅ 여러 무료 등록 서비스가 있어도 서로 rate limit이 섞이지 않게 group 기준 포함
  const groupKey = ENV.GOOGLE_GROUP_EMAIL.toLowerCase();

  const ipDocId = `group:${groupKey}:ip:${ip}:${hourKey}`;
  const emDocId = `group:${groupKey}:email:${email}:${dayKey}`;

  const ipRef = db.collection("rate_limits").doc(ipDocId);
  const emRef = db.collection("rate_limits").doc(emDocId);

  await db.runTransaction(async (tx) => {
    const [ipSnap, emSnap] = await Promise.all([tx.get(ipRef), tx.get(emRef)]);

    const ipCount = (ipSnap.exists ? ipSnap.data().count || 0 : 0) + 1;
    const emCount = (emSnap.exists ? emSnap.data().count || 0 : 0) + 1;

    if (ipCount > ENV.RATE_IP_PER_HOUR) throw new Error("RATE_IP");
    if (emCount > ENV.RATE_EMAIL_PER_DAY) throw new Error("RATE_EMAIL");

    const ttlIp = new Date(now.getTime() + 2 * 60 * 60 * 1000);
    const ttlEm = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000);

    tx.set(
      ipRef,
      {
        count: ipCount,
        expireAt: ttlIp,
        ip,
        groupEmail: ENV.GOOGLE_GROUP_EMAIL,
        serviceName: ENV.SERVICE_NAME,
      },
      { merge: true }
    );

    tx.set(
      emRef,
      {
        count: emCount,
        expireAt: ttlEm,
        email,
        groupEmail: ENV.GOOGLE_GROUP_EMAIL,
        serviceName: ENV.SERVICE_NAME,
      },
      { merge: true }
    );
  });
}

// ---------- Google Directory client ----------
async function getDirectoryClient() {
  const sa = JSON.parse(ENV.GOOGLE_SA_JSON);

  const subject = stripOuterQuotes(ENV.GOOGLE_ADMIN_SUBJECT);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(subject)) {
    throw new Error(`BAD_GOOGLE_ADMIN_SUBJECT:${subject}`);
  }

  const jwt = new google.auth.JWT({
    email: sa.client_email,
    key: sa.private_key,
    scopes: ["https://www.googleapis.com/auth/admin.directory.group.member"],
    subject,
  });

  try {
    await jwt.authorize();
  } catch (e) {
    const status = e?.response?.status;
    const data = e?.response?.data;
    console.error("GOOGLE_AUTH_FAILED", {
      status,
      data,
      message: String(e?.message || ""),
      serviceName: ENV.SERVICE_NAME,
      groupEmail: ENV.GOOGLE_GROUP_EMAIL,
    });
    throw new Error("GOOGLE_AUTH_FAILED");
  }

  return google.admin({ version: "directory_v1", auth: jwt });
}

async function addToGroup(email) {
  const directory = await getDirectoryClient();

  try {
    await directory.members.insert({
      groupKey: ENV.GOOGLE_GROUP_EMAIL,
      requestBody: { email, role: "MEMBER" },
    });

    console.log("GROUP_MEMBER_ADDED", {
      email,
      groupEmail: ENV.GOOGLE_GROUP_EMAIL,
      serviceName: ENV.SERVICE_NAME,
    });

    return {
      added: true,
      groupEmail: ENV.GOOGLE_GROUP_EMAIL,
      serviceName: ENV.SERVICE_NAME,
    };
  } catch (e) {
    const code = e?.code;
    const msg = String(e?.message || "");

    if (code === 409 || msg.includes("Member already exists") || msg.includes("duplicate")) {
      console.log("GROUP_MEMBER_ALREADY_EXISTS", {
        email,
        groupEmail: ENV.GOOGLE_GROUP_EMAIL,
        serviceName: ENV.SERVICE_NAME,
      });

      return {
        added: false,
        already: true,
        groupEmail: ENV.GOOGLE_GROUP_EMAIL,
        serviceName: ENV.SERVICE_NAME,
      };
    }

    if (
      code === 404 &&
      isGmailAddress(email) &&
      msg.toLowerCase().includes("resource not found") &&
      msg.toLowerCase().includes(String(email).toLowerCase())
    ) {
      console.warn("EMAIL_NOT_FOUND_GMAIL", {
        email,
        code,
        msg,
        groupEmail: ENV.GOOGLE_GROUP_EMAIL,
        serviceName: ENV.SERVICE_NAME,
      });
      throw new Error("EMAIL_NOT_FOUND");
    }

    console.error("DIRECTORY_ERROR", {
      code,
      msg,
      email,
      groupEmail: ENV.GOOGLE_GROUP_EMAIL,
      serviceName: ENV.SERVICE_NAME,
    });

    throw new Error("DIRECTORY_ERROR");
  }
}

// ---------- routes ----------
app.get("/health", (req, res) =>
  res.json({
    ok: true,
    serviceName: ENV.SERVICE_NAME,
    groupEmail: ENV.GOOGLE_GROUP_EMAIL,
  })
);

app.post("/api/free-signup", async (req, res) => {
  const ip = getClientIp(req);
  const email = normalizeEmail(req.body?.email);
  const token = String(req.body?.turnstileToken || "");

  if (!email) return res.status(400).json({ ok: false, code: "INVALID_EMAIL" });
  if (!token) return res.status(400).json({ ok: false, code: "MISSING_CAPTCHA" });

  try {
    await rateLimitOrThrow({ ip, email });

    const { ok: human, data } = await verifyTurnstile(token, ip);
    if (!human) {
      console.warn("CAPTCHA_FAILED", {
        ip,
        email,
        data,
        groupEmail: ENV.GOOGLE_GROUP_EMAIL,
        serviceName: ENV.SERVICE_NAME,
      });

      return res.status(403).json({ ok: false, code: "CAPTCHA_FAILED" });
    }

    const result = await addToGroup(email);

    return res.json({
      ok: true,
      result,
    });
  } catch (e) {
    const m = String(e?.message || "");

    if (m === "RATE_IP") return res.status(429).json({ ok: false, code: "RATE_IP" });
    if (m === "RATE_EMAIL") return res.status(429).json({ ok: false, code: "RATE_EMAIL" });

    if (m === "EMAIL_NOT_FOUND") {
      return res.status(404).json({ ok: false, code: "EMAIL_NOT_FOUND" });
    }

    if (m.startsWith("BAD_GOOGLE_ADMIN_SUBJECT:")) {
      return res.status(500).json({ ok: false, code: "BAD_GOOGLE_ADMIN_SUBJECT" });
    }

    if (m === "GOOGLE_AUTH_FAILED") {
      return res.status(500).json({ ok: false, code: "GOOGLE_AUTH_FAILED" });
    }

    if (m === "DIRECTORY_ERROR") {
      return res.status(500).json({ ok: false, code: "DIRECTORY_ERROR" });
    }

    console.error("free-signup error", {
      message: m,
      error: e,
      groupEmail: ENV.GOOGLE_GROUP_EMAIL,
      serviceName: ENV.SERVICE_NAME,
    });

    return res.status(500).json({ ok: false, code: "SERVER_ERROR" });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () =>
  console.log(`Listening on ${port}`, {
    serviceName: ENV.SERVICE_NAME,
    groupEmail: ENV.GOOGLE_GROUP_EMAIL,
  })
);
