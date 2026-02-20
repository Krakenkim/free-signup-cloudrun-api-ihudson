"use strict";

const express = require("express");
const admin = require("firebase-admin");
const { google } = require("googleapis");

// --------------------
// ENV
// --------------------
function mustEnv(name) {
  const v = process.env[name];
  if (!v || String(v).trim() === "") throw new Error(`Missing env: ${name}`);
  return v;
}

const ENV = {
  PORT: Number(process.env.PORT || 8080),

  // ✅ CORS 허용할 워드프레스 도메인들 (쉼표로 여러개)
  // 기본값: 네 콘솔에 찍힌 origin 포함
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS ||
    "https://ihudson.mycafe24.com,https://calvestor.com,https://www.calvestor.com,http://localhost:3000"
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  // Turnstile
  TURNSTILE_SECRET: mustEnv("TURNSTILE_SECRET"),

  // Google Groups 추가용 (DWD 서비스계정 JSON)
  GOOGLE_SA_JSON: mustEnv("GOOGLE_SA_JSON"),
  GOOGLE_ADMIN_EMAIL: mustEnv("GOOGLE_ADMIN_EMAIL"),
  FREE_GROUP_EMAIL: process.env.FREE_GROUP_EMAIL || "free-subs@calvestor.com",

  // Rate limit (Firestore)
  RATE_LIMIT_MAX: Number(process.env.RATE_LIMIT_MAX || 5), // window 안에서 최대 요청
  RATE_LIMIT_WINDOW_SEC: Number(process.env.RATE_LIMIT_WINDOW_SEC || 600), // 10분
  RATE_COLLECTION: process.env.RATE_COLLECTION || "free_signup_rate_limits",
};

// --------------------
// App
// --------------------
const app = express();

// ✅ 1) CORS + Preflight(OPTIONS) 처리 (가장 위에 있어야 함)
const ALLOWED = new Set(ENV.ALLOWED_ORIGINS);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // allowlist에 있는 origin만 허용
  if (origin && ALLOWED.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  // preflight에 필요한 헤더들
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// JSON 바디
app.use(express.json({ limit: "1mb" }));

// --------------------
// Firestore init (rate limit)
// --------------------
function initFirestoreIfNeeded() {
  if (admin.apps.length > 0) return;

  // GOOGLE_SA_JSON으로 Firestore까지 같이 초기화(같은 프로젝트라고 가정)
  const sa = JSON.parse(ENV.GOOGLE_SA_JSON);
  admin.initializeApp({
    credential: admin.credential.cert(sa),
  });
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

async function rateLimitOrThrow(req) {
  initFirestoreIfNeeded();
  const db = admin.firestore();

  const ip = getClientIp(req);
  const now = Date.now();
  const windowSec = ENV.RATE_LIMIT_WINDOW_SEC;
  const bucket = Math.floor(now / (windowSec * 1000)); // window 단위 버킷
  const docId = `${ip}:${bucket}`;

  const ref = db.collection(ENV.RATE_COLLECTION).doc(docId);

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const count = snap.exists ? Number(snap.data().count || 0) : 0;

    if (count >= ENV.RATE_LIMIT_MAX) {
      const err = new Error("RATE_LIMITED");
      err.statusCode = 429;
      throw err;
    }

    const expireAt = new Date(now + windowSec * 2 * 1000); // TTL용(대충 2배)
    tx.set(
      ref,
      {
        ip,
        bucket,
        count: count + 1,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        expireAt, // Firestore TTL 정책 걸면 자동 정리됨
      },
      { merge: true }
    );
  });
}

// --------------------
// Turnstile verify
// --------------------
async function verifyTurnstile({ token, remoteip }) {
  const form = new URLSearchParams();
  form.set("secret", ENV.TURNSTILE_SECRET);
  form.set("response", token);
  if (remoteip) form.set("remoteip", remoteip);

  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    return { success: false, errorCodes: ["turnstile_http_error"], detail: text };
  }
  return resp.json();
}

// --------------------
// Google Groups add member
// --------------------
async function getDirectoryClient() {
  const sa = JSON.parse(ENV.GOOGLE_SA_JSON);
  const scopes = ["https://www.googleapis.com/auth/admin.directory.group.member"];

  const auth = new google.auth.JWT({
    email: sa.client_email,
    key: sa.private_key,
    scopes,
    subject: ENV.GOOGLE_ADMIN_EMAIL, // ✅ 도메인-wide delegation
  });

  const directory = google.admin({ version: "directory_v1", auth });
  return directory;
}

async function addMemberToGroup(email) {
  const directory = await getDirectoryClient();

  try {
    await directory.members.insert({
      groupKey: ENV.FREE_GROUP_EMAIL,
      requestBody: {
        email,
        role: "MEMBER",
      },
    });
    return { status: "added" };
  } catch (e) {
    const code = e?.code || e?.response?.status;
    const msg = e?.message || "";

    // 이미 멤버면 성공 취급
    if (code === 409 || /Member already exists/i.test(msg)) {
      return { status: "exists" };
    }

    // 그대로 throw
    throw e;
  }
}

// --------------------
// Routes
// --------------------
app.get("/healthz", (req, res) => res.status(200).send("ok"));

app.post("/api/free-signup", async (req, res) => {
  try {
    // (선택) origin 체크를 서버에서도 한 번 더
    const origin = req.headers.origin;
    if (origin && !ALLOWED.has(origin)) {
      return res.status(403).json({ ok: false, error: "FORBIDDEN_ORIGIN", origin });
    }

    const emailRaw = (req.body?.email || "").toString().trim().toLowerCase();
    const turnstileToken = (req.body?.turnstileToken || "").toString().trim();

    if (!emailRaw) return res.status(400).json({ ok: false, error: "EMAIL_REQUIRED" });

    // 아주 기본 이메일 체크
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailRaw)) {
      return res.status(400).json({ ok: false, error: "EMAIL_INVALID" });
    }

    if (!turnstileToken) {
      return res.status(400).json({ ok: false, error: "TURNSTILE_TOKEN_REQUIRED" });
    }

    // ✅ 레이트리밋(너무 많이 누르면 막기)
    await rateLimitOrThrow(req);

    // ✅ Turnstile 검증
    const remoteip = getClientIp(req);
    const result = await verifyTurnstile({ token: turnstileToken, remoteip });

    if (!result?.success) {
      return res.status(400).json({
        ok: false,
        error: "TURNSTILE_FAILED",
        codes: result?.["error-codes"] || result?.errorCodes || [],
      });
    }

    // ✅ Google Group 추가
    const out = await addMemberToGroup(emailRaw);

    return res.status(200).json({
      ok: true,
      email: emailRaw,
      group: ENV.FREE_GROUP_EMAIL,
      status: out.status,
    });
  } catch (e) {
    const status = e?.statusCode || 500;

    if (e?.message === "RATE_LIMITED") {
      return res.status(429).json({ ok: false, error: "RATE_LIMITED" });
    }

    console.error("[free-signup] error:", e);
    return res.status(status).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// --------------------
// Listen (Cloud Run은 PORT 필수)
// --------------------
app.listen(ENV.PORT, "0.0.0.0", () => {
  console.log(`free-signup api listening on :${ENV.PORT}`);
  console.log("allowed origins:", ENV.ALLOWED_ORIGINS);
});
