// index.js (Node 20+ / ESM)
import express from "express";
import { google } from "googleapis";
import admin from "firebase-admin";

const app = express();
app.disable("x-powered-by");

// --------------------
// ENV
// --------------------
const ENV = {
  GOOGLE_SA_JSON: process.env.GOOGLE_SA_JSON,
  GOOGLE_ADMIN_SUBJECT: process.env.GOOGLE_ADMIN_SUBJECT,
  GOOGLE_GROUP_EMAIL: process.env.GOOGLE_GROUP_EMAIL, // free-subs@calvestor.com
  TURNSTILE_SECRET: process.env.TURNSTILE_SECRET,

  // ✅ CORS 허용 목록 (비어있으면 기본값 사용)
  // Cloud Run 콘솔에서 ALLOWED_ORIGINS를 따로 안 넣어도 동작하도록 기본값을 넣어둠
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS ||
    "https://ihudson.mycafe24.com,https://calvestor.com,https://www.calvestor.com")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  // ✅ 레이트리밋
  RATE_IP_PER_HOUR: Number(process.env.RATE_IP_PER_HOUR || 20),
  RATE_EMAIL_PER_DAY: Number(process.env.RATE_EMAIL_PER_DAY || 3),
};

function must(name, v) {
  if (!v || String(v).trim() === "") throw new Error(`Missing env: ${name}`);
}
must("GOOGLE_SA_JSON", ENV.GOOGLE_SA_JSON);
must("GOOGLE_ADMIN_SUBJECT", ENV.GOOGLE_ADMIN_SUBJECT);
must("GOOGLE_GROUP_EMAIL", ENV.GOOGLE_GROUP_EMAIL);
must("TURNSTILE_SECRET", ENV.TURNSTILE_SECRET);

// --------------------
// ✅ CORS (핵심 수정)
// --------------------
const ALLOWED_ORIGIN_SET = new Set(ENV.ALLOWED_ORIGINS);

function applyCors(req, res) {
  const origin = req.headers.origin;

  // allowlist에 있는 origin만 허용 (보안상 * 금지)
  if (origin && ALLOWED_ORIGIN_SET.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  // preflight에 필수
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "3600");
}

// ✅ CORS를 라우트 안이 아니라 "전역 미들웨어"로 처리 (프리플라이트/에러에서도 헤더 유지)
app.use((req, res, next) => {
  applyCors(req, res);

  // 브라우저가 먼저 보내는 OPTIONS(preflight)는 여기서 바로 끝내야 함
  if (req.method === "OPTIONS") return res.status(204).send();
  next();
});

// JSON body는 CORS 다음에
app.use(express.json({ limit: "200kb" }));

// --------------------
// Firestore init (Cloud Run 실행 서비스계정에 Firestore 권한 필요)
// --------------------
if (!admin.apps.length) admin.initializeApp();
const db = admin.firestore();

// --------------------
// Helpers
// --------------------
function normalizeEmail(raw) {
  const email = String(raw || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
  return email;
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.ip;
}

// --------------------
// Turnstile verify
// --------------------
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

  // 혹시 Cloudflare 응답이 이상하면 안전하게 실패 처리
  if (!r.ok) return false;

  const data = await r.json().catch(() => null);
  return !!data?.success;
}

// --------------------
// ✅ rate limit (Firestore)
// --------------------
async function rateLimitOrThrow({ ip, email }) {
  const now = new Date();
  const hourKey = `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-${now.getUTCDate()}-${now.getUTCHours()}`;
  const dayKey = `${now.getUTCFullYear()}-${now.getUTCMonth() + 1}-${now.getUTCDate()}`;

  const ipDocId = `ip:${ip}:${hourKey}`;
  const emDocId = `email:${email}:${dayKey}`;

  const ipRef = db.collection("rate_limits").doc(ipDocId);
  const emRef = db.collection("rate_limits").doc(emDocId);

  await db.runTransaction(async (tx) => {
    const [ipSnap, emSnap] = await Promise.all([tx.get(ipRef), tx.get(emRef)]);

    const ipCount = (ipSnap.exists ? ipSnap.data().count || 0 : 0) + 1;
    const emCount = (emSnap.exists ? emSnap.data().count || 0 : 0) + 1;

    if (ipCount > ENV.RATE_IP_PER_HOUR) throw new Error("RATE_IP");
    if (emCount > ENV.RATE_EMAIL_PER_DAY) throw new Error("RATE_EMAIL");

    // TTL용 만료시간(나중에 Firestore TTL로 자동 삭제 가능)
    const ttlIp = new Date(now.getTime() + 2 * 60 * 60 * 1000); // 2시간
    const ttlEm = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000); // 2일

    tx.set(ipRef, { count: ipCount, expireAt: ttlIp, ip }, { merge: true });
    tx.set(emRef, { count: emCount, expireAt: ttlEm, email }, { merge: true });
  });
}

// --------------------
// Google Directory client
// --------------------
async function getDirectoryClient() {
  const sa = JSON.parse(ENV.GOOGLE_SA_JSON);
  const jwt = new google.auth.JWT({
    email: sa.client_email,
    key: sa.private_key,
    scopes: ["https://www.googleapis.com/auth/admin.directory.group.member"],
    subject: ENV.GOOGLE_ADMIN_SUBJECT,
  });
  await jwt.authorize();
  return google.admin({ version: "directory_v1", auth: jwt });
}

async function addToGroup(email) {
  const directory = await getDirectoryClient();
  try {
    await directory.members.insert({
      groupKey: ENV.GOOGLE_GROUP_EMAIL,
      requestBody: { email, role: "MEMBER" },
    });
    return { added: true };
  } catch (e) {
    const code = e?.code;
    const msg = String(e?.message || "");
    // 이미 멤버면 “이미 가입됨” 처리
    if (code === 409 || msg.includes("Member already exists") || msg.includes("duplicate")) {
      return { added: false, already: true };
    }
    throw e;
  }
}

// --------------------
// Routes
// --------------------
app.get("/healthz", (req, res) => res.status(200).send("ok"));

app.post("/api/free-signup", async (req, res) => {
  const origin = req.headers.origin;

  // ✅ 서버에서도 origin 체크 (CORS 우회 요청 방지)
  if (origin && !ALLOWED_ORIGIN_SET.has(origin)) {
    return res.status(403).json({ ok: false, code: "FORBIDDEN_ORIGIN", origin });
  }

  const ip = getClientIp(req);
  const email = normalizeEmail(req.body?.email);
  const token = String(req.body?.turnstileToken || "").trim();

  if (!email) return res.status(400).json({ ok: false, code: "INVALID_EMAIL" });
  if (!token) return res.status(400).json({ ok: false, code: "MISSING_CAPTCHA" });

  try {
    // 1) 레이트리밋
    await rateLimitOrThrow({ ip, email });

    // 2) 캡차
    const human = await verifyTurnstile(token, ip);
    if (!human) return res.status(403).json({ ok: false, code: "CAPTCHA_FAILED" });

    // 3) 그룹 추가
    const result = await addToGroup(email);
    return res.json({ ok: true, result });
  } catch (e) {
    const m = String(e?.message || "");
    if (m === "RATE_IP") return res.status(429).json({ ok: false, code: "RATE_IP" });
    if (m === "RATE_EMAIL") return res.status(429).json({ ok: false, code: "RATE_EMAIL" });

    console.error("free-signup error", e);
    return res.status(500).json({ ok: false, code: "SERVER_ERROR" });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Listening on ${port}`);
  console.log("Allowed origins:", [...ALLOWED_ORIGIN_SET]);
});
