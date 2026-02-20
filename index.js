// index.js (Node 20+)
import express from "express";
import { google } from "googleapis";
import admin from "firebase-admin";

const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "200kb" }));

// Firestore init (Cloud Run 실행 서비스계정에 Firestore 권한 필요)
if (!admin.apps.length) admin.initializeApp();
const db = admin.firestore();

// ENV
const ENV = {
  GOOGLE_SA_JSON: process.env.GOOGLE_SA_JSON,
  GOOGLE_ADMIN_SUBJECT: process.env.GOOGLE_ADMIN_SUBJECT,
  GOOGLE_GROUP_EMAIL: process.env.GOOGLE_GROUP_EMAIL, // free-subs@calvestor.com
  TURNSTILE_SECRET: process.env.TURNSTILE_SECRET,
  ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  // rate limit
  RATE_IP_PER_HOUR: Number(process.env.RATE_IP_PER_HOUR || 20),
  RATE_EMAIL_PER_DAY: Number(process.env.RATE_EMAIL_PER_DAY || 3),

  // 디버그(필요시 Cloud Run env로 DEBUG_ERRORS=1 넣고 테스트)
  DEBUG_ERRORS: String(process.env.DEBUG_ERRORS || "") === "1",
};

function must(name, v) {
  if (!v || String(v).trim() === "") throw new Error(`Missing env: ${name}`);
}
must("GOOGLE_SA_JSON", ENV.GOOGLE_SA_JSON);
must("GOOGLE_ADMIN_SUBJECT", ENV.GOOGLE_ADMIN_SUBJECT);
must("GOOGLE_GROUP_EMAIL", ENV.GOOGLE_GROUP_EMAIL);
must("TURNSTILE_SECRET", ENV.TURNSTILE_SECRET);

// CORS
function cors(req, res) {
  const origin = req.headers.origin;

  // origin이 없으면(서버-서버 호출 등) 그냥 통과
  if (!origin) return;

  // 화이트리스트가 비어있으면 "모두 허용"이 되므로 운영에서는 ALLOWED_ORIGINS 넣는 걸 추천
  const allowed =
    ENV.ALLOWED_ORIGINS.length === 0 || ENV.ALLOWED_ORIGINS.includes(origin);

  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  // 브라우저가 preflight에서 보내는 헤더가 더 있을 수 있어 넉넉히 허용
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Requested-With"
  );
  res.setHeader("Access-Control-Max-Age", "3600");
}

app.options("/api/free-signup", (req, res) => {
  cors(req, res);
  return res.status(204).send();
});

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

// Turnstile verify
async function verifyTurnstile(token, ip) {
  const body = new URLSearchParams();
  body.set("secret", ENV.TURNSTILE_SECRET);
  body.set("response", token);
  if (ip) body.set("remoteip", ip);

  const r = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    }
  );

  const data = await r.json().catch(() => ({}));
  return !!data.success;
}

// rate limit (Firestore)
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

    const ttlIp = new Date(now.getTime() + 2 * 60 * 60 * 1000); // 2시간
    const ttlEm = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000); // 2일

    tx.set(ipRef, { count: ipCount, expireAt: ttlIp, ip }, { merge: true });
    tx.set(emRef, { count: emCount, expireAt: ttlEm, email }, { merge: true });
  });
}

// ✅ 서비스계정 JSON 파서(줄바꿈 깨짐/형식 문제 방어)
function parseServiceAccount(raw) {
  const s = String(raw || "").trim();

  // 1) 그대로 JSON인 경우
  let jsonText = s;

  // 2) 혹시 base64로 넣은 경우도 방어(가능성 낮지만)
  if (!s.startsWith("{") && !s.startsWith("[")) {
    try {
      const decoded = Buffer.from(s, "base64").toString("utf8").trim();
      if (decoded.startsWith("{")) jsonText = decoded;
    } catch (_) {}
  }

  const sa = JSON.parse(jsonText);

  // ⭐ 핵심: Secret/env로 넣을 때 private_key 줄바꿈이 \\n으로 깨지는 경우 복구
  if (typeof sa.private_key === "string") {
    sa.private_key = sa.private_key.replace(/\\n/g, "\n");
  }

  if (!sa.client_email || !sa.private_key) {
    throw new Error("BAD_GOOGLE_SA_JSON");
  }
  return sa;
}

// Google Directory client (캐시하면 토큰요청 줄어듦)
let cachedDirectory = null;
let cachedUntil = 0;

async function getDirectoryClient() {
  const now = Date.now();
  if (cachedDirectory && now < cachedUntil) return cachedDirectory;

  const sa = parseServiceAccount(ENV.GOOGLE_SA_JSON);

  const jwt = new google.auth.JWT({
    email: sa.client_email,
    key: sa.private_key,
    scopes: ["https://www.googleapis.com/auth/admin.directory.group.member"],
    subject: ENV.GOOGLE_ADMIN_SUBJECT,
  });

  try {
    await jwt.authorize();
  } catch (e) {
    // gaxios 에러는 여기에 자세한 바디가 들어있음
    const status = e?.response?.status;
    const data = e?.response?.data;
    console.error("GOOGLE_AUTH_FAILED", {
      status,
      data,
      message: e?.message,
    });
    throw new Error("GOOGLE_AUTH_FAILED");
  }

  const directory = google.admin({ version: "directory_v1", auth: jwt });

  // 토큰은 보통 3600s 유효. 안전하게 50분 캐시
  cachedDirectory = directory;
  cachedUntil = now + 50 * 60 * 1000;

  return directory;
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
    const status = e?.response?.status;
    const data = e?.response?.data;

    console.error("GOOGLE_GROUP_ADD_FAILED", { code, status, data, msg });

    if (code === 409 || msg.includes("Member already exists") || msg.includes("duplicate")) {
      return { added: false, already: true };
    }
    throw new Error("GOOGLE_GROUP_ADD_FAILED");
  }
}

// health check
app.get("/healthz", (req, res) => res.json({ ok: true }));

// main endpoint
app.post("/api/free-signup", async (req, res) => {
  cors(req, res);

  const ip = getClientIp(req);
  const email = normalizeEmail(req.body?.email);
  const token = String(req.body?.turnstileToken || "");

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

    if (m === "BAD_GOOGLE_SA_JSON") {
      return res.status(500).json({ ok: false, code: "BAD_GOOGLE_SA_JSON" });
    }
    if (m === "GOOGLE_AUTH_FAILED") {
      return res.status(500).json({ ok: false, code: "GOOGLE_AUTH_FAILED" });
    }
    if (m === "GOOGLE_GROUP_ADD_FAILED") {
      return res.status(500).json({ ok: false, code: "GOOGLE_GROUP_ADD_FAILED" });
    }

    console.error("free-signup error", e);
    return res.status(500).json({ ok: false, code: "SERVER_ERROR" });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Listening on ${port}`));
