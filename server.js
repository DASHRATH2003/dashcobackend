import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import fs from 'fs';
import fetch from 'node-fetch';
import admin from 'firebase-admin';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 5000;
const FCM_DRIVER = String(process.env.FCM_DRIVER || 'auto').toLowerCase();

// --- CORS Setup ---
const ORIGINS = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (ORIGINS.includes('*') || ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('CORS not allowed'));
  },
  credentials: true
}));

app.use(express.json());

// --- Firebase Admin Init ---
let hasAdmin = false;
try {
  if (!admin.apps || admin.apps.length === 0) {
    let creds = null;
    const jsonEnv = process.env.FIREBASE_ADMIN_CREDENTIALS;
    const jsonB64 = process.env.FIREBASE_ADMIN_CREDENTIALS_BASE64;
    const jsonPath = process.env.FIREBASE_ADMIN_CREDENTIALS_PATH;

    if (jsonEnv) {
      try { creds = JSON.parse(jsonEnv); } catch (e) {
        try { creds = JSON.parse(Buffer.from(jsonEnv, 'base64').toString('utf8')); } catch {}
      }
    }
    if (!creds && jsonB64) {
      try { creds = JSON.parse(Buffer.from(jsonB64, 'base64').toString('utf8')); } catch {}
    }
    if (!creds && jsonPath) {
      try { creds = JSON.parse(fs.readFileSync(jsonPath, 'utf8')); } catch {}
    }

    if (creds) {
      if (creds.private_key && typeof creds.private_key === 'string' && creds.private_key.includes('\\n')) {
        creds.private_key = creds.private_key.replace(/\\n/g, '\n');
      }
      admin.initializeApp({ credential: admin.credential.cert(creds) });
    } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      admin.initializeApp({ credential: admin.credential.applicationDefault() });
    }
  }
  hasAdmin = !!(admin?.apps?.length);
  if (hasAdmin) {
    console.log('Firebase Admin initialized ✅');
  } else {
    console.log('Firebase Admin not configured');
  }
} catch (err) {
  console.error('Firebase Admin init error:', err);
}

// --- Health Check ---
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    fcm: hasAdmin ? 'admin' : (process.env.FCM_SERVER_KEY ? 'legacy' : 'none')
  });
});

// --- Razorpay Key Endpoint ---
app.get('/api/key', (req, res) => {
  res.json({ key_id: process.env.RAZORPAY_KEY_ID || '' });
});

// --- Razorpay Order Creation ---
function getRazorpay() {
  const { RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET } = process.env;
  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) throw new Error('Razorpay keys missing');
  return new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
}

app.post('/api/orders', async (req, res) => {
  try {
    const { amount, currency = 'INR', notes = {} } = req.body || {};
    if (!amount || Number.isNaN(Number(amount))) return res.status(400).json({ error: 'amount required' });

    const instance = getRazorpay();
    const order = await instance.orders.create({
      amount: Math.round(Number(amount) * 100), // paise
      currency,
      receipt: 'rcpt_' + Date.now(),
      notes,
    });

    res.json({ order });
  } catch (err) {
    console.error('Create order error:', err.message);
    res.status(500).json({ error: 'order_creation_failed' });
  }
});

// --- Razorpay Payment Verification ---
app.post('/api/verify', (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
      return res.status(400).json({ error: 'missing_fields' });

    const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
    hmac.update(razorpay_order_id + '|' + razorpay_payment_id);
    const digest = hmac.digest('hex');
    if (digest !== razorpay_signature) return res.status(400).json({ success: false, error: 'invalid_signature' });

    res.json({ success: true });
  } catch (err) {
    console.error('Verify error:', err.message);
    res.status(500).json({ error: 'verification_failed' });
  }
});

// Helper: fetch admin FCM tokens from Firestore
async function fetchAdminTokens() {
  if (!hasAdmin) return [];
  try {
    const collectionName = process.env.FIRESTORE_COLLECTION_ADMIN_TOKENS || 'admin_tokens';
    const db = admin.firestore();
    const snap = await db.collection(collectionName).limit(500).get();
    const tokens = [];
    snap.forEach((d) => {
      const t = (d.data() || {}).token;
      if (t) tokens.push(String(t));
    });
    return Array.from(new Set(tokens));
  } catch (e) {
    console.error('fetchAdminTokens error:', e?.message || e);
    return [];
  }
}

// Register admin/mobile FCM token for notifications
app.post('/api/register-admin-token', async (req, res) => {
  try {
    const { token, device = '', platform = '', user = '' } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token_missing' });
    if (!hasAdmin) return res.status(500).json({ error: 'admin_not_configured' });

    const collectionName = process.env.FIRESTORE_COLLECTION_ADMIN_TOKENS || 'admin_tokens';
    const db = admin.firestore();
    // Upsert by deterministic ID derived from token
    const id = crypto.createHash('sha1').update(String(token)).digest('hex');
    await db.collection(collectionName).doc(id).set({
      token: String(token),
      device: String(device || ''),
      platform: String(platform || ''),
      user: String(user || ''),
      updatedAt: new Date().toISOString(),
      updatedAtMs: Date.now(),
    }, { merge: true });

    res.json({ success: true, id });
  } catch (e) {
    console.error('register-admin-token error:', e);
    res.status(500).json({ error: 'register_failed', message: e?.message || String(e) });
  }
});

// --- Send FCM Notification (Cookie Consent Example) ---
app.post('/api/notify-cookie', async (req, res) => {
  try {
    const { token, decision, page = '', meta = {} } = req.body || {};

    if (!decision) return res.status(400).json({ error: 'decision_missing' });

    const title = decision === 'accepted' ? 'Cookie accepted' : 'Cookie rejected';
    const body = page ? `On ${new URL(page).host}` : 'On your website';
    const data = { type: 'cookie_consent', decision, page, ...meta };

    let driver = 'none';
    let sendOk = false;
    let sendResult = null;
    let sendError = null;

    // Build broadcast token list: include client token (if any), admin tokens from Firestore, and env fallback
    let targetTokens = [];
    try {
      if (token) targetTokens.push(String(token));
      const adminTokens = await fetchAdminTokens();
      targetTokens = targetTokens.concat(adminTokens);
      if (process.env.FCM_NOTIFY_TOKEN) targetTokens.push(String(process.env.FCM_NOTIFY_TOKEN));
      targetTokens = Array.from(new Set(targetTokens.filter(Boolean)));
    } catch {}

    if (targetTokens.length === 0) {
      return res.status(400).json({ error: 'token_missing' });
    }

    // --- Driver selection: force admin/legacy/none or auto ---
    const prefer = FCM_DRIVER;
    const canAdmin = !!hasAdmin;
    const canLegacy = !!process.env.FCM_SERVER_KEY;

    const tryLegacySend = async () => {
  driver = driver === 'admin' ? 'admin_fallback_legacy' : 'legacy';
  try {
    const payload = {
      priority: 'high',
      notification: { title, body },
      data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)]))
    };
    if (targetTokens.length === 1) payload.to = targetTokens[0];
    else payload.registration_ids = targetTokens;
    const response = await fetch('https://fcm.googleapis.com/fcm/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `key=${process.env.FCM_SERVER_KEY}`
      },
      body: JSON.stringify(payload)
    });
    const json = await response.json();
    const ok = Boolean(json?.success) || Array.isArray(json?.results);
    if (ok) {
      sendOk = true;
      sendResult = json;
      sendError = null;
    } else {
      sendError = JSON.stringify(json);
    }
  } catch (e) {
    sendError = e?.message || String(e);
  }
};

    const tryAdminSend = async () => {
      driver = 'admin';
      try {
        let successCount = 0;
        let failureCount = 0;
        let lastError = null;

        for (const t of targetTokens) {
          try {
            const message = {
              token: t,
              notification: { title, body },
              data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)]))
            };
            await admin.messaging().send(message);
            successCount++;
          } catch (err) {
            failureCount++;
            lastError = err?.message || String(err);
          }
        }

        sendOk = successCount > 0;
        sendResult = { successCount, failureCount };
        if (!sendOk && lastError) {
          sendError = lastError;
        }
      } catch (e) {
        sendError = e?.message || String(e);
      }
    };

    if (prefer === 'none') {
      driver = 'none';
      sendOk = false;
    } else if (prefer === 'legacy') {
      if (!canLegacy) {
        sendError = 'legacy_driver_selected_but_FCM_SERVER_KEY_missing';
      } else {
        await tryLegacySend();
      }
    } else if (prefer === 'admin') {
      if (!canAdmin) {
        sendError = 'admin_driver_selected_but_admin_not_configured';
      } else {
        await tryAdminSend();
      }
    } else {
      // auto: try admin first, then legacy fallback
      if (canAdmin) {
        await tryAdminSend();
        if (!sendOk && canLegacy) {
          await tryLegacySend();
        }
      } else if (canLegacy) {
        await tryLegacySend();
      } else {
        driver = 'none';
        sendOk = false;
        sendError = 'fcm_not_configured';
      }
    }

    // Save log to Firestore
    let saved = false;
    let savedId = null;
    let saveError = null;

    try {
      if (hasAdmin) {
        const collection = process.env.FIRESTORE_COLLECTION_NOTIFICATIONS_LOG || 'notifications_log';
        const db = admin.firestore();
        const doc = {
          token: token ? String(token) : '',
          sendError,
          createdAt: new Date().toISOString(),
          createdAtMs: Date.now()
        };
        const ref = await db.collection(collection).add(doc);
        saved = true;
        savedId = ref.id;
      }
    } catch (e) {
      saveError = e?.message || String(e);
    }

    if (driver === 'none') {
      return res.status(500).json({ success: false, driver, error: 'fcm_not_configured', saved, savedId, saveError });
    }

    return res.json({ success: sendOk, driver, result: sendResult, error: sendError, saved, savedId, saveError });
  } catch (err) {
    console.error('notify-cookie error:', err);
    res.status(500).json({ error: 'notify_failed', message: err.message });
  }
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
