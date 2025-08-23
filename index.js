// FIL: index.js

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express(); // ✅ Skapa app INNAN du använder den

// Aktivera CORS
app.use(cors({
  origin: [ 'https://pressify.se', 'https://www.pressify.se' ],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false
}));

// Shopify-info från miljövariabler
const SHOP = process.env.SHOP;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET; 

// 🔽 Nya env för Partner-app & Proxy
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET; // används för App Proxy + OAuth-verifiering
const SCOPES = process.env.SCOPES || 'read_orders,read_customers,write_customers,read_metafields,write_app_proxy';
const HOST = (process.env.HOST || 'https://after-order-1.onrender.com').replace(/\/$/, '');
const ORDER_META_NAMESPACE = process.env.ORDER_META_NAMESPACE || 'order-created';
const ORDER_META_KEY = process.env.ORDER_META_KEY || 'order-created';
// överst bland konfig:
// Publik butik (för delningslänkar till Shopify-sidan)
const STORE_BASE = (process.env.STORE_BASE || 'https://pressify.se').replace(/\/$/, '');
const PUBLIC_PROOF_PATH = process.env.PUBLIC_PROOF_PATH || '/pages/proof';


/* ===== PROOF TOKEN CONFIG & HELPERS (NYTT) ===== */
const PROOF_TOKEN_SECRET = process.env.PROOF_TOKEN_SECRET || 'CHANGE_ME_LONG_RANDOM';
const PROOF_SNAPSHOT_ACTIVITY_LIMIT = parseInt(process.env.PROOF_SNAPSHOT_ACTIVITY_LIMIT || '20', 10);

// b64url helpers
function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function fromB64url(input) {
  input = String(input || '').replace(/-/g,'+').replace(/_/g,'/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString('utf8');
}

// token: payload { orderId, lineItemId, tid, iat }
function signTokenPayload(payloadObj){
  const payload = JSON.stringify(payloadObj);
  const p64 = b64url(payload);
  const sig = crypto.createHmac('sha256', PROOF_TOKEN_SECRET).update(p64).digest('base64url');
  return `${p64}.${sig}`;
}
function verifyAndParseToken(token){
  const parts = String(token || '').split('.');
  if (parts.length !== 2) return null;
  const [p64, sig] = parts;
  const expSig = crypto.createHmac('sha256', PROOF_TOKEN_SECRET).update(p64).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expSig))) return null;
  } catch { return null; }
  try { return JSON.parse(fromB64url(p64)); } catch { return null; }
}
function newTid(){ return crypto.randomBytes(8).toString('hex'); } // per-token id
function nowIso(){ return new Date().toISOString(); }

// Läs/skriv order-created
async function readOrderProjects(orderId) {
  const { data } = await axios.get(
    `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
    { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
  );
  const mf = (data.metafields || []).find(m => m.namespace === ORDER_META_NAMESPACE && m.key === ORDER_META_KEY);
  if (!mf) return { metafieldId: null, projects: [] };
  try { return { metafieldId: mf.id, projects: JSON.parse(mf.value || '[]') || [] }; }
  catch { return { metafieldId: mf.id, projects: [] }; }
}
async function writeOrderProjects(metafieldId, projects) {
  await axios.put(
    `https://${SHOP}/admin/api/2025-07/metafields/${metafieldId}.json`,
    { metafield: { id: metafieldId, type: 'json', value: JSON.stringify(projects) } },
    { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
  );
}

/* ===== REVIEWS: produkt-metafält helpers (NYTT) ===== */
const PRODUCT_REVIEW_NS = 'review';
const PRODUCT_REVIEW_KEY = 'review';

async function readProductReviews(productId) {
  try {
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/products/${productId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const mf = (data.metafields || []).find(m => m.namespace === PRODUCT_REVIEW_NS && m.key === PRODUCT_REVIEW_KEY);
    if (!mf) return { metafieldId: null, reviews: [] };
    try { return { metafieldId: mf.id, reviews: JSON.parse(mf.value || '[]') || [] }; }
    catch { return { metafieldId: mf.id, reviews: [] }; }
  } catch (e) {
    console.warn('readProductReviews():', e?.response?.data || e.message);
    return { metafieldId: null, reviews: [] };
  }
}
async function writeProductReviews(productId, metafieldId, reviewsArray) {
  const payload = { metafield: { namespace: PRODUCT_REVIEW_NS, key: PRODUCT_REVIEW_KEY, type: 'json', value: JSON.stringify(reviewsArray || []) } };
  try {
    if (metafieldId) {
      await axios.put(
        `https://${SHOP}/admin/api/2025-07/metafields/${metafieldId}.json`,
        { metafield: { id: metafieldId, ...payload.metafield } },
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
    } else {
      await axios.post(
        `https://${SHOP}/admin/api/2025-07/products/${productId}/metafields.json`,
        payload,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
    }
  } catch (e) {
    console.warn('writeProductReviews():', e?.response?.data || e.message);
  }
}
/* ===== END REVIEWS helpers ===== */

// Snapshot helpers
function safeProjectFields(p){
  return {
    previewUrl: p.previewUrl || p.preview_img || null,
    productTitle: p.productTitle || '',
    quantity: typeof p.quantity === 'number' ? p.quantity : 1,
    proofNote: p.proofNote || null
  };
}
function sliceActivityForLine(log, lineItemId){
  const arr = Array.isArray(log) ? log.filter(e => String(e?.line_item_id) === String(lineItemId)) : [];
  arr.sort((a,b)=> new Date(a?.ts||0) - new Date(b?.ts||0)); // äldst → nyast
  const cut = Math.max(0, arr.length - PROOF_SNAPSHOT_ACTIVITY_LIMIT);
  return arr.slice(cut);
}
/* ===== END PROOF TOKEN HELPERS ===== */


// 🔰 NYTT: Global throttling/retry för Shopify Admin API (utan att ändra dina handlers)
const SHOP_ADMIN_PATTERN = SHOP ? `${SHOP}/admin/api/` : '/admin/api/';
let __lastAdminCallAt = 0;

axios.interceptors.request.use(async (config) => {
  try {
    const url = (config.baseURL || '') + (config.url || '');
    if (url.includes(SHOP_ADMIN_PATTERN)) {
      const now = Date.now();
      const wait = Math.max(0, 550 - (now - __lastAdminCallAt)); // ~2 calls/sek
      if (wait) {
        await new Promise(r => setTimeout(r, wait));
      }
      __lastAdminCallAt = Date.now();
    }
  } catch {}
  return config;
});

axios.interceptors.response.use(
  (res) => res,
  async (error) => {
    const { response, config } = error || {};
    const url = ((config && (config.baseURL || '')) + (config && config.url || '')) || '';
    if (response && response.status === 429 && url.includes(SHOP_ADMIN_PATTERN)) {
      config.__retryCount = (config.__retryCount || 0) + 1;
      if (config.__retryCount <= 3) {
        const ra = parseFloat(response.headers?.['retry-after']) || 1;
        await new Promise(r => setTimeout(r, ra * 1000));
        return axios(config); // prova igen
      }
    }
    return Promise.reject(error);
  }
);

// Enkel in-memory store för OAuth state & (ev.) tokens per shop
const oauthStateStore = {};   // { state: shop }
const shopTokenStore = {};    // { shop: token }  // OBS: din kod använder fortfarande ACCESS_TOKEN – detta är för framtida bruk

// Temporär lagring för förhandsdata från frontend
const temporaryStorage = {}; // { [projectId]: { previewUrl, cloudinaryPublicId, instructions, date } }

// Middleware
app.use(bodyParser.json({ verify: (req, res, buf) => {
  req.rawBody = buf;
}}));
// ⬇️ NYTT: för att hantera application/x-www-form-urlencoded från HTML-formulär
app.use(bodyParser.urlencoded({ extended: true }));

// Liten hälsosida så "Cannot GET /" försvinner
app.get('/', (req, res) => res.type('text').send('OK'));
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ===== OAuth (Partner-app) =====
// Starta installationen: /auth?shop=xxxx.myshopify.com
app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send('Missing ?shop');

  const state = crypto.randomBytes(16).toString('hex');
  oauthStateStore[state] = shop;

  const redirectUri = `${HOST}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(SHOPIFY_API_KEY)}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});

// Verifiera HMAC på OAuth-queryn (använder hmac-param)
function verifyOAuthHmac(query) {
  const { hmac, signature, ...rest } = query;
  const ordered = Object.keys(rest).sort().map(k => `${k}=${Array.isArray(rest[k]) ? rest[k].join(',') : rest[k]}`).join('&');
  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(ordered).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest, 'utf8'), Buffer.from(String(hmac || ''), 'utf8'));
  } catch {
    return false;
  }
}

// Callback efter godkännande
app.get('/auth/callback', async (req, res) => {
  const { shop, hmac, code, state } = req.query;
  if (!shop || !hmac || !code || !state) return res.status(400).send('Missing params');
  if (oauthStateStore[state] !== shop) return res.status(400).send('Invalid state');
  if (!verifyOAuthHmac(req.query)) return res.status(400).send('Invalid HMAC');

  try {
    const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: SHOPIFY_API_KEY,
      client_secret: SHOPIFY_API_SECRET,
      code
    });
    const accessToken = tokenRes.data.access_token;
    shopTokenStore[shop] = accessToken; // (valfritt) – din nuvarande kod använder ACCESS_TOKEN, inte denna

    // Snyggt avslut på installationen
    return res.type('html').send('<html><body style="font-family:sans-serif">App installed ✔️<br/>You can close this tab.</body></html>');
  } catch (e) {
    console.error('OAuth exchange failed:', e?.response?.data || e.message);
    return res.status(500).send('OAuth failed');
  }
});
// ===== END OAuth =====

// Verifiera Shopify-signatur (webhooks – behåll som du hade, eftersom dina webhooks tillhör gamla appen)
function verifyShopifyRequest(req) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  const digest = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody, 'utf8')
    .digest('base64');

  return digest === hmacHeader;
}

/* ============================================================
   ==== ACTIVITY LOG: Helper-funktioner (namespace=activity) ===
   - LÄSER/SKRIVER order.metafields.activity.activity (type=json)
   - Påverkar INTE befintlig order-created-logik
   ============================================================ */
const ACTIVITY_NS = 'activity';
const ACTIVITY_KEY = 'activity';

// Hämta/parse:a aktivitetslogg (array) för en order
async function getActivityLog(orderId) {
  try {
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const mf = (data.metafields || []).find(m => m.namespace === ACTIVITY_NS && m.key === ACTIVITY_KEY);
    if (!mf) return { metafieldId: null, log: [] };
    try {
      const arr = JSON.parse(mf.value || '[]');
      return { metafieldId: mf.id, log: Array.isArray(arr) ? arr : [] };
    } catch {
      return { metafieldId: mf.id, log: [] };
    }
  } catch (e) {
    console.warn('getActivityLog():', e?.response?.data || e.message);
    return { metafieldId: null, log: [] };
  }
}

// Skriv (PUT/POST) aktivitetslogg (array) till order
async function writeActivityLog(orderId, metafieldId, logArray) {
  const payload = { metafield: { type: 'json', value: JSON.stringify(logArray) } };
  try {
    if (metafieldId) {
      // PUT
      await axios.put(
        `https://${SHOP}/admin/api/2025-07/metafields/${metafieldId}.json`,
        { metafield: { id: metafieldId, ...payload.metafield, namespace: ACTIVITY_NS, key: ACTIVITY_KEY } },
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
    } else {
      // POST
      await axios.post(
        `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
        { metafield: { namespace: ACTIVITY_NS, key: ACTIVITY_KEY, ...payload.metafield } },
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
    }
  } catch (e) {
    console.warn('writeActivityLog():', e?.response?.data || e.message);
  }
}

// Lägg till entries i aktivitetslogg med enkel idempotens på correlation_id
async function appendActivity(orderId, entries) {
  try {
    if (!orderId || !Array.isArray(entries) || !entries.length) return;
    const { metafieldId, log } = await getActivityLog(orderId);

    // Idempotens: om entry har correlation_id och den redan finns, hoppa över
    const have = new Set(log.map(e => e && e.correlation_id).filter(Boolean));
    const toAdd = entries.filter(e => {
      if (!e || typeof e !== 'object') return false;
      if (e.correlation_id && have.has(e.correlation_id)) return false;
      return true;
    });
    if (!toAdd.length) return;

    const next = log.concat(toAdd);
    await writeActivityLog(orderId, metafieldId, next);
  } catch (e) {
    console.warn('appendActivity():', e?.response?.data || e.message);
  }
}

// Hjälp: hämta kundnamn (för request-changes/approve)
async function getCustomerNameByOrder(orderId) {
  try {
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const c = data?.order?.customer || {};
    const first = (c.first_name || '').trim();
    const last = (c.last_name || '').trim();
    const full = [first, last].filter(Boolean).join(' ').trim();
    return { name: full || 'Kund', id: c.id ? `customer:${c.id}` : undefined };
  } catch {
    return { name: 'Kund' };
  }
}
/* ========================== END ACTIVITY LOG =========================== */

// === ACTIVITY: Läs-endpoint (påverkar inte övrig logik)
app.get('/activity', async (req, res) => {
  try {
    const orderId = req.query.orderId;
    if (!orderId) return res.status(400).json({ error: 'orderId krävs' });

    const { log } = await getActivityLog(orderId);

    // Valfri filtrering per line item: ?lineItemId=...
    const lineItemId = req.query.lineItemId;
    let out = Array.isArray(log) ? log.slice() : [];
    if (lineItemId != null) {
      out = out.filter(e => String(e?.line_item_id) === String(lineItemId));
    }

    // sortera äldst → nyast
    out.sort((a,b) => new Date(a?.ts || 0) - new Date(b?.ts || 0));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ log: out });
  } catch (e) {
    console.error('GET /activity error:', e?.response?.data || e.message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// Tar emot förhandsdata innan order läggs
app.post('/precheckout-store', (req, res) => {
  const { projectId, previewUrl, cloudinaryPublicId, instructions } = req.body;


  if (!projectId || !previewUrl) {
    return res.status(400).json({ error: 'projectId och previewUrl krävs' });
  }

  temporaryStorage[projectId] = {
    previewUrl,
    cloudinaryPublicId,
    instructions,
    date: new Date().toISOString()
  };

  console.log(`💾 Sparade temporärt projekt för ${projectId}`);
  res.sendStatus(200);
});

// Webhook: Order skapad
app.post('/webhooks/order-created', async (req, res) => {
  console.log('📬 Webhook mottagen');

  if (!verifyShopifyRequest(req)) {
    console.warn('❌ Ogiltig Shopify-signatur!');
    return res.sendStatus(401);
  }

  const order = req.body;
  const orderId = order.id;
  const customerId = order.customer?.id;
  const orderNumber = order.name;
  const lineItems = order.line_items || [];

  // Mappa varje radpost till ett projekt
  const newProjects = lineItems.map(item => {
    // Ta med alla line item properties
    const props = item.properties || [];

    // Hämta projekt-id (originalt filnamn) från line item properties
    const projectId = props.find(p => p.name === 'Tryckfil')?.value;
    const fallback = projectId ? (temporaryStorage[projectId] || {}) : {};

    // Hämta instruktioner direkt från properties om de finns, annars från fallback
    const instructionProp = props.find(p => p.name === 'instructions')?.value;
    const instructions = instructionProp != null
      ? instructionProp
      : (fallback.instructions || null);

    return {
      orderId,
      lineItemId:        item.id,
      productId:         item.product_id,
      productTitle:      item.title,
      variantId:         item.variant_id,
      variantTitle:      item.variant_title,
      quantity:          item.quantity,
      properties:        props,
      preview_img:       fallback.previewUrl || null,
      cloudinaryPublicId: fallback.cloudinaryPublicId || null,
      instructions,     // <-- nu inkluderar vi både property- eller fallback-instruktioner
      customerId,
      orderNumber,
      status:            'Tar fram korrektur',
      tag:               'Tar fram korrektur',
      date:              new Date().toISOString(),
      review: { status: 'pending' }
    };
  });

  if (newProjects.length === 0) return res.sendStatus(200);

  try {
    // Hämta befintliga metafält (🔧 fixad URL)
    const existing = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`, {
        headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
      }
    );

    const currentMetafield = existing.data.metafields.find(mf =>
      mf.namespace === 'order-created' && mf.key === 'order-created'
    );

    // Kombinera nya med gamla projekt
    let combined = [...newProjects];
    if (currentMetafield && currentMetafield.value) {
      try {
        const existingData = JSON.parse(currentMetafield.value);
        if (Array.isArray(existingData)) {
          combined = [...existingData, ...newProjects];
        }
      } catch (e) {
        console.warn('Kunde inte tolka gammal JSON:', e);
      }
    }

    // Uppdatera eller skapa metafältet
    if (currentMetafield) {
      await axios.put(
        `https://${SHOP}/admin/api/2025-07/metafields/${currentMetafield.id}.json`,
        { metafield: { id: currentMetafield.id, type: 'json', value: JSON.stringify(combined) } },
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
    } else {
      await axios.post(
        `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
        { metafield: { namespace: 'order-created', key: 'order-created', type: 'json', value: JSON.stringify(combined) } },
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
    }

    console.log('✅ Metafält sparat!');

    /* ==== ACTIVITY LOG: Första loggen per line item (file.uploaded) ==== */
    try {
      const customerName = ((order.customer?.first_name || '') + ' ' + (order.customer?.last_name || '')).trim() || 'Kund';
      const customerActor = { type: 'customer', name: customerName, id: customerId ? `customer:${customerId}` : undefined };
      const ts = order.processed_at || order.created_at || new Date().toISOString();

      const firstEntries = combined.map(p => {
        // Hitta filnamn från property "Tryckfil"
        let fileName = '';
        try {
          fileName = (p.properties || []).find(x => x && x.name === 'Tryckfil')?.value || '';
        } catch {}
        const entry = {
          ts,
          actor: customerActor,
          action: 'file.uploaded',
          order_id: orderId,
          line_item_id: p.lineItemId,
          product_title: p.productTitle,
          project_id: fileName || undefined,
          data: Object.assign(
            {},
            fileName ? { fileName } : {},
            p.instructions ? { instructions: String(p.instructions) } : {}
          ),
          correlation_id: `order.created:${orderId}:${p.lineItemId}`
        };
        return entry;
      });

      await appendActivity(orderId, firstEntries);
    } catch (e) {
      console.warn('order-created → appendActivity misslyckades:', e?.response?.data || e.message);
    }
    /* ======================= END ACTIVITY LOG ======================= */

    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Fel vid webhook/order-created:', err?.response?.data || err.message);
    res.sendStatus(500);
  }
});

// Hämta korrektur-status för kund
app.get('/pages/korrektur', async (req, res) => {
  const customerId = req.query.customerId;
  if (!customerId) return res.status(400).json({ error: 'customerId krävs' });

  try {
    const ordersRes = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders.json?customer_id=${customerId}`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

    const orders = ordersRes.data.orders || [];
    const results = [];

    for (const order of orders) {
      const metafieldsRes = await axios.get(
        `https://${SHOP}/admin/api/2025-07/orders/${order.id}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );

      const proofMetafield = metafieldsRes.data.metafields.find(mf =>
        mf.namespace === 'order-created' && mf.key === 'order-created'
      );
      if (!proofMetafield) continue;

      const projects = JSON.parse(proofMetafield.value || '[]');
      const enriched = projects.map(p => ({ ...p, orderId: order.id }));
      const awaiting = enriched.filter(p => p.status === 'Korrektur redo');

      results.push(...awaiting);
    }

    if (results.length === 0) {
      return res.json({ message: 'Just nu har du ingenting att godkänna', projects: [] });
    }

    res.json({ message: 'Godkänn korrektur', projects: results });
  } catch (err) {
    console.error('❌ Fel vid hämtning av korrektur:', err?.response?.data || err.message);
    res.status(500).json({ error: 'Internt serverfel' });
  }
});

// Uppdatera korrektur-status (när du laddar upp korrekturbild)
// Uppdatera korrektur-status (när du laddar upp korrekturbild) — TOKENS + SNAPSHOT
app.post('/proof/upload', async (req, res) => {
  const { orderId, lineItemId, previewUrl, proofNote } = req.body;
  if (!orderId || !lineItemId || !previewUrl) return res.status(400).json({ error: 'orderId, lineItemId och previewUrl krävs' });

  try {
    // Läs order-created
    const { metafieldId, projects } = await readOrderProjects(orderId);
    if (!metafieldId) return res.status(404).json({ error: 'Metafält hittades inte' });

    // 1) Uppdatera preview/status (som tidigare)
    let exists = false;
    const nextProjects = projects.map(p => {
      if (String(p.lineItemId) === String(lineItemId)) {
        exists = true;
        return {
          ...p,
          previewUrl,
          ...(typeof proofNote === 'string' && proofNote.trim() ? { proofNote: proofNote.trim() } : {}),
          status: 'Korrektur redo'
        };
      }
      return p;
    });
    if (!exists) return res.status(404).json({ error: 'Line item hittades inte i metafält' });

    // 2) Snapshot: “första” activity-hämtningen (för snabb token-vy)
    const { log } = await getActivityLog(orderId);
    const snapActivity = sliceActivityForLine(log, lineItemId);
    const projAfter = nextProjects.find(p => String(p.lineItemId) === String(lineItemId));
    const snap = { ...safeProjectFields(projAfter), activity: snapActivity, hideActivity: false };

    // 3) Generera token + tid (kort id)
    const tid = newTid();
    const token = signTokenPayload({ orderId: Number(orderId), lineItemId: Number(lineItemId), tid, iat: Date.now() });

    // 4) Rotera shares[] under rätt line item
    const rotated = nextProjects.map(p => {
      if (String(p.lineItemId) !== String(lineItemId)) return p;
      const prev = Array.isArray(p.shares) ? p.shares : [];
      const superseded = prev.map(s => ({ ...s, status: s.status === 'active' ? 'superseded' : (s.status || 'superseded') }));
      const share = {
        tid,
        token_hash: crypto.createHash('sha256').update(token).digest('hex'),
        status: 'active',
        createdAt: nowIso(),
        snapshot: snap
      };
      return { ...p, shares: [share, ...superseded].slice(0, 10), latestToken: tid };
    });

    // 5) Spara tillbaka i SAMMA metafält
    await writeOrderProjects(metafieldId, rotated);

    // 6) Logga som tidigare
    try {
      const proj = rotated.find(p => String(p.lineItemId) === String(lineItemId)) || {};
      const fileName = (() => {
        try { return (proj.properties || []).find(x => x && x.name === 'Tryckfil')?.value || ''; } catch { return ''; }
      })();
      await appendActivity(orderId, [{
        ts: new Date().toISOString(),
        actor: { type: 'admin', name: 'Pressify' },
        action: 'proof.uploaded',
        order_id: Number(orderId),
        line_item_id: Number(lineItemId),
        product_title: proj.productTitle || '',
        project_id: fileName || undefined,
        data: Object.assign({ previewUrl }, (proofNote && proofNote.trim() ? { note: proofNote.trim() } : {})),
        correlation_id: `proof.uploaded:${orderId}:${lineItemId}:${previewUrl}`
      }]);
    } catch (e) {
      console.warn('/proof/upload → appendActivity misslyckades:', e?.response?.data || e.message);
    }

// 7) Svara med token + URL till butikens publika sida (Shopify pages kan inte ha dynamiska segments)
// Använd query-param: /pages/proof?token=...
const url = `${STORE_BASE}${PUBLIC_PROOF_PATH}?token=${encodeURIComponent(token)}`;

// (valfritt) skicka även backend-länken om du vill felsöka
const backendShare = `${HOST}/proof/share/${encodeURIComponent(token)}`;

return res.json({ ok: true, token, url, backendShare });

  } catch (err) {
    console.error('❌ Fel vid /proof/upload:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Kunde inte uppdatera korrektur' });
  }
});



// Godkänn korrektur
app.post('/proof/approve', async (req, res) => {
  const { orderId, lineItemId } = req.body;
  if (!orderId || !lineItemId) return res.status(400).json({ error: 'orderId och lineItemId krävs' });

  try {
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

    const metafield = data.metafields.find(mf => mf.namespace === 'order-created' && mf.key === 'order-created');
    if (!metafield) return res.status(404).json({ error: 'Metafält hittades inte' });

let projects = JSON.parse(metafield.value || '[]');
projects = projects.map(p => {
  if (p.lineItemId == lineItemId) {
    return {
      ...p,
      status: 'I produktion',
      // 👇 Promote approved proof → becomes the image shown på ordersidan
      preview_img: p.previewUrl || p.preview_img || null
    };
  }
  return p;
});


    await axios.put(
      `https://${SHOP}/admin/api/2025-07/metafields/${metafield.id}.json`,
      { metafield: { id: metafield.id, type: 'json', value: JSON.stringify(projects) } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

    /* ==== ACTIVITY LOG: Kund godkände korrektur ==== */
    try {
      const proj = projects.find(p => String(p.lineItemId) === String(lineItemId)) || {};
      const fileName = (() => {
        try { return (proj.properties || []).find(x => x && x.name === 'Tryckfil')?.value || ''; } catch { return ''; }
      })();
      const cust = await getCustomerNameByOrder(orderId);

      await appendActivity(orderId, [{
        ts: new Date().toISOString(),
        actor: { type: 'customer', name: cust.name, id: cust.id },
        action: 'proof.approved',
        order_id: Number(orderId),
        line_item_id: Number(lineItemId),
        product_title: proj.productTitle || '',
        project_id: fileName || undefined,
        data: {},
        correlation_id: `proof.approved:${orderId}:${lineItemId}`
      }]);
    } catch (e) {
      console.warn('/proof/approve → appendActivity misslyckades:', e?.response?.data || e.message);
    }
    /* ======================= END ACTIVITY LOG ======================= */
    // 🧹 NYTT: Dölj activity i aktiv share.snapshot för tokensidan, men behåll preview/product/qty
    try {
      const { metafieldId, projects: prj2 } = await readOrderProjects(orderId);
      if (metafieldId && Array.isArray(prj2)) {
        const idx = prj2.findIndex(p => String(p.lineItemId) === String(lineItemId));
        if (idx >= 0) {
          const p = prj2[idx];
          const shares = Array.isArray(p.shares) ? p.shares : [];
          const activeIdx = shares.findIndex(s => s && s.status === 'active');
          if (activeIdx >= 0) {
            const snap = { ...(shares[activeIdx].snapshot || {}) };
            shares[activeIdx] = { ...shares[activeIdx], snapshot: { ...snap, hideActivity: true } };
            prj2[idx] = { ...p, shares };
            await writeOrderProjects(metafieldId, prj2);
          }
        }
      }
    } catch (e) {
      console.warn('mark hideActivity on approve failed:', e?.response?.data || e.message);
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Fel vid /proof/approve:', err?.response?.data || err.message);
    res.status(500).json({ error: 'Kunde inte godkänna korrektur' });
  }
});

// Begär ändringar – uppdaterar status + instructions
app.post('/proof/request-changes', async (req, res) => {
  console.log('🏷️ /proof/request-changes called with:', req.body);
  const { orderId, lineItemId, instructions } = req.body;
  if (!orderId || !lineItemId || !instructions) {
    console.warn('⚠️ Missing parameters in request-changes:', req.body);
    return res.status(400).json({ error: 'orderId, lineItemId och instructions krävs' });
  }

  try {
    const mfRes = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const metafield = mfRes.data.metafields.find(mf =>
      mf.namespace === 'order-created' && mf.key === 'order-created'
    );
    if (!metafield) {
      console.error('❌ Metafält hittades inte vid request-changes');
      return res.status(404).json({ error: 'Metafält hittades inte' });
    }

    let projects = JSON.parse(metafield.value || '[]');
    console.log('⏳ Projects before update:', projects);
    let updated = false;
    projects = projects.map(p => {
      if (String(p.lineItemId) === String(lineItemId)) {
        updated = true;
        return { ...p, instructions, status: 'Tar fram korrektur', tag: 'Tar fram korrektur' };
      }
      return p;
    });

    if (!updated) {
      console.warn('⚠️ Line item hittades inte i metafält vid request-changes:', lineItemId);
      return res.status(404).json({ error: 'Line item hittades inte i metafält' });
    }

    console.log('✨ Projects after update:', projects);
    const putRes = await axios.put(
      `https://${SHOP}/admin/api/2025-07/metafields/${metafield.id}.json`,
      { metafield: { id: metafield.id, type: 'json', value: JSON.stringify(projects) } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    console.log('✅ Shopify response for request-changes:', putRes.status);

    /* ==== ACTIVITY LOG: Kund begärde ändringar ==== */
    try {
      const proj = projects.find(p => String(p.lineItemId) === String(lineItemId)) || {};
      const fileName = (() => {
        try { return (proj.properties || []).find(x => x && x.name === 'Tryckfil')?.value || ''; } catch { return ''; }
      })();
      const cust = await getCustomerNameByOrder(orderId);

      await appendActivity(orderId, [{
        ts: new Date().toISOString(),
        actor: { type: 'customer', name: cust.name, id: cust.id },
        action: 'changes.requested',
        order_id: Number(orderId),
        line_item_id: Number(lineItemId),
        product_title: proj.productTitle || '',
        project_id: fileName || undefined,
        data: { instructions: String(instructions || '').trim() },
        correlation_id: `changes.requested:${orderId}:${lineItemId}:${crypto.createHash('sha256').update(String(instructions || '')).digest('hex')}`
      }]);
    } catch (e) {
      console.warn('/proof/request-changes → appendActivity misslyckades:', e?.response?.data || e.message);
    }
    /* ======================= END ACTIVITY LOG ======================= */
    // 🔁 NYTT: Spegla senaste activity in i aktiv share.snapshot.activity
    try {
      const { metafieldId, projects: prj2 } = await readOrderProjects(orderId);
      if (metafieldId && Array.isArray(prj2)) {
        const idx = prj2.findIndex(p => String(p.lineItemId) === String(lineItemId));
        if (idx >= 0) {
          const p = prj2[idx];
          const shares = Array.isArray(p.shares) ? p.shares : [];
          const activeIdx = shares.findIndex(s => s && s.status === 'active');
          if (activeIdx >= 0) {
            const { log } = await getActivityLog(orderId);
            const merged = sliceActivityForLine(log, lineItemId); // “första + nya”
            shares[activeIdx] = {
              ...shares[activeIdx],
              snapshot: { ...(shares[activeIdx].snapshot || {}), activity: merged }
            };
            prj2[idx] = { ...p, shares };
            await writeOrderProjects(metafieldId, prj2);
          }
        }
      }
    } catch (e) {
      console.warn('mirror activity into active share failed:', e?.response?.data || e.message);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Fel vid /proof/request-changes:', err?.response?.data || err.message);
    res.status(500).json({ error: 'Kunde inte uppdatera korrektur' });
  }
});

// ===== APP PROXY: /apps/orders-meta =====
// Verifiering av App Proxy-signatur (använder partner-appens "Klienthemlighet")
function xySignature(search) {
  const params = new URLSearchParams(search || "");
  const signature = params.get("signature");
  if (!signature) return false;
  params.delete("signature");

  const parts = [];
  Array.from(params.keys())
    .sort()
    .forEach((k) => {
      parts.push(`${k}=${params.getAll(k).join(",")}`);
    });

  const message = parts.join("");
  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
  } catch {
    return false;
  }
}

// alias
const verifyAppProxySignature = xySignature;

// ===== APP PROXY: /proxy/avatar (mappar från /apps/.../avatar) =====
app.all('/proxy/avatar', async (req, res) => {
  try {
    // 1) Verifiera att anropet kommer via Shopify App Proxy
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // 2) Kräver inloggad kund (Shopify bifogar logged_in_customer_id)
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'Not logged in' });

    if (req.method === 'GET') {
      // Hämta nuvarande metafält
      const mfRes = await axios.get(
        `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const mf = (mfRes.data.metafields || []).find(m => m.namespace === 'Profilbild' && m.key === 'Profilbild');
      return res.json({ metafield: mf ? mf.value : null });
    }

    if (req.method === 'POST') {
      const { action, meta } = req.body || {};

      // Hämta ev. befintligt metafält
      const existingRes = await axios.get(
        `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const existing = (existingRes.data.metafields || []).find(m => m.namespace === 'Profilbild' && m.key === 'Profilbild');

      if (action === 'delete') {
        if (existing) {
          await axios.delete(
            `https://${SHOP}/admin/api/2025-07/metafields/${existing.id}.json`,
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
        }
        return res.json({ ok: true, deleted: true });
      }

      if (action === 'save') {
        // Tillåt att spara enbart selection/marketing/role, eller bild, eller kombination
        if (
          !meta ||
          (
            !meta.public_id &&
            !meta.secure_url &&
            typeof meta.selection === 'undefined' &&
            typeof meta.marketing === 'undefined' &&
            typeof meta.role === 'undefined'
          )
        ) {
          return res.status(400).json({ error: 'Invalid meta payload' });
        }

        // Bevara tidigare metafält-värde (om det finns)
        let existingValue = {};
        try { existingValue = existing?.value ? JSON.parse(existing.value) : {}; } catch {}

        // Normalisera inkommande fält
        const normalizeBool = (v) => {
          if (typeof v === 'boolean') return v;
          if (typeof v === 'number') return v !== 0;
          if (typeof v === 'string') return /^(true|1|yes|on)$/i.test(v.trim());
          return false;
        };

        const payload = {
          namespace: 'Profilbild',
          key: 'Profilbild',
          type: 'json',
          value: JSON.stringify({
            // Bildfält – bevara om ej skickas
            public_id:  String(meta.public_id ?? existingValue.public_id ?? ''),
            version:    meta.version ?? existingValue.version ?? null,
            secure_url: String(meta.secure_url ?? existingValue.secure_url ?? ''),

            // Nya fält – bevara om ej skickas
            selection:  String(meta.selection ?? existingValue.selection ?? ''),  // dropdown
            marketing:  (typeof meta.marketing !== 'undefined')
                          ? normalizeBool(meta.marketing)
                          : (typeof existingValue.marketing !== 'undefined' ? !!existingValue.marketing : false),
            role:       String(meta.role ?? existingValue.role ?? ''),           // arbetsroll

            // Uppdaterad timestamp
            updatedAt:  new Date().toISOString()
          })
        };

        if (existing) {
          await axios.put(
            `https://${SHOP}/admin/api/2025-07/metafields/${existing.id}.json`,
            { metafield: { id: existing.id, ...payload } },
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
        } else {
          await axios.post(
            `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
            { metafield: payload },
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
        }

        return res.json({ ok: true });
      }

      return res.status(400).json({ error: 'Unknown action' });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('/proxy/avatar error:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ===== DUPLICATE ROUTE for stores where Proxy URL includes "/proxy/orders-meta" =====
app.all('/proxy/orders-meta/avatar', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'Not logged in' });

    if (req.method === 'GET') {
      const mfRes = await axios.get(
        `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const mf = (mfRes.data.metafields || []).find(m => m.namespace === 'Profilbild' && m.key === 'Profilbild');
      return res.json({ metafield: mf ? mf.value : null });
    }

    if (req.method === 'POST') {
      const { action, meta } = req.body || {};

      const existingRes = await axios.get(
        `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const existing = (existingRes.data.metafields || []).find(m => m.namespace === 'Profilbild' && m.key === 'Profilbild');

      if (action === 'delete') {
        if (existing) {
          await axios.delete(
            `https://${SHOP}/admin/api/2025-07/metafields/${existing.id}.json`,
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
        }
        return res.json({ ok: true, deleted: true });
      }

      if (action === 'save') {
        // Tillåt att spara enbart selection/marketing/role, eller bild, eller kombination
        if (
          !meta ||
          (
            !meta.public_id &&
            !meta.secure_url &&
            typeof meta.selection === 'undefined' &&
            typeof meta.marketing === 'undefined' &&
            typeof meta.role === 'undefined'
          )
        ) {
          return res.status(400).json({ error: 'Invalid meta payload' });
        }

        // Hämta ev. befintligt metafält (för att bevara gamla värden)
        const mfRes2 = await axios.get(
          `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
        const existing2 = (mfRes2.data.metafields || []).find(m => m.namespace === 'Profilbild' && m.key === 'Profilbild');

        let existingValue = {};
        try { existingValue = existing2?.value ? JSON.parse(existing2.value) : {}; } catch {}

        const normalizeBool = (v) => {
          if (typeof v === 'boolean') return v;
          if (typeof v === 'number') return v !== 0;
          if (typeof v === 'string') return /^(true|1|yes|on)$/i.test(v.trim());
          return false;
        };

        const payload = {
          namespace: 'Profilbild',
          key: 'Profilbild',
          type: 'json',
          value: JSON.stringify({
            public_id:  String(meta.public_id ?? existingValue.public_id ?? ''),
            version:    meta.version ?? existingValue.version ?? null,
            secure_url: String(meta.secure_url ?? existingValue.secure_url ?? ''),

            selection:  String(meta.selection ?? existingValue.selection ?? ''),
            marketing:  (typeof meta.marketing !== 'undefined')
                          ? normalizeBool(meta.marketing)
                          : (typeof existingValue.marketing !== 'undefined' ? !!existingValue.marketing : false),
            role:       String(meta.role ?? existingValue.role ?? ''),

            updatedAt:  new Date().toISOString()
          })
        };

        if (existing2) {
          await axios.put(
            `https://${SHOP}/admin/api/2025-07/metafields/${existing2.id}.json`,
            { metafield: { id: existing2.id, ...payload } },
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
        } else {
          await axios.post(
            `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
            { metafield: payload },
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
        }

        return res.json({ ok: true });
      }

      return res.status(400).json({ error: 'Unknown action' });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('/proxy/orders-meta/avatar error:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// 🔰 NYTT: 20s micro-cache för /proxy/orders-meta (utökad med scope i nyckeln)
const ordersMetaCache = new Map(); // key -> { at, data }

app.use('/proxy/orders-meta', (req, res, next) => {
  try {
    const cid = req.query.logged_in_customer_id || 'anon';
    const first = req.query.first || '25';
    const scope = req.query.scope || 'customer';
    const key = `${cid}:${first}:${scope}`;

    const hit = ordersMetaCache.get(key);
    if (hit && (Date.now() - hit.at) < 20000) {
      res.setHeader('Cache-Control', 'no-store');
      return res.json(hit.data);
    }

    const originalJson = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode === 200 && body && typeof body === 'object' && Array.isArray(body.orders)) {
        ordersMetaCache.set(key, { at: Date.now(), data: body });
      }
      return originalJson(body);
    };
  } catch {
    // om cachen felar, släpp igenom normalt
  }
  next();
});

// 🔹 Hjälp: GraphQL-anrop + GID -> numeric ID
async function shopifyGraphQL(query, variables) {
  const url = `https://${SHOP}/admin/api/2025-07/graphql.json`;
  const res = await axios.post(url, { query, variables }, {
    headers: {
      'X-Shopify-Access-Token': ACCESS_TOKEN,
      'Content-Type': 'application/json'
    }
  });
  return res.data;
}
function gidToId(gid) {
  try { return gid.split('/').pop(); } catch { return gid; }
}

// 🔹 NYTT: Admin-kontroll via kundtaggar
async function isAdminCustomer(customerId) {
  try {
    const resp = await axios.get(
      `https://${SHOP}/admin/api/2025-07/customers/${customerId}.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const tagsStr = String(resp.data?.customer?.tags || '');
    const tags = tagsStr.split(',').map(t => t.trim().toLowerCase()).filter(Boolean);
    return tags.includes('admin');
  } catch (e) {
    console.warn('isAdminCustomer(): kunde inte läsa kund', e?.response?.data || e.message);
    return false;
  }
}

// 🔹 Hjälp: bestäm om order ska räknas som levererad
function isDeliveredOrderShape(o) {
  const disp = String(o.displayFulfillmentStatus || o.display_delivery_status || '').toUpperCase();
  const fs = String(o.fulfillmentStatus || '').toUpperCase();
  if (disp === 'DELIVERED' || fs === 'FULFILLED') return true;

  // Fallback: om metafältets projekt alla säger "Levererad"
  try {
    const arr = o.metafield ? JSON.parse(o.metafield) : [];
    if (Array.isArray(arr) && arr.length) {
      const allDelivered = arr.every(p => {
        const s = String(p?.status || p?.tag || '').toLowerCase();
        return s.includes('levererad');
      });
      if (allDelivered) return true;
    }
  } catch {}
  return false;
}

app.get('/proxy/orders-meta', async (req, res) => {
  try {
    // 1) Säkerställ att anropet kommer från Shopify App Proxy
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerId = req.query.logged_in_customer_id; // sätts av Shopify
    if (!loggedInCustomerId) return res.status(204).end(); // ej inloggad kund

    const limit = Math.min(parseInt(req.query.first || '25', 10), 50);
    const scope = String(req.query.scope || '').toLowerCase();

    // ===== NYTT: ADMIN-LÄGE (scope=all) – hämta ALLA ordrar och filtrera bort levererade =====
    if (scope === 'all') {
      const ok = await isAdminCustomer(loggedInCustomerId);
      if (!ok) return res.status(403).json({ error: 'Forbidden' });

      // Först: GraphQL
      try {
        const query = `
          query AllOrdersWithMetafield($first: Int!, $ns: String!, $key: String!) {
            orders(first: $first, query: "status:any", sortKey: CREATED_AT, reverse: true) {
              edges {
                node {
                  id
                  name
                  processedAt
                  fulfillmentStatus
                  displayFulfillmentStatus
                  metafield(namespace: $ns, key: $key) { value }
                }
              }
            }
          }
        `;
        const data = await shopifyGraphQL(query, { first: limit, ns: ORDER_META_NAMESPACE, key: ORDER_META_KEY });
        if (data.errors) throw new Error('GraphQL error');

        const edges = data?.data?.orders?.edges || [];
        let out = edges.map(e => ({
          id: parseInt(gidToId(e.node.id), 10) || gidToId(e.node.id),
          name: e.node.name,
          processedAt: e.node.processedAt,
          metafield: e.node.metafield ? e.node.metafield.value : null,
          fulfillmentStatus: e.node.fulfillmentStatus || null,
          displayFulfillmentStatus: e.node.displayFulfillmentStatus || null
        }));
        out = out.filter(o => !isDeliveredOrderShape(o));
        
        res.setHeader('Cache-Control', 'no-store');
        return res.json({ orders: out, admin: true });
      } catch (gqlErr) {
        // REST-FALLBACK: hämta ALLA ordrar utan customer_id
        try {
          const ordersRes = await axios.get(
            `https://${SHOP}/admin/api/2025-07/orders.json?status=any&limit=${limit}&order=created_at+desc`,
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
          const orders = ordersRes.data.orders || [];

          const out = [];
          for (const o of orders) {
            const mfRes = await axios.get(
              `https://${SHOP}/admin/api/2025-07/orders/${o.id}/metafields.json`,
              { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
            );
            const mf = (mfRes.data.metafields || []).find(
              m => m.namespace === ORDER_META_NAMESPACE && m.key === ORDER_META_KEY
            );
            out.push({
              id: o.id,
              name: o.name,
              processedAt: o.processed_at || o.created_at,
              metafield: mf ? mf.value : null,
              // håll fältnamnen kompatibla med frontend-filtret
              fulfillmentStatus: o.fulfillment_status || null,
              displayFulfillmentStatus: null
            });
          }

          const filtered = out.filter(o => !isDeliveredOrderShape(o));

          res.setHeader('Cache-Control', 'no-store');
          return res.json({ orders: filtered, admin: true });
        } catch (restErr) {
          console.error('Admin REST fallback error:', restErr?.response?.data || restErr.message);
          return res.status(500).json({ error: 'Internal error' });
        }
      }
    }

    // ===== BEFINTLIGT: Kundbundna ordrar (oförändrat beteende) =====
    const query = `
      query OrdersWithMetafield($first: Int!, $q: String!, $ns: String!, $key: String!) {
        orders(first: $first, query: $q, sortKey: CREATED_AT, reverse: true) {
          edges {
            node {
              id
              name
              processedAt
              metafield(namespace: $ns, key: $key) { value }
            }
          }
        }
      }
    `;
    // Inkludera status:any så det matchar REST-listan (öppna/stängda)
    const q = `customer_id:${loggedInCustomerId} status:any`;
    let data = await shopifyGraphQL(query, { first: limit, q, ns: ORDER_META_NAMESPACE, key: ORDER_META_KEY });

    if (data.errors) {
      // Fallback till REST om GraphQL skulle fela
      throw new Error('GraphQL error');
    }

    const edges = data?.data?.orders?.edges || [];
    const out = edges.map(e => ({
      id: parseInt(gidToId(e.node.id), 10) || gidToId(e.node.id),
      name: e.node.name,
      processedAt: e.node.processedAt,
      metafield: e.node.metafield ? e.node.metafield.value : null
    }));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ orders: out });
  } catch (e) {
    // 🔁 Fallback: befintlig REST-implementation (oförändrad) om något går fel
    try {
      const loggedInCustomerId = req.query.logged_in_customer_id;
      if (!loggedInCustomerId) return res.status(204).end();

      const limit = Math.min(parseInt(req.query.first || '25', 10), 50);
      const ordersRes = await axios.get(
        `https://${SHOP}/admin/api/2025-07/orders.json?customer_id=${loggedInCustomerId}&limit=${limit}&status=any&order=created_at+desc`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const orders = ordersRes.data.orders || [];

      const out = [];
      for (const o of orders) {
        const mfRes = await axios.get(
          `https://${SHOP}/admin/api/2025-07/orders/${o.id}/metafields.json`,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
        const mf = (mfRes.data.metafields || []).find(
          m => m.namespace === ORDER_META_NAMESPACE && m.key === ORDER_META_KEY
        );
        out.push({
          id: o.id,
          name: o.name,
          processedAt: o.processed_at || o.created_at,
          metafield: mf ? mf.value : null
        });
      }

      res.setHeader('Cache-Control', 'no-store');
      return res.json({ orders: out });
    } catch (err) {
      console.error('proxy/orders-meta error:', err?.response?.data || err.message);
      return res.status(500).json({ error: 'Internal error' });
    }
  }
});
/* ===== NYTT: pending reviews för inloggad kund ===== */
app.get('/proxy/orders-meta/reviews/pending', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(204).end();

    const q = `customer_id:${loggedInCustomerId} status:any`;
    const query = `
      query OrdersWithMeta($first:Int!,$q:String!,$ns:String!,$key:String!){
        orders(first:$first, query:$q, sortKey:CREATED_AT, reverse:true){
          edges{
            node{
              id
              name
              processedAt
              metafield(namespace:$ns, key:$key){ value }
            }
          }
        }
      }`;
    let data = await shopifyGraphQL(query, { first: 50, q, ns: ORDER_META_NAMESPACE, key: ORDER_META_KEY });
    if (data.errors) throw new Error('GraphQL error');

    const edges = data?.data?.orders?.edges || [];
    const out = [];
    for (const e of edges) {
      const orderId = parseInt(gidToId(e.node.id), 10) || gidToId(e.node.id);
      let items = [];
      try { items = e.node.metafield?.value ? JSON.parse(e.node.metafield.value) : []; } catch { items = []; }
      (items || []).forEach(p => {
        const isDone = p?.review?.status === 'done';
        if (!isDone) {
          out.push({
            orderId,
            orderNumber: e.node.name,
            processedAt: e.node.processedAt,
            lineItemId: p.lineItemId,
            productId: p.productId,
            productTitle: p.productTitle,
            preview_img: p.previewUrl || p.preview_img || null
          });
        }
      });
    }

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ pending: out });
  } catch (err) {
    console.error('GET /proxy/orders-meta/reviews/pending:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'internal' });
  }
});
// ===== NYA APP PROXY-ROUTER FÖR PROFILUPPDATERING =====
app.post('/proxy/profile/update', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'Not logged in' });

    const firstName = (req.body.first_name || '').trim();
    const lastName  = (req.body.last_name  || '').trim();
    const email     = (req.body.email      || '').trim();

    // --- REST istället för GraphQL ---
    const cidRaw = String(loggedInCustomerId || '').trim();
    // REST vill ha numeriskt id (inte GID)
    const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;

    // Bygg endast de fält som användaren skickat in
    const payload = {
      customer: {
        id: cidNum,
        ...(firstName ? { first_name: firstName } : {}),
        ...(lastName  ? { last_name:  lastName  } : {}),
        ...(email     ? { email } : {})
      }
    };

    // Kör uppdateringen via Admin REST
    const upRes = await axios.put(
      `https://${SHOP}/admin/api/2025-07/customers/${cidNum}.json`,
      payload,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' } }
    );

    // Svara som tidigare (JSON om Accept: application/json, annars redirect)
    if (req.get('accept')?.includes('application/json')) {
      return res.json({ ok: true, customer: upRes.data.customer });
    }
    return res.redirect(302, '/account');

  } catch (err) {
    console.error('profile/update error:', err?.response?.data || err.message);
    if (req.get('accept')?.includes('application/json')) {
      return res.status(500).json({ error: 'Internal error' });
    }
    return res.redirect(302, '/account?profile_error=Internal%20error');
  }
});
// Duplicerad route för App Proxy-sökvägen /apps/orders-meta/profile/update
app.post('/proxy/orders-meta/profile/update', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'Not logged in' });

    const firstName = (req.body.first_name || '').trim();
    const lastName  = (req.body.last_name  || '').trim();
    const email     = (req.body.email      || '').trim();

    // --- REST istället för GraphQL ---
    const cidRaw = String(loggedInCustomerId || '').trim();
    const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;

    const payload = {
      customer: {
        id: cidNum,
        ...(firstName ? { first_name: firstName } : {}),
        ...(lastName  ? { last_name:  lastName  } : {}),
        ...(email     ? { email } : {})
      }
    };

    const upRes = await axios.put(
      `https://${SHOP}/admin/api/2025-07/customers/${cidNum}.json`,
      payload,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' } }
    );

    if (req.get('accept')?.includes('application/json')) {
      return res.json({ ok: true, customer: upRes.data.customer });
    }
    return res.redirect(302, '/account');
  } catch (err) {
    console.error('profile/update (orders-meta) error:', err?.response?.data || err.message);
    if (req.get('accept')?.includes('application/json')) {
      return res.status(500).json({ error: 'Internal error' });
    }
    return res.redirect(302, '/account?profile_error=Internal%20error');
  }
});
// ===== END APP PROXY =====

app.get('/proof/share/:token', async (req, res) => {
  try {
    const token = req.params.token || '';
const payload = verifyAndParseToken(token);
// Bakåtkompatibilitet: acceptera tokens utan 'kind' (äldre länkar), men neka fel 'kind'
if (!payload || (payload.kind && payload.kind !== 'review')) {
  return res.status(401).json({ error: 'invalid_token' });
}


    const { orderId, lineItemId, tid } = payload || {};
    if (!orderId || !lineItemId || !tid) return res.status(400).json({ error: 'Bad payload' });

    const { projects } = await readOrderProjects(orderId);
    const proj = (projects || []).find(p => String(p.lineItemId) === String(lineItemId));
    if (!proj) return res.status(404).json({ error: 'Not found' });

    const share = (Array.isArray(proj.shares) ? proj.shares : []).find(s =>
      s && s.status === 'active' && String(s.tid) === String(tid)
    );
    if (!share) return res.status(410).json({ error: 'Superseded or revoked' });

    // Hämta ordersammanfattning (frivilligt)
    let summary = null;
    try {
      const { data: oRes } = await axios.get(
        `https://${SHOP}/admin/api/2025-07/orders/${orderId}.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const o = oRes?.order || {};
      const ship =
        (o.total_shipping_price_set?.presentment_money?.amount) ??
        (o.total_shipping_price_set?.shop_money?.amount) ??
        (Array.isArray(o.shipping_lines) ? o.shipping_lines.reduce((s,ln)=> s + parseFloat(ln.price||0), 0) : 0);

      summary = {
        name: o.name || null,
        currency: o.currency || 'SEK',
        subtotal_price: o.subtotal_price || null,
        shipping_price: ship != null ? String(ship) : null,
        total_price: o.total_price || null
      };
    } catch(e) {
      console.warn('share summary fetch failed:', e?.response?.data || e.message);
    }

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      project: {
        orderId,
        lineItemId,
        ...(proj.orderNumber ? { orderNumber: proj.orderNumber } : {}),
        ...safeProjectFields(proj)
      },
      snapshot: share.snapshot || {},
      ...(summary ? { summary } : {})
    });

  } catch (e) {
    console.error('GET /proof/share/:token error:', e?.response?.data || e.message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

/* ===== NYTT: hämta review-form data via token ===== */
app.get('/review/share/:token', async (req, res) => {
  try {
    const token = req.params.token || '';
    const payload = verifyAndParseToken(token);
    if (!payload || payload.kind !== 'review') return res.status(401).json({ error: 'invalid_token' });

    const { orderId, lineItemId, tid } = payload || {};
    if (!orderId || !lineItemId || !tid) return res.status(400).json({ error: 'bad_payload' });

    const { projects } = await readOrderProjects(orderId);
    const proj = (projects || []).find(p => String(p.lineItemId) === String(lineItemId));
    if (!proj) return res.status(404).json({ error: 'not_found' });

    const r = proj.review || {};
    if (r.status === 'done') return res.status(410).json({ error: 'already_submitted' });
    if (!r || String(r.tid || '') !== String(tid)) return res.status(410).json({ error: 'token_superseded' });

    return res.json({
      orderId,
      lineItemId,
      orderNumber: proj.orderNumber || null,
      productId: proj.productId,
      productTitle: proj.productTitle || '',
      preview_img: proj.previewUrl || proj.preview_img || null
    });
  } catch (err) {
    console.error('GET /review/share/:token:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'internal' });
  }
});
/* ======= SIMPLE CANCEL VIA APP PROXY (MVP) ======= */
/* POST /apps/orders-meta/order/cancel  (Shopify App Proxy → server: /proxy/orders-meta/order/cancel)
   Body: { orderId }
   Säkerhet:
   - Verifierar App Proxy-signaturen (verifyAppProxySignature).
   - Kräver logged_in_customer_id (kunden måste vara inloggad).
   - Säkerställer att ordern tillhör kunden.
   Beteende:
   - Nekar om någon projekt-rad har status "I produktion".
   - Annars sätter ALLA projekt i orderns metafält till { status: "Annulerad", tag: "Annulerad", cancelledAt }.
*/

/* ===== NYTT: spara review + markera done ===== */
app.post('/proxy/orders-meta/reviews/submit', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'not_logged_in' });

    const token = String(req.body?.token || '');
    let { rating, title, body, would_order_again } = req.body || {};
    const payload = verifyAndParseToken(token);
    if (!payload || payload.kind !== 'review') return res.status(401).json({ error: 'invalid_token' });

    rating = parseInt(rating, 10);
    if (!(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'invalid_rating' });
    title = String(title || '').trim();
    body = String(body || '').trim();
    if (!title || !body) return res.status(400).json({ error: 'missing_fields' });
    const again = (function(v){
      if (typeof v === 'boolean') return v;
      if (typeof v === 'number') return v !== 0;
      if (typeof v === 'string') return /^(true|1|yes|ja)$/i.test(v);
      return false;
    })(would_order_again);

    const { orderId, lineItemId, tid } = payload || {};

    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const order = data?.order;
    if (!order) return res.status(404).json({ error: 'order_not_found' });

    const cidRaw = String(loggedInCustomerId);
    const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;
    const ownerId = String(order?.customer?.id || '');
    if (!ownerId.endsWith(cidNum)) return res.status(403).json({ error: 'forbidden_not_owner' });

    const { metafieldId, projects } = await readOrderProjects(orderId);
    if (!metafieldId) return res.status(404).json({ error: 'metafield_not_found' });

    const idx = (projects || []).findIndex(p => String(p.lineItemId) === String(lineItemId));
    if (idx < 0) return res.status(404).json({ error: 'line_item_not_found' });

    const p = projects[idx] || {};
    const r = p.review || {};
    if (r.status === 'done') return res.status(410).json({ error: 'already_submitted' });
    if (!r || String(r.tid || '') !== String(tid)) return res.status(410).json({ error: 'token_superseded' });

    const productId = p.productId;
    const { metafieldId: revMfId, reviews } = await readProductReviews(productId);
    const displayName = `${order.customer?.first_name || ''} ${order.customer?.last_name || ''}`.trim() || 'Kund';

    const entry = {
      orderId: Number(orderId),
      lineItemId: Number(lineItemId),
      customerId: order.customer?.id || null,
      productId: productId,
      rating,
      title,
      body,
      would_order_again: !!again,
      createdAt: nowIso(),
      displayName
    };
    const nextReviews = [entry, ...(Array.isArray(reviews) ? reviews : [])].slice(0, 500);

    await writeProductReviews(productId, revMfId, nextReviews);

    const updated = { ...(p.review || {}), status: 'done', submittedAt: nowIso() };
    projects[idx] = { ...p, review: updated };
    await writeOrderProjects(metafieldId, projects);

    try {
      await appendActivity(orderId, [{
        ts: new Date().toISOString(),
        actor: { type: 'customer', name: displayName, id: order.customer?.id ? `customer:${order.customer.id}` : undefined },
        action: 'review.submitted',
        order_id: Number(orderId),
        line_item_id: Number(lineItemId),
        product_title: p.productTitle || '',
        data: { rating, would_order_again: !!again },
        correlation_id: `review.submitted:${orderId}:${lineItemId}:${tid}`
      }]);
    } catch {}

    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /proxy/orders-meta/reviews/submit:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'internal' });
  }
});


app.post('/proxy/orders-meta/order/cancel', async (req, res) => {
  try {
    // 1) Verifiera App Proxy-signatur
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ ok: false, error: 'invalid_signature' });
    }

    // 2) Kräver inloggad kund
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) {
      return res.status(401).json({ ok: false, error: 'not_logged_in' });
    }

    // 3) Läs orderId från body
    const orderId = String(req.body?.orderId || '').trim();
    if (!orderId) return res.status(400).json({ ok: false, error: 'orderId_required' });

    // 4) Säkerställ att kunden äger ordern
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const order = data?.order;
    if (!order) return res.status(404).json({ ok: false, error: 'order_not_found' });

    // Shopify REST kör numeriska id för kunder, App Proxy sänder ibland GID → normalisera
    const cidRaw = String(loggedInCustomerId);
    const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;
    const orderCustomerId = String(order?.customer?.id || '');
    if (!orderCustomerId.endsWith(cidNum)) {
      return res.status(403).json({ ok: false, error: 'forbidden_not_owner' });
    }

    // 5) Läs projekten i orderns metafält
    const { metafieldId, projects } = await readOrderProjects(orderId);
    if (!metafieldId) return res.status(404).json({ ok: false, error: 'projects_not_found' });

    // 6) Neka om någon rad redan är i produktion (säkerhet även om UI döljer knappen)
    const hasInProduction = (projects || []).some(p => String(p.status || '') === 'I produktion');
    if (hasInProduction) {
      return res.status(409).json({ ok: false, error: 'in_production' });
    }

    // 7) Sätt status till "Annulerad" på samtliga projekt
    const now = new Date().toISOString();
    const next = (projects || []).map(p => ({
      ...p,
      status: 'Annulerad',
      tag: 'Annulerad',
      cancelledAt: now
    }));
    await writeOrderProjects(metafieldId, next);

    // 8) (valfritt) enkel activity-logg
    try {
      const entries = (order.line_items || []).map(li => ({
        ts: now,
        actor: { type: 'customer', name: `${order.customer?.first_name || ''} ${order.customer?.last_name || ''}`.trim() || 'Kund' },
        action: 'order.cancelled_request',
        order_id: Number(orderId),
        line_item_id: Number(li.id),
        product_title: li.title,
        data: { via: 'app_proxy', status: 'Annulerad' },
        correlation_id: `order.cancelled_request:${orderId}:${li.id}:${cidNum}`
      }));
      await appendActivity(orderId, entries);
    } catch {}

    return res.json({ ok: true });
  } catch (e) {
    console.error('proxy cancel error:', e?.response?.data || e.message);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

/* ===== NYTT: skapa review-token & skriv in i order-metafält ===== */
app.post('/proxy/orders-meta/reviews/create', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'not_logged_in' });

    const orderId = String(req.body?.orderId || '').trim();
    const lineItemId = String(req.body?.lineItemId || '').trim();
    if (!orderId || !lineItemId) return res.status(400).json({ error: 'missing_params' });

    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const order = data?.order;
    if (!order) return res.status(404).json({ error: 'order_not_found' });

    const cidRaw = String(loggedInCustomerId);
    const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;
    const ownerId = String(order?.customer?.id || '');
    if (!ownerId.endsWith(cidNum)) return res.status(403).json({ error: 'forbidden_not_owner' });

    const { metafieldId, projects } = await readOrderProjects(orderId);
    if (!metafieldId) return res.status(404).json({ error: 'metafield_not_found' });

    const idx = (projects || []).findIndex(p => String(p.lineItemId) === String(lineItemId));
    if (idx < 0) return res.status(404).json({ error: 'line_item_not_found' });

    const tid = newTid();
    const token = signTokenPayload({ kind: 'review', orderId: Number(orderId), lineItemId: Number(lineItemId), tid, iat: Date.now() });
    const token_hash = crypto.createHash('sha256').update(token).digest('hex');

    const p = projects[idx] || {};
    const reviewObj = Object.assign(
      { status: 'pending' },
      (p.review && typeof p.review === 'object') ? p.review : {}
    );
    if (reviewObj.status !== 'done') {
      reviewObj.tid = tid;
      reviewObj.token_hash = token_hash;
      reviewObj.createdAt = nowIso();
    }
    projects[idx] = { ...p, review: reviewObj };

    await writeOrderProjects(metafieldId, projects);

    const url = `${STORE_BASE}/pages/review?token=${encodeURIComponent(token)}`;
    return res.json({ ok: true, url });
  } catch (err) {
    console.error('POST /proxy/orders-meta/reviews/create:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'internal' });
  }
});
/* Duplicerad path för butiker där proxy-basen inte innehåller "/orders-meta"
   → klienten kan ändå anropa /apps/orders-meta/order/cancel, men vissa teman mappar till /proxy/... direkt. */
app.post('/proxy/order/cancel', async (req, res) => {
  // Återanvänd exakt samma logik som ovan genom att proxya req/res till vår huvudhandler.
  // Enkelt sätt: sätt om pathen och kalla verify/signature igen – eller duplicera koden.
  // Här kallar vi bara om samma funktionella kropp.
  req.url = req.url.includes('?') ? req.url : (req.url + '?'); // säkerställ att split fungerar
  return app._router.handle({ ...req, url: '/proxy/orders-meta/order/cancel' + req.url.slice(req.url.indexOf('?')) }, res, () => {});
});
/* ====== END SIMPLE CANCEL VIA APP PROXY ====== */


// Starta servern
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Kör på port ${PORT}`);
});







