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
      date:              new Date().toISOString()
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
app.post('/proof/upload', async (req, res) => {
  // ⬇️ NYTT: valfritt fält proofNote (bakåtkompatibelt)
  const { orderId, lineItemId, previewUrl, proofNote } = req.body;
  if (!orderId || !lineItemId || !previewUrl) return res.status(400).json({ error: 'orderId, lineItemId och previewUrl krävs' });

  try {
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

    const metafield = data.metafields.find(mf => mf.namespace === 'order-created' && mf.key === 'order-created');
    if (!metafield) return res.status(404).json({ error: 'Metafält hittades inte' });

    let projects = JSON.parse(metafield.value || '[]');
    let updated = false;

    projects = projects.map(p => {
      if (p.lineItemId == lineItemId) {
        updated = true;
        return {
          ...p,
          previewUrl,
          // ⬇️ NYTT: spara texten om den skickas (i övrigt oförändrat)
          ...(typeof proofNote === 'string' && proofNote.trim() ? { proofNote: proofNote.trim() } : {}),
          status: 'Korrektur redo'
        };
      }
      return p;
    });

    if (!updated) return res.status(404).json({ error: 'Line item hittades inte i metafält' });

    await axios.put(
      `https://${SHOP}/admin/api/2025-07/metafields/${metafield.id}.json`,
      { metafield: { id: metafield.id, type: 'json', value: JSON.stringify(projects) } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

    /* ==== ACTIVITY LOG: Pressify laddade upp korrektur ==== */
    try {
      const proj = projects.find(p => String(p.lineItemId) === String(lineItemId)) || {};
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
    /* ======================= END ACTIVITY LOG ======================= */

    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Fel vid /proof/upload:', err?.response?.data || err.message);
    res.status(500).json({ error: 'Kunde inte uppdatera korrektur' });
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
        return { ...p, status: 'Redo för tryck' };
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

// Starta servern
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Kör på port ${PORT}`);
});







