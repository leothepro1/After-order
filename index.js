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
      status:            'Väntar på korrektur',
      tag:               'Väntar på korrektur',
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
      const awaiting = enriched.filter(p => p.status === 'Väntar på godkännande');

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
  const { orderId, lineItemId, previewUrl } = req.body;
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
        return { ...p, previewUrl, status: 'Väntar på godkännande' };
      }
      return p;
    });

    if (!updated) return res.status(404).json({ error: 'Line item hittades inte i metafält' });

    await axios.put(
      `https://${SHOP}/admin/api/2025-07/metafields/${metafield.id}.json`,
      { metafield: { id: metafield.id, type: 'json', value: JSON.stringify(projects) } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

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
        return { ...p, status: 'Godkänd' };
      }
      return p;
    });

    await axios.put(
      `https://${SHOP}/admin/api/2025-07/metafields/${metafield.id}.json`,
      { metafield: { id: metafield.id, type: 'json', value: JSON.stringify(projects) } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

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
        return { ...p, instructions, status: 'Väntar på korrektur', tag: 'Väntar på korrektur' };
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
        if (!meta || (!meta.public_id && !meta.secure_url)) {
          return res.status(400).json({ error: 'Invalid meta payload' });
        }

        const payload = {
          namespace: 'Profilbild',
          key: 'Profilbild',
          type: 'json',
          value: JSON.stringify({
            public_id:  String(meta.public_id || ''),
            version:    meta.version || null,
            secure_url: String(meta.secure_url || ''),
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
        if (!meta || (!meta.public_id && !meta.secure_url)) {
          return res.status(400).json({ error: 'Invalid meta payload' });
        }

        const payload = {
          namespace: 'Profilbild',
          key: 'Profilbild',
          type: 'json',
          value: JSON.stringify({
            public_id:  String(meta.public_id || ''),
            version:    meta.version || null,
            secure_url: String(meta.secure_url || ''),
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
    console.error('/proxy/orders-meta/avatar error:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// 🔰 NYTT: 20s micro-cache för /proxy/orders-meta (ingen ändring av själva route-handlern)
const ordersMetaCache = new Map(); // key -> { at, data }

app.use('/proxy/orders-meta', (req, res, next) => {
  try {
    const cid = req.query.logged_in_customer_id || 'anon';
    const first = req.query.first || '25';
    const key = `${cid}:${first}`;

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

app.get('/proxy/orders-meta', async (req, res) => {
  try {
    // 1) Säkerställ att anropet kommer från Shopify App Proxy
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerId = req.query.logged_in_customer_id; // sätts av Shopify
    if (!loggedInCustomerId) return res.status(204).end(); // ej inloggad kund

    // 2) Hämta kundens ordrar + metafält i ETT GraphQL-anrop
    const limit = Math.min(parseInt(req.query.first || '25', 10), 50);
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

    const mutation = `
      mutation customerUpdate($id: ID!, $input: CustomerInput!) {
        customerUpdate(id: $id, input: $input) {
          customer { id firstName lastName email }
          userErrors { field message }
        }
      }
    `;
    const variables = {
      id: `gid://shopify/Customer/${loggedInCustomerId}`,
      input: {
        ...(firstName ? { firstName } : {}),
        ...(lastName  ? { lastName  } : {}),
        ...(email     ? { email     } : {})
      }
    };

    const data = await shopifyGraphQL(mutation, variables);
    const result = data?.data?.customerUpdate;

    if (!result || (result.userErrors && result.userErrors.length)) {
      if (req.get('accept')?.includes('application/json')) {
        return res.status(400).json({ errors: result?.userErrors || [{ message: 'Okänt fel' }] });
      }
      const msg = encodeURIComponent(result?.userErrors?.[0]?.message || 'Kunde inte uppdatera profil');
      return res.redirect(302, `/account?profile_error=${msg}`);
    }

    if (req.get('accept')?.includes('application/json')) {
      return res.json({ ok: true, customer: result.customer });
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

// Duplicerad route för proxybas under /proxy/orders-meta (i linje med dina avatar-routes)
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

    const mutation = `
      mutation customerUpdate($id: ID!, $input: CustomerInput!) {
        customerUpdate(id: $id, input: $input) {
          customer { id firstName lastName email }
          userErrors { field message }
        }
      }
    `;
    const variables = {
      id: `gid://shopify/Customer/${loggedInCustomerId}`,
      input: {
        ...(firstName ? { firstName } : {}),
        ...(lastName  ? { lastName  } : {}),
        ...(email     ? { email     } : {})
      }
    };

    const data = await shopifyGraphQL(mutation, variables);
    const result = data?.data?.customerUpdate;

    if (!result || (result.userErrors && result.userErrors.length)) {
      if (req.get('accept')?.includes('application/json')) {
        return res.status(400).json({ errors: result?.userErrors || [{ message: 'Okänt fel' }] });
      }
      const msg = encodeURIComponent(result?.userErrors?.[0]?.message || 'Kunde inte uppdatera profil');
      return res.redirect(302, `/account?profile_error=${msg}`);
    }

    if (req.get('accept')?.includes('application/json')) {
      return res.json({ ok: true, customer: result.customer });
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
// ===== END APP PROXY =====

// Starta servern
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Kör på port ${PORT}`);
});



