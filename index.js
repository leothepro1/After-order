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

// ✅ NYTT: API secret för App Proxy-signatur
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;

// Temporär lagring för förhandsdata från frontend
const temporaryStorage = {}; // { [projectId]: { previewUrl, cloudinaryPublicId, instructions, date } }

// Middleware
app.use(bodyParser.json({ verify: (req, res, buf) => {
  req.rawBody = buf;
}}));

// Verifiera Shopify-signatur
function verifyShopifyRequest(req) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  const digest = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody, 'utf8')
    .digest('base64');

  return digest === hmacHeader;
}

// ✅ NYTT: Verifiera App Proxy-signatur (query-param "signature")
function verifyAppProxySignature(query) {
  const { signature, ...rest } = query || {};
  if (!signature) return false;

  const pairs = Object.keys(rest).map(k => {
    const v = Array.isArray(rest[k]) ? rest[k].join(',') : String(rest[k] ?? '');
    return `${k}=${v}`;
  });

  try {
    const digest = crypto
      .createHmac('sha256', process.env.SHOPIFY_API_SECRET || '')
      .update(pairs.sort().join(''))
      .digest('hex');

    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(String(signature), 'utf8'));
  } catch (e) {
    console.error('App Proxy HMAC fel (saknas SHOPIFY_API_SECRET eller ogiltig?):', e.message);
    return false; // gör att route svarar 401 med JSON, inte tom body
  }
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
    // Hämta befintliga metafält
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

// ✅ NYTT: App Proxy – hämta order-metafält för inloggad kund
// Denna route träffas via Shopify App Proxy, t.ex.
// https://{shop}.myshopify.com/apps/<subpath>/orders-meta?ns=order-created&key=order-created
// som proxas till https://<din-render-domän>/proxy/orders-meta
app.get('/proxy/orders-meta', async (req, res) => {
  if (!verifyAppProxySignature(req.query)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const shop = String(req.query.shop || SHOP);
  const customerId = String(req.query.logged_in_customer_id || '');
  const ns = String(req.query.ns || 'order-created');
  const key = String(req.query.key || 'order-created');

  if (!customerId) {
    return res.status(401).json({ error: 'Customer must be logged in' });
  }

  try {
    // Hämta kundens ordrar (senaste först). status=any för att inkludera alla.
    const ordersRes = await axios.get(
      `https://${shop}/admin/api/2025-07/orders.json?customer_id=${encodeURIComponent(customerId)}&status=any&limit=50&order=created_at+desc`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const orders = ordersRes.data.orders || [];

    const results = [];
    for (const order of orders) {
      // Hämta bara vårt namespace för mindre payload
      const mfRes = await axios.get(
        `https://${shop}/admin/api/2025-07/orders/${order.id}/metafields.json?namespace=${encodeURIComponent(ns)}`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const mf = (mfRes.data.metafields || []).find(m => m.namespace === ns && m.key === key);
      if (!mf || !mf.value) continue;

      let projects = [];
      try { projects = JSON.parse(mf.value) || []; } catch {}

      const items = projects.map(p => ({
        orderId: order.id,
        orderName: order.name,
        createdAt: order.created_at,
        status: p.status || null,
        productTitle: p.productTitle || null,
        quantity: p.quantity || null,
        properties: Array.isArray(p.properties) ? p.properties.filter(x => x && x.name && x.value) : [],
        fileUrl: (p.preview_img || p.previewUrl || null),
        lineItemId: p.lineItemId ?? null
      }));

      results.push(...items);
    }

    // Sortera nyast först
    results.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return res.json({ ok: true, count: results.length, items: results });
  } catch (err) {
    console.error('❌ /proxy/orders-meta error:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Starta servern
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Kör på port ${PORT}`);
});


