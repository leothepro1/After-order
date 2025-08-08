// FIL: index.js

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express(); // ✅ Skapa app INNAN du använder den

// Aktivera CORS
app.use(cors({
  origin: 'https://pressify.se',
  methods: ['GET', 'POST', 'PUT', 'PATCH'],
  credentials: false
}));

// Shopify-info från miljövariabler
const SHOP = process.env.SHOP;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;

// Temporär lagring för förhandsdata från frontend
const temporaryStorage = {}; // { [projectId]: { previewUrl, cloudinaryPublicId, instructions } }

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
    console.log('📦 Header-hash:', req.get('X-Shopify-Hmac-Sha256'));
    const testDigest = crypto
      .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
      .update(req.rawBody, 'utf8')
      .digest('base64');
    console.log('🔐 Beräknad digest:', testDigest);
    return res.sendStatus(401);
  }

  console.log('🔓 Signatur verifierad! Bearbetar order...');

  const order = req.body;
  const orderId = order.id;
  const customerId = order.customer?.id;
  const orderNumber = order.name;
  const lineItems = order.line_items || [];

  const newProjects = lineItems.map(item => {
    const fileName = item.properties?.find(p => p.name === 'Tryckfil')?.value || '';
    const key = `${item.product_id}-${item.title}-${fileName}`;
    const fallback = temporaryStorage[key] || temporaryStorage[item.id] || {};

    return {
      lineItemId: item.id,
      productId: item.product_id,
      productTitle: item.title,
      variantId: item.variant_id,
      variantTitle: item.variant_title,
      quantity: item.quantity,
      previewUrl: fallback.previewUrl || null,
      cloudinaryPublicId: fallback.cloudinaryPublicId || null,
      instructions: fallback.instructions || null,
      properties: item.properties || [],
      customerId,
      orderNumber,
      status: 'Väntar på korrektur',
      tag: 'Väntar på korrektur',
      date: new Date().toISOString()
    };
  });

  if (newProjects.length === 0) return res.sendStatus(200);

  try {
    const existing = await axios.get(`https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`, {
      headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
    });

    const currentMetafield = existing.data.metafields.find(mf =>
      mf.namespace === 'order-created' && mf.key === 'order-created'
    );

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

    if (currentMetafield) {
      await axios.put(`https://${SHOP}/admin/api/2025-07/metafields/${currentMetafield.id}.json`, {
        metafield: {
          id: currentMetafield.id,
          type: 'json',
          value: JSON.stringify(combined)
        }
      }, {
        headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
      });
    } else {
      await axios.post(`https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`, {
        metafield: {
          namespace: 'order-created',
          key: 'order-created',
          type: 'json',
          value: JSON.stringify(combined)
        }
      }, {
        headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
      });
    }

    console.log('✅ Metafält sparat!');
    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Fel:', err?.response?.data || err.message);
    res.sendStatus(500);
  }
});

// Hämta korrektur-status för kund
app.get('/pages/korrektur', async (req, res) => {
  const customerId = req.query.customerId;
  if (!customerId) return res.status(400).json({ error: 'customerId krävs' });

  try {
    const ordersRes = await axios.get(`https://${SHOP}/admin/api/2025-07/orders.json?customer_id=${customerId}`, {
      headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
    });

    const orders = ordersRes.data.orders || [];
    const results = [];

    for (const order of orders) {
      const metafieldsRes = await axios.get(`https://${SHOP}/admin/api/2025-07/orders/${order.id}/metafields.json`, {
        headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
      });

      const proofMetafield = metafieldsRes.data.metafields.find(mf =>
        mf.namespace === 'order-created' && mf.key === 'order-created'
      );

      if (!proofMetafield) continue;

      const projects = JSON.parse(proofMetafield.value || '[]');
      const awaiting = projects.filter(p => p.status === 'Väntar på godkännande');

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
    const { data } = await axios.get(`https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`, {
      headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
    });

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

    await axios.put(`https://${SHOP}/admin/api/2025-07/metafields/${metafield.id}.json`, {
      metafield: {
        id: metafield.id,
        type: 'json',
        value: JSON.stringify(projects)
      }
    }, {
      headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
    });

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
    const { data } = await axios.get(`https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`, {
      headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
    });

    const metafield = data.metafields.find(mf => mf.namespace === 'order-created' && mf.key === 'order-created');
    if (!metafield) return res.status(404).json({ error: 'Metafält hittades inte' });

    let projects = JSON.parse(metafield.value || '[]');
    projects = projects.map(p => {
      if (p.lineItemId == lineItemId) {
        return { ...p, status: 'Godkänd' };
      }
      return p;
    });

    await axios.put(`https://${SHOP}/admin/api/2025-07/metafields/${metafield.id}.json`, {
      metafield: {
        id: metafield.id,
        type: 'json',
        value: JSON.stringify(projects)
      }
    }, {
      headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
    });

    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Fel vid /proof/approve:', err?.response?.data || err.message);
    res.status(500).json({ error: 'Kunde inte godkänna korrektur' });
  }
});

// Starta servern
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Kör på port ${PORT}`);
});


