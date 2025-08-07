// FIL: index.js

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const app = express();

// Shopify-info från miljövariabler
const SHOP = process.env.SHOP;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;

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

// Webhook: Order skapad
app.post('/webhooks/order-created', async (req, res) => {
  if (!verifyShopifyRequest(req)) {
    console.warn('❌ Ogiltig Shopify-signatur!');
    return res.sendStatus(401);
  }

  const order = req.body;
  const orderId = order.id;
  const customerId = order.customer?.id;
  const orderNumber = order.name;
  const lineItems = order.line_items || [];

  const newProjects = [];

  for (const item of lineItems) {
    const props = item.properties || [];

    const fileName = props.find(p => p.name === "fileName")?.value;
    const previewUrl = props.find(p => p.name === "previewUrl")?.value;
    const cloudinaryPublicId = props.find(p => p.name === "cloudinaryPublicId")?.value;

    if (!fileName || !previewUrl) continue;

    newProjects.push({
      projectId: item.id,
      fileName,
      previewUrl,
      cloudinaryPublicId,
      productId: item.product_id,
      productTitle: item.title,
      lineItemId: item.id,
      customerId,
      orderNumber,
      date: new Date().toISOString()
    });
  }

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

// Starta servern
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Kör på port ${PORT}`);
});

