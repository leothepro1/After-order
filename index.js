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

  const newProjects = lineItems.map(item => ({
    lineItemId: item.id,
    productId: item.product_id,
    productTitle: item.title,
    variantId: item.variant_id,
    variantTitle: item.variant_title,
    quantity: item.quantity,
    properties: item.properties || [],
    customerId,
    orderNumber,
    date: new Date().toISOString()
  }));

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

