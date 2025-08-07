// FIL: index.js

const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const app = express();

// Middleware
app.use(bodyParser.json());

// Shopify-info
const SHOP = 'din-butik.myshopify.com'; // Byt ut till din butik
const ACCESS_TOKEN = 'din_shopify_access_token'; // Din privata app-token

// Webhook: Order skapad
app.post('/webhooks/order-created', async (req, res) => {
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
    // Hämta befintliga metafält
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
      // Uppdatera
      await axios.put(`https://${SHOP}/admin/api/2024-07/metafields/${currentMetafield.id}.json`, {
        metafield: {
          id: currentMetafield.id,
          type: 'json',
          value: JSON.stringify(combined)
        }
      }, {
        headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
      });
    } else {
      // Skapa nytt
      await axios.post(`https://${SHOP}/admin/api/2024-07/orders/${orderId}/metafields.json`, {
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
