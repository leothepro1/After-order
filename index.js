// FIL: index.js

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const http = require('http');
const https = require('https');
axios.defaults.httpAgent  = new http.Agent({ keepAlive: true, maxSockets: 100 });
axios.defaults.httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 100 });
const crypto = require('crypto');
const compression = require('compression');
const bodyParser = require('body-parser');
const fs = require('fs');         
const path = require('path');  

const app = express(); // ✅ Skapa app INNAN du använder den

// CORS – en gång (inkl. preflight) + helper för fel
const ALLOWED_ORIGINS = ['https://pressify.se', 'https://www.pressify.se'];

const CORS_OPTIONS = {
  origin: ALLOWED_ORIGINS,                  // räcker – cors speglar origin om det matchar listan
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false
};

app.use(cors(CORS_OPTIONS));               // <– enda cors-middleware
app.options('*', cors(CORS_OPTIONS));      // preflight för alla paths

app.use(compression({ level: 6, threshold: 1024 }));

// CORS på fel-svar (t.ex. i catch)
function setCorsOnError(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
}

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
function adminHeaders(extra = {}) {
  return { 'X-Shopify-Access-Token': ADMIN_TOKEN, ...extra };
}
async function adminGet(url, cfg = {}) {
  return axios.get(url, { ...cfg, headers: adminHeaders(cfg.headers) });
}
async function adminPost(url, data, cfg = {}) {
  return axios.post(url, data, { ...cfg, headers: adminHeaders(cfg.headers) });
}
async function adminPut(url, data, cfg = {}) {
  return axios.put(url, data, { ...cfg, headers: adminHeaders(cfg.headers) });
}


/* ===== REFERLINK CONFIG ===== */
const REFER_NS  = 'referlink';
const REFER_KEY = 'referlink';          // JSON-metafält: {{ customer.metafields.referlink.referlink }}
const SLUG_SECRET = process.env.SLUG_SECRET || 'CHANGE_ME_LONG_RANDOM';
const BACKFILL_SECRET = process.env.BACKFILL_SECRET || '';
// Vi använder en stabil, alfanumerisk slug via Base32 på HMAC(customerId) → låg kollisionsrisk och samma för evigt
const B32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'; // crockford-ish lower
function hmacHex(input) {
  return crypto.createHmac('sha256', SLUG_SECRET).update(String(input)).digest('hex');
}
// ===== Shop tax config (cache 5 min) =====
let __shopTaxCfg = { at: 0, taxes_included: true };
async function getShopTaxConfig() {
  const now = Date.now();
  if (now - __shopTaxCfg.at < 5 * 60 * 1000) return __shopTaxCfg; // 5 min
  const { data } = await axios.get(`https://${SHOP}/admin/api/2025-07/shop.json`, {
    headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
  });
  const taxes_included = !!data?.shop?.taxes_included;
  __shopTaxCfg = { at: now, taxes_included };
  return __shopTaxCfg;
}

async function getProductDefaultTaxableMap(productIds = []) {
  const uniq = Array.from(new Set(productIds.filter(Boolean).map(String)));
  const out = Object.create(null);

  const missing = [];
  for (const pid of uniq) {
    const hit = __taxProdCache.get(pid);
    if (hit && (Date.now() - hit.at) < TAX_CACHE_TTL) {
      out[pid] = !!hit.value;
    } else {
      missing.push(pid);
    }
  }
  if (missing.length === 0) return out;

  const chunk = (arr, n) => arr.reduce((a, _, i) => (i % n ? a : [...a, arr.slice(i, i+n)]), []);
  for (const group of chunk(missing, 250)) {
    try {
      const ids = group.map(id => toGid('Product', id));
      const query = `
        query ProductFirstVariantTaxable($ids:[ID!]!) {
          nodes(ids:$ids) {
            ... on Product {
              id
              variants(first:1) { nodes { taxable } }
            }
          }
        }`;
      const data = await shopifyGraphQL(query, { ids });
      const nodes = data?.data?.nodes || [];
      for (const n of nodes) {
        if (n && n.id) {
          const id = gidToId(n.id);
          const v0 = (n.variants?.nodes || [])[0];
          const val = (v0 && typeof v0.taxable === 'boolean') ? !!v0.taxable : true;
          out[id] = val;
          __taxProdCache.set(id, { at: Date.now(), value: val });
        }
      }
    } catch (e) {
      await Promise.all(group.map(async (pid) => {
        if (out[pid] !== undefined) return;
        try {
          const { data } = await axios.get(
            `https://${SHOP}/admin/api/2025-07/products/${pid}.json?fields=id,variants`,
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
          const v = (data?.product?.variants || [])[0];
          const val = v && typeof v.taxable === 'boolean' ? !!v.taxable : true;
          out[pid] = val;
          __taxProdCache.set(pid, { at: Date.now(), value: val });
        } catch (err) {
          console.warn('getProductDefaultTaxableMap (fallback):', pid, err?.response?.data || err.message);
        }
      }));
    }
  }
  return out;
}


// 5 min in-memory cache för taxable
const TAX_CACHE_TTL = 5 * 60 * 1000;
const __taxVarCache  = new Map(); // variantId -> { at, value:boolean }
const __taxProdCache = new Map(); // productId -> { at, value:boolean }

async function getVariantTaxableMap(variantIds = []) {
  const uniq = Array.from(new Set(variantIds.filter(Boolean).map(String)));
  const out = Object.create(null);

  // cache hits
  const missing = [];
  for (const vid of uniq) {
    const hit = __taxVarCache.get(vid);
    if (hit && (Date.now() - hit.at) < TAX_CACHE_TTL) {
      out[vid] = !!hit.value;
    } else {
      missing.push(vid);
    }
  }
  if (missing.length === 0) return out;

  // GraphQL batch
  const chunk = (arr, n) => arr.reduce((a, _, i) => (i % n ? a : [...a, arr.slice(i, i+n)]), []);
  for (const group of chunk(missing, 250)) {
    try {
      const ids = group.map(id => toGid('ProductVariant', id));
      const query = `
        query VariantTaxable($ids:[ID!]!) {
          nodes(ids:$ids) { ... on ProductVariant { id taxable } }
        }`;
      const data = await shopifyGraphQL(query, { ids });
      const nodes = data?.data?.nodes || [];
      for (const n of nodes) {
        if (n && n.id) {
          const id = gidToId(n.id);
          const val = !!n.taxable;
          out[id] = val;
          __taxVarCache.set(id, { at: Date.now(), value: val });
        }
      }
    } catch (e) {
      // REST-fallback per id om GraphQL skulle fela
      await Promise.all(group.map(async (vid) => {
        if (out[vid] !== undefined) return;
        try {
          const { data } = await axios.get(
            `https://${SHOP}/admin/api/2025-07/variants/${vid}.json?fields=taxable,id`,
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
          const val = !!data?.variant?.taxable;
          out[vid] = val;
          __taxVarCache.set(vid, { at: Date.now(), value: val });
        } catch (err) {
          console.warn('getVariantTaxableMap (fallback):', vid, err?.response?.data || err.message);
        }
      }));
    }
  }
  return out;
}



/* ====== SLUT GLOBALA TAXABLE-HELPERS ====== */


function hexToBase32Lower(hex, len = 8) {
  // Ta första 40 bit (~10 hex) och koda till base32; klipp till len tecken
  const bits = BigInt('0x' + hex.slice(0, 10));
  let s = '';
  let v = bits;
  for (let i=0;i<16;i++) { // 16*5=80 bits > 40, räcker
    const idx = Number(v & BigInt(31));
    s = B32_ALPHABET[idx] + s;
    v >>= BigInt(5);
  }
  return s.slice(-len);
}
function makeSlugFromCustomerId(customerId) {
  const hex = hmacHex(customerId);
  return hexToBase32Lower(hex, 8); // 8 tecken, t.ex. "q7m2r9kd"
}
function referlinkJsonFor(slug) {
  const url = `${STORE_BASE.replace(/\/$/,'')}/${slug}`;
  return {
    slug,
    url,
    createdAt: new Date().toISOString(),
    version: 1
  };
}
async function readCustomerReferlink(customerId) {
  const { data } = await axios.get(
    `https://${SHOP}/admin/api/2025-07/customers/${customerId}/metafields.json`,
    { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
  );
  const mf = (data.metafields || []).find(m => m.namespace === REFER_NS && m.key === REFER_KEY);
  if (!mf) return { metafieldId: null, value: null };
  let value = null;
  try { value = mf.value ? JSON.parse(mf.value) : null; } catch {}
  return { metafieldId: mf.id, value };
}
async function writeCustomerReferlink(customerId, metafieldId, valueObj) {
  const payload = {
    metafield: {
      namespace: REFER_NS,
      key: REFER_KEY,
      type: 'json',
      value: JSON.stringify(valueObj)
    }
  };
  if (metafieldId) {
    await axios.put(
      `https://${SHOP}/admin/api/2025-07/metafields/${metafieldId}.json`,
      { metafield: { id: metafieldId, ...payload.metafield } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
  } else {
    await axios.post(
      `https://${SHOP}/admin/api/2025-07/customers/${customerId}/metafields.json`,
      payload,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
  }
}
async function ensureRootRedirectToHome(slug) {
  try {
    // Finns redirect redan?
    const check = await axios.get(
      `https://${SHOP}/admin/api/2025-07/redirects.json?path=%2F${encodeURIComponent(slug)}`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    if ((check.data.redirects || []).length) return true;
    // Skapa 301 till startsidan
    await axios.post(
      `https://${SHOP}/admin/api/2025-07/redirects.json`,
      { redirect: { path: `/${slug}`, target: '/' } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    return true;
  } catch (e) {
    console.warn('ensureRootRedirectToHome:', e?.response?.data || e.message);
    return false;
  }
}


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
// === Artwork-token helper (återanvänder exakt samma format/signatur som övriga tokens)
function generateArtworkToken(orderId, lineItemId) {
  const tid = newTid();
  const token = signTokenPayload({
    kind: 'artwork',
    orderId: Number(orderId),
    lineItemId: Number(lineItemId),
    tid,
    iat: Date.now()
  });
  const token_hash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, tid, token_hash };
}

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
// ===== UPSTASH REDIS (WRITE-THROUGH CACHE) =====
const WRITE_ORDERS_TO_REDIS = String(process.env.WRITE_ORDERS_TO_REDIS || 'true') === 'true';
const ORDER_PROJECTS_TTL_SECONDS = parseInt(process.env.ORDER_PROJECTS_TTL_SECONDS || '864000', 10); // 10 dagar
const UPSTASH_REDIS_REST_URL   = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_REDIS_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redisCmd(commandArray) {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) return null;
  try {
    const r = await axios.post(
      UPSTASH_REDIS_REST_URL,
      commandArray, // ⬅️ Viktigt: skicka själva arrayen, inte { command: [...] }
      {
        headers: {
          Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
          'Content-Type': 'application/json'
        },
        timeout: 2000
      }
    );
    return r.data;
  } catch (e) {
    console.warn('[redisCmd] err:', e?.response?.data || e.message);
    return null;
  }
}

// ===== PASS-BY-REFERENCE TOKEN REGISTRY (Upstash Redis) =====
const ARTWORK_TOKEN_TTL_SECONDS = parseInt(process.env.ARTWORK_TOKEN_TTL_SECONDS || '2592000', 10); // 30 dagar

function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}
function tokenKey(hash) {
  return `artworktoken:${hash}:v1`;
}
async function registerTokenInRedis(token, payload /* { kind, orderId, lineItemId, iat, tid } */) {
  try {
    if (!token) return false;
    const h = tokenHash(token);
    const key = tokenKey(h);

    const kind = String(payload?.kind || 'artwork');
    const orderId = String(payload?.orderId ?? '');
    const lineItemId = String(payload?.lineItemId ?? '');
    if (!orderId || !lineItemId) return false;

    const iat = String(payload?.iat || Date.now());
    const tid = String(payload?.tid || (typeof newTid === 'function' ? newTid() : ''));
    const ver = 'v1'; // schema-version om du vill kunna migrera senare

    const flat = [
      'token_hash', h,
      'kind', kind,
      'orderId', orderId,
      'lineItemId', lineItemId,
      'iat', iat,
      'tid', tid,
      'ver', ver
    ];

    await redisCmd(['HSET', key, ...flat]);

    const ttl = Number(ARTWORK_TOKEN_TTL_SECONDS);
    if (Number.isFinite(ttl) && ttl > 0) {
      await redisCmd(['EXPIRE', key, String(ttl)]);
    }

    return true;
  } catch (e) {
    console.error('registerTokenInRedis failed:', e?.message || e);
    return false;
  }
}

async function resolveTokenFromRedis(rawToken) {
  try {
    const h = tokenHash(rawToken);
    const key = tokenKey(h);
    const r = await redisCmd(['HGETALL', key]);
    const kv = r?.result || r;
    if (!kv || typeof kv !== 'object' || !kv.orderId || !kv.lineItemId) return null;
    return {
      kind: kv.kind || 'artwork',
      orderId: Number(kv.orderId),
      lineItemId: Number(kv.lineItemId),
      iat: Number(kv.iat || 0) || Date.now(),
      tid: kv.tid || ''
    };
  } catch { return null; }
}

// Cachea hela projects-arrayen under key: order:{orderId}:projects:v1
async function cacheOrderProjects(orderId, projects) {
  if (!WRITE_ORDERS_TO_REDIS) return;
  try {
    const key = `order:${orderId}:projects:v1`;
    const payload = JSON.stringify({ projects, updatedAt: new Date().toISOString() });
    await redisCmd(["SET", key, payload, "EX", String(ORDER_PROJECTS_TTL_SECONDS)]);
  } catch (e) {
    console.warn('[cacheOrderProjects] err:', e?.response?.data || e.message);
  }
}
// ---- Redis order-sammanfattningar (lista/snabb-läsning) ----
// ZSET index per kund:  key = `cust:{customerId}:orders`  score = processedAt (epoch ms)
// HASH per order:       key = `order:{orderId}:summary`   fält: id,name,processedAt,metafield,fulfillmentStatus,preview

function epochMs(iso) {
  try { return new Date(iso).getTime() || Date.now(); } catch { return Date.now(); }
}

async function zaddCustomerOrder(customerId, orderId, processedAt) {
  const zkey = `cust:${customerId}:orders`;
  const score = String(epochMs(processedAt));
  await redisCmd(["ZADD", zkey, score, String(orderId)]);
  await redisCmd(["EXPIRE", zkey, String(ORDER_PROJECTS_TTL_SECONDS)]);
  return true;
}


async function hsetOrderSummary(orderId, summaryObj) {
  const hkey = `order:${orderId}:summary`;
  const flat = [];
  for (const [k,v] of Object.entries(summaryObj)) {
    flat.push(k, typeof v === 'string' ? v : JSON.stringify(v));
  }
  // HSET + samma TTL som projekten
  await redisCmd(["HSET", hkey, ...flat]);
  await redisCmd(["EXPIRE", hkey, String(ORDER_PROJECTS_TTL_SECONDS)]);
}

async function tryReadOrdersFromRedis(customerId, first) {
  // Läs topp N orderIds från ZSET och sen HGETALL per order
  const zkey = `cust:${customerId}:orders`;
  const zres = await redisCmd(["ZREVRANGE", zkey, "0", String(Math.max(0, first - 1))]);
  const orderIds = Array.isArray(zres?.result || zres) ? zres.result || zres : [];
  if (!orderIds.length) return [];

  const out = [];
  for (const oid of orderIds) {
    const h = await redisCmd(["HGETALL", `order:${oid}:summary`]);
    const kv = h?.result || h;
    if (kv && typeof kv === 'object' && Object.keys(kv).length) {
      out.push({
        id: Number(kv.id || oid),
        name: kv.name || null,
        processedAt: kv.processedAt || null,
        metafield: kv.metafield || null, // lagrat som sträng
        fulfillmentStatus: kv.fulfillmentStatus || null,
        displayFulfillmentStatus: null
      });
    }
  }
  return out;
}

function firstPreviewFromMeta(metafieldValue) {
  try {
    const arr = JSON.parse(metafieldValue || '[]');
    const p = Array.isArray(arr) && arr.length ? arr[0] : null;
    return p ? (p.previewUrl || p.preview_img || null) : null;
  } catch { return null; }
}

async function seedOrdersToRedis(customerId, items /* array av {id,name,processedAt,metafield,fulfillmentStatus} */) {
  try {
    for (const o of items) {
      await zaddCustomerOrder(customerId, o.id, o.processedAt);
      await hsetOrderSummary(o.id, {
        id: String(o.id),
        name: o.name || '',
        processedAt: o.processedAt || '',
        metafield: typeof o.metafield === 'string' ? o.metafield : (o.metafield ? JSON.stringify(o.metafield) : 'null'),
        fulfillmentStatus: o.fulfillmentStatus || '',
        preview: firstPreviewFromMeta(o.metafield)
      });
    }
  } catch (e) {
    console.warn('[seedOrdersToRedis] err:', e?.response?.data || e.message);
  }
}

// Hjälpare att “toucha/uppdatera” sammanfattning efter ändringar (t.ex. rename/proof/etc)
async function touchOrderSummary(customerId, orderId, { name, processedAt, metafield, fulfillmentStatus } = {}) {
  try {
    if (customerId) await zaddCustomerOrder(customerId, orderId, processedAt || new Date().toISOString());
    await hsetOrderSummary(orderId, {
      id: String(orderId),
      name: name || '',
      processedAt: processedAt || new Date().toISOString(),
      metafield: typeof metafield === 'string' ? metafield : (metafield ? JSON.stringify(metafield) : 'null'),
      fulfillmentStatus: fulfillmentStatus || ''
    });
  } catch (e) {
    console.warn('[touchOrderSummary] err:', e?.response?.data || e.message);
  }
}
// ---- END Redis order-sammanfattningar ----

// ===== END UPSTASH REDIS =====

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
// --- GLOBAL ADMIN API THROTTLE (≈1.6 rps) ---
const SHOP_ADMIN_PATTERN = SHOP ? `${SHOP}/admin/api/` : '/admin/api/';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// (Ta bort RateLimiter-klassen och adminLimiter-instansen, eller kommentera ut dem)

// Global throttling för Shopify Admin API (request-KÖ + 429-retry)
// ANVÄNDER befintlig sleep(...) ovan – redeklarera den inte här!
const ADMIN_MIN_DELAY_MS = 550; // ~1.8 rps (fortfarande under 2 rps)
let __adminLastAt = 0;
const __adminQueue = [];
let __adminDraining = false;

function isShopAdminUrl(config) {
  const full = ((config && (config.baseURL || '')) + (config && config.url || '')) || '';
  return full.includes(SHOP_ADMIN_PATTERN);
}

async function __drainQueue() {
  if (__adminDraining) return;
  __adminDraining = true;
  try {
    while (__adminQueue.length) {
      const next = __adminQueue.shift();
      const wait = Math.max(0, ADMIN_MIN_DELAY_MS - (Date.now() - __adminLastAt));
      if (wait) await sleep(wait);
      next.resolve(); // släpp igenom requesten
      __adminLastAt = Date.now();
    }
  } finally {
    __adminDraining = false;
  }
}

// Request-interceptor: alla Admin-requests går via kön
axios.interceptors.request.use(async (config) => {
  if (!isShopAdminUrl(config)) return config; // throttla bara Admin API
  await new Promise((resolve) => {
    __adminQueue.push({ resolve });
    __drainQueue();
  });
  return config;
});

// Response-interceptor: mjuk retry på 429 med Retry-After
axios.interceptors.response.use(
  (res) => res,
  async (error) => {
    const { response, config } = error || {};
    if (response && response.status === 429 && isShopAdminUrl(config)) {
      config.__retryCount = (config.__retryCount || 0) + 1;
      if (config.__retryCount <= 3) {
        const ra = parseFloat(response.headers?.['retry-after']) || 1;
        await sleep(ra * 1000);
        return axios(config);
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

app.use(bodyParser.json({ verify: (req, res, buf) => {
  req.rawBody = buf;
}}));
app.use(bodyParser.urlencoded({ extended: true }));

/* ====== NYTT: config-hjälpare ====== */
function readJson(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}
function mergeConfig(productCfg, globalsCfg) {
  const merged = { ...productCfg };
  merged.options = [ ...(globalsCfg.options || []), ...(productCfg.options || []) ];
  return merged;
}
function sendWithCache(res, cfg, versionHint) {
  const etag = `"cfg-${versionHint || cfg.version || Date.now()}"`;
  res.set('ETag', etag);
  res.set('Cache-Control', 'public, max-age=300');
  res.json(cfg);
}
/* ====== SLUT config-hjälpare ====== */
// === ARTWORK TOKEN RESOLVER (PUBLIC VIA APP PROXY) ===
app.get('/proxy/printed/artwork-token', async (req, res) => {
  try {
    // Shopify App Proxy-signatur (kräver att requesten går via /apps/...)
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }

    // Stötta flera query-nycklar
    const raw = String(req.query.artwork || req.query.token || req.query.id || '').trim();
    if (!raw) return res.status(400).json({ error: 'missing_token' });

    const payload = verifyAndParseToken(raw);
    // Tillåt tokens utan 'kind' (legacy), men neka felaktiga
    if (!payload) return res.status(401).json({ error: 'invalid_token' });
    if (payload.kind && payload.kind !== 'artwork') {
      return res.status(401).json({ error: 'wrong_token_kind' });
    }

    const { orderId, lineItemId } = payload;
    if (!orderId || !lineItemId) return res.status(400).json({ error: 'bad_payload' });

    // Hämta projektet från orderns metafält
    const { projects } = await readOrderProjects(orderId);
    const proj = (projects || []).find(p => String(p.lineItemId) === String(lineItemId));
    if (!proj) return res.status(404).json({ error: 'not_found' });

    // Plocka ut preview + filnamn (Tryckfil)
    const preview =
      proj.previewUrl || proj.preview_img || null;

    let fileName = '';
    try {
      fileName =
        (proj.properties || [])
          .find(x => x && typeof x.name === 'string' && x.name.toLowerCase() === 'tryckfil')
          ?.value || '';
    } catch {}

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      preview,
      tryckfil: fileName,
      filename: fileName, // alias som din frontend letar efter
      name: fileName
    });
  } catch (e) {
    console.error('/proxy/printed/artwork-token error:', e?.response?.data || e.message);
    setCorsOnError(req, res);
    return res.status(500).json({ error: 'internal' });
  }
});
// === PUBLIC RESOLVER: /public/printed/artwork-token ==================
// Accepterar ?artwork=, ?token= eller ?id=
// - Signerad token (p64url.<sig>): verifieras → hämtar projekt + aktiv share-snapshot.
// - Legacy (t.ex. "071ea4..." eller ett gammalt filnamn): söker i orderns projekt om möjligt.
//   Obs: legacy utan orderId blir "best effort": vi försöker hitta i senaste snapshoten/Redis-index om tillgängligt.
app.get('/public/printed/artwork-token', async (req, res) => {
  try {
    const raw =
      (req.query.artwork || req.query.token || req.query.id || '').toString().trim();
    if (!raw) return res.status(400).json({ error: 'missing_param' });

    // Helper: normalisera svar
    const sendOk = ({ preview, filename, token }) => {
      res.setHeader('Cache-Control', 'no-store');
      return res.json({
        preview,
        filename,
        tryckfil: filename,
        name: filename,
        ...(token ? { token } : {}) // gör det lättare för frontend att använda rätt suffix
      });
    };

    // 1) Är det en signerad token? (innehåller en punkt)
    if (raw.includes('.')) {
      const payload = verifyAndParseToken(raw);
      // Tillåt äldre tokens utan "kind", men om "kind" finns måste den vara 'artwork' eller 'proof'
      if (!payload || (payload.kind && !/^artwork|proof$/.test(payload.kind))) {
        return res.status(401).json({ error: 'invalid_token' });
      }

      const { orderId, lineItemId, tid } = payload || {};
      if (!orderId || !lineItemId) {
        return res.status(400).json({ error: 'bad_payload' });
      }

      // Läs projekten
      const { projects } = await readOrderProjects(orderId);
      const proj = (projects || []).find(p => String(p.lineItemId) === String(lineItemId));
      if (!proj) return res.status(404).json({ error: 'not_found' });

      // Om tokenen är en "share" (proof) – använd snapshot först
      const shares = Array.isArray(proj.shares) ? proj.shares : [];
      const active = shares.find(s => s && s.status === 'active' && (!tid || String(s.tid) === String(tid)));

      const preview =
        (active?.snapshot?.previewUrl) ||
        proj.previewUrl ||
        proj.preview_img ||
        null;

      // Försök plocka ut filnamn ("Tryckfil") från properties
      let filename = '';
      try {
        filename =
          (proj.properties || []).find(x => x && x.name && x.name.toLowerCase() === 'tryckfil')?.value || '';
      } catch {}
      if (!filename) filename = proj.tryckfil || '';

      if (!preview) return res.status(404).json({ error: 'preview_missing' });
      return sendOk({ preview, filename, token: raw });
    }

    // 2) Legacy: HEX/filnamn etc. (delbar bakåtkompatibilitet)
    // För legacy försöker vi:
    //  a) leta i senaste ordern där samma "Tryckfil" förekommer (via caches/summary om tillgängligt),
    //  b) annars (om du har Redis-index) kan du lägga in din egen lookup här.
    const legacy = decodeURIComponent(raw).toLowerCase();

    // === Minimal, säker fallback: sök i "senaste skrivna snapshoten" i order-projektens cache (Redis) ===
    // Notera: om du inte har ett centralt index – kommentera blocket nedan och ersätt med din egen lookup.
    try {
      // Hämta *senaste* aktiva share via order-sammanfattning om du har det indexerat
      // (vi använder dina redan existerande hjälpmetoder om de finns; om inte, hoppa över try-blocket)
      const recentOrders = await getRecentOrdersFromCache?.(50); // valfritt helper i din kodbas
      if (Array.isArray(recentOrders)) {
        for (const o of recentOrders) {
          const { projects } = await readOrderProjects(o.id);
          const hit = (projects || []).find(p => {
            const fn = (() => {
              try {
                return (p.properties || []).find(x => x && x.name?.toLowerCase() === 'tryckfil')?.value || '';
              } catch { return ''; }
            })().toLowerCase() || (p.tryckfil || '').toLowerCase();
            return fn && fn === legacy;
          });
          if (hit) {
            const preview = hit.previewUrl || hit.preview_img || null;
            let filename = '';
            try {
              filename =
                (hit.properties || []).find(x => x && x.name?.toLowerCase() === 'tryckfil')?.value || '';
            } catch {}
            if (!filename) filename = hit.tryckfil || '';
            if (preview) return sendOk({ preview, filename });
          }
        }
      }
    } catch {
      // Ignorera – vi har en sista fallback nedan
    }

    // 2c) Sista utväg: legacy utan träff
    return res.status(401).json({ error: 'invalid_or_legacy_unresolved' });
  } catch (e) {
    console.error('GET /public/printed/artwork-token error:', e?.response?.data || e.message);
    setCorsOnError(req, res);
    return res.status(500).json({ error: 'internal' });
  }
});
// === PUBLIC REGISTER: /public/printed/artwork-register ==================
// Body: { kind:'artwork', orderId, lineItemId, preview?, tryckfil? }
app.post('/public/printed/artwork-register', async (req, res) => {
  try {
    const { kind, orderId, lineItemId, preview, tryckfil } = req.body || {};
    if (!orderId || !lineItemId) {
      return res.status(400).json({ ok:false, error:'missing_params' });
    }

    // Endast artwork tillåts här (proof har egen flow)
    const k = String(kind || 'artwork').toLowerCase();
    if (k !== 'artwork') return res.status(400).json({ ok:false, error:'invalid_kind' });

    // Skapa signerad token (DELNINGSBAR)
    const tid = newTid();
    const token = signTokenPayload({
      kind: 'artwork',
      orderId: Number(orderId),
      lineItemId: Number(lineItemId),
      tid,
      iat: Date.now()
    });

    // Valfritt: registrera i Redis så resolvern kan “pass-by-reference”
    try {
      await registerTokenInRedis(token, {
        kind: 'artwork',
        orderId: Number(orderId),
        lineItemId: Number(lineItemId),
        iat: Date.now(),
        tid,
        // små hjälpfält för snabb client-preview
        preview: preview || null,
        tryckfil: tryckfil || ''
      });
    } catch {}

    const url = `${STORE_BASE}/pages/printed?artwork=${encodeURIComponent(token)}`;
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok:true, token, url });
  } catch (e) {
    console.error('POST /public/printed/artwork-register:', e?.response?.data || e.message);
    setCorsOnError(req, res);
    return res.status(500).json({ ok:false, error:'internal' });
  }
});

// === Alias så att /apps/... träffar den publika resolvern (utan redirect) ===
app.get('/apps/printed/artwork-token',  forward('/public/printed/artwork-token'));
app.get('/apps/pressify/artwork-token', forward('/public/printed/artwork-token'));
app.get('/apps/artwork-token',          forward('/public/printed/artwork-token'));
app.post('/apps/printed/artwork-register',  forward('/public/printed/artwork-register'));
app.post('/apps/pressify/artwork-register', forward('/public/printed/artwork-register'));
app.post('/apps/artwork-register',          forward('/public/printed/artwork-register'));



// Liten hälsosida så "Cannot GET /" försvinner
app.get('/', (req, res) => res.type('text').send('OK'));
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/health', (req, res) => res.sendStatus(204));

// ⬇️⬇️ NYTT: hämta merged config (ex: /calc/etiketter)
const cfgMem = new Map(); // id -> { at, data }
app.get('/calc/:id', (req, res) => {
  try {
    const id = req.params.id;
    const now = Date.now();
    const hit = cfgMem.get(id);
    if (hit && (now - hit.at) < 60_000) { // 60s
      return sendWithCache(res, hit.data, hit.data.version);
    }

    const baseDir = process.env.CONFIG_DIR || path.join(__dirname, 'configs');
    const globalsPath = path.join(baseDir, 'globals.json');
    const productPath = path.join(baseDir, `${id}.json`);

    if (!fs.existsSync(productPath)) {
      setCorsOnError(req, res);
      return res.status(404).json({ error: `Config not found: ${id}` });
    }

    const productCfg = readJson(productPath);
    const globalsCfg = fs.existsSync(globalsPath) ? readJson(globalsPath) : { options: [] };
    const merged = mergeConfig(productCfg, globalsCfg);
    cfgMem.set(id, { at: now, data: merged });

    sendWithCache(res, merged, productCfg.version);
  } catch (e) {
    setCorsOnError(req, res);
    res.status(500).json({ error: 'Failed to load config' });
  }
});

// ⬆️⬆️ SLUT NYTT

/* ========= PRESSIFY DRAFT ORDER (ENDPOINTS + NORMALISERING + SANERING) ========= */

// 1) Sanera properties – tillåt bara synliga fält (det du visar i varukorgen)
const STRIP_KEYS = new Set([
  'calc_payload','preview_img',
  '_total_price','total_price',
  'qty','Qty'
]);
function isBlank(v){ return v==null || String(v).trim()===''; }
function num(v){ const n = Number(String(v??'').replace(',','.')); return Number.isFinite(n)?n:0; }

// Object → [{name,value}]
function propsObjToArray(obj){
  const out = [];
  for (const [k,v] of Object.entries(obj||{})){
    if (isBlank(v)) continue;
    out.push({ name:String(k), value:String(v) });
  }
  return out;
}
// --- hidden property for internal linking (döljs i checkout) ---
const HIDDEN_PRODUCT_ID_KEY = '_product_id';
function appendHiddenProp(props, name, value) {
  const arr = Array.isArray(props) ? props : [];
  const val = value == null ? '' : String(value).trim();
  if (!val) return arr;
  const exists = arr.some(p => String(p?.name || '').toLowerCase() === String(name).toLowerCase());
  return exists ? arr : [...arr, { name, value: val }];
}
function appendHiddenIds(props, pid, vid) {
  const arr = Array.isArray(props) ? props.slice() : [];
  const lower = new Set(arr.map(p => String(p?.name || '').toLowerCase()));
  const add = (name, value) => {
    const v = String(value ?? '').trim();
    if (!v) return;
    if (!lower.has(name.toLowerCase())) arr.push({ name, value: v });
  };
  // Dolda fält (Shopify visar inte properties som börjar med "_")
  add('_product_id', pid);
  add('_variant_id', vid);
  return arr;
}

// Array/Obj → sanerad array
function sanitizeProps(props){
  const arr = Array.isArray(props) ? props : propsObjToArray(props);
  const out = [];
  for (const p of (arr||[])){
    if (!p) continue;
    const name = String(p.name||p.key||'').trim();
    const value = String(p.value ?? '').trim();
    if (!name || isBlank(value)) continue;
    if (STRIP_KEYS.has(name)) continue;
    out.push({ name, value });
  }
  return out;
}

async function buildCustomLinesFromGeneric(items){
  const lines = [];

  // Batcha uppslag av taxable
  const variantIds = items.map(it => it.variantId || it.variant_id).filter(Boolean);
  const productIds = items.map(it => it.productId  || it.product_id).filter(Boolean);
  const [vTaxMap, pTaxMap] = await Promise.all([
    getVariantTaxableMap(variantIds),
    getProductDefaultTaxableMap(productIds)
  ]);

  for (const it of (items||[])){
    const qty = Math.max(1, parseInt(it.quantity ?? it.qty ?? 1, 10));
    const propsIn  = it.properties || {};
    const propsArr = Array.isArray(propsIn) ? propsIn : propsObjToArray(propsIn);

    const rawTotalProp = (() => {
      try {
        const map = new Map(propsArr.map(p=>[String(p.name||'').toLowerCase(), p.value]));
        return map.get('_total_price') ?? map.get('total_price');
      } catch { return null; }
    })();
    const lineTotal =
      !isBlank(rawTotalProp) ? num(rawTotalProp) :
      (typeof it.custom_line_total === 'number' ? it.custom_line_total :
      (typeof it.line_price_hint === 'number' ? it.line_price_hint : 0));
    const unitCustom = qty > 0
      ? (typeof it.custom_price === 'number' ? it.custom_price : Number((lineTotal/qty).toFixed(2)))
      : 0;

    // Bestäm taxable
    const vid = it.variantId || it.variant_id;
    const pid = it.productId  || it.product_id;
    const propsSafe = appendHiddenIds(sanitizeProps(propsArr), pid, vid);
    let taxable = true; // default moms = på
    if (vid && typeof vTaxMap[vid] === 'boolean') {
      taxable = vTaxMap[vid];
    } else if (pid && typeof pTaxMap[pid] === 'boolean') {
      taxable = pTaxMap[pid];
    }

    lines.push({
      custom: true,
      title: String(it.title || it.productTitle || 'Trycksak'),
      quantity: qty,
      price: normalizePrice(unitCustom),
      taxable, // ⬅️ viktigt
      requires_shipping: true,
      properties: propsSafe
    });
  }
  return lines;
}

// --- helpers för pris och email ---

// Shopify vill ha pris som STRÄNG med två decimaler, punkt som decimaltecken
function normalizePrice(v) {
  const n = Number(String(v ?? '').replace(',', '.'));
  const safe = Number.isFinite(n) ? Math.max(0, n) : 0;
  return safe.toFixed(2);
}


// Minimal emailvalidering; vi tar hellre bort felaktiga email än låter Shopify tolka dem
function isValidEmail(e) {
  if (!e || typeof e !== 'string') return false;
  // enkel men robust: text@text.tld, inga mellanslag
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim());
}

// Ta bort felaktiga email så att Shopify inte försöker koppla kund eller trigga moms/discount-regler fel
function purgeInvalidEmails(payload) {
  try {
    const d = payload?.draft_order || {};
    if (d.email && !isValidEmail(d.email)) delete d.email;
    if (d.customer && typeof d.customer === 'object') {
      if (d.customer.email && !isValidEmail(d.customer.email)) delete d.customer.email;
    }
  } catch {}
  return payload;
}


// 3) Huvud-handler: tar emot flera möjliga format och skapar draft_order
async function handleDraftCreate(req, res){
  try{
    const body = req.body || {};
    let payloadToShopify = null;

    // A) Om frontend skickar ett färdigt shopify.draft_order → sanera + vidarebefordra
    if (body.shopify && body.shopify.draft_order && Array.isArray(body.shopify.draft_order.line_items)) {
      const incoming = body.shopify.draft_order;
// Bygg taxable-kartor en gång
const vTaxMap = await getVariantTaxableMap((incoming.line_items || []).map(li => li.variant_id).filter(Boolean));
const pTaxMap = await getProductDefaultTaxableMap((incoming.line_items || []).map(li => li.product_id).filter(Boolean));

const cleanLines = incoming.line_items.map(li => {
  const qty = Math.max(1, parseInt(li.quantity || 1, 10));
  const props = appendHiddenIds(sanitizeProps(li.properties || []), li.product_id, li.variant_id);
  const hasCustomPrice = (typeof li.price !== 'undefined') || !!li.custom;

  const vid = li.variant_id;
  const pid = li.product_id;
  const inferredTaxable =
    typeof vTaxMap[vid] === 'boolean' ? vTaxMap[vid] :
    (typeof pTaxMap[pid] === 'boolean' ? pTaxMap[pid] : true);

if (hasCustomPrice) {
    return {
      custom: true,
      title: String(li.title || 'Trycksak'),
      quantity: qty,
      price: normalizePrice(li.price),
      taxable: inferredTaxable,          // ⬅️ lägg på taxable
      requires_shipping: true,
      properties: props 
    };
  }

  const out = {
    ...(li.variant_id ? { variant_id: li.variant_id } : {}),
    quantity: qty,
    properties: props
  };

  if (li.applied_discount) {
    const ad = li.applied_discount || {};
    out.applied_discount = {
      title: String(ad.title || 'Pressify pris'),
      value_type: ad.value_type === 'fixed_amount' ? 'fixed_amount' : 'percentage',
      value: Number.isFinite(Number(ad.value)) ? String(ad.value) : '0'
    };
  }

  if (!out.variant_id) {
    return {
      custom: true,
      title: String(li.title || 'Trycksak'),
      quantity: qty,
      price: normalizePrice(0),
      taxable: inferredTaxable,          // ⬅️ även här
      requires_shipping: true,
      properties: props 
    };
  }
  return out;
});



const shopCfg = await getShopTaxConfig();
payloadToShopify = {
  draft_order: {
    ...incoming,
    line_items: cleanLines,
    ...(body.note ? { note: body.note } : {}),
    taxes_included: shopCfg.taxes_included,
    tags: incoming.tags ? String(incoming.tags) : 'pressify,draft-checkout'
  }
};
}

    // B) Annars: bygg egna custom lines från lineItems/lines (kör på ert pris)
    if (!payloadToShopify) {
      const items = Array.isArray(body.lineItems) ? body.lineItems :
                    Array.isArray(body.lines)     ? body.lines     : [];
      if (!items.length) {
        return res.status(400).json({ error: 'Inga rader i payload' });
      }
 const shopCfg = await getShopTaxConfig();
const line_items = await buildCustomLinesFromGeneric(items);
payloadToShopify = {
  draft_order: {
    line_items,
    ...(body.note ? { note: body.note } : {}),
    ...(body.customerId ? { customer: { id: body.customerId } } : {}),
    taxes_included: shopCfg.taxes_included,
    tags: 'pressify,draft-checkout'
  }
};
  }

    // 4) Skicka till Shopify
    payloadToShopify = purgeInvalidEmails(payloadToShopify); // ✅ ta bort ogiltiga email 
      
    const r = await axios.post(
      `https://${SHOP}/admin/api/2025-07/draft_orders.json`,
      payloadToShopify,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type':'application/json' } }
    );

    const draft = r.data?.draft_order;
    if (!draft || !draft.invoice_url) {
      return res.status(502).json({ error: 'draft_order saknar invoice_url' });
    }

    // 5) Svara uniformt (frontend letar flera nycklar)
    return res.json({
      ok: true,
      draft_order_id: draft.id,
      name: draft.name,
      invoice_url: draft.invoice_url,
      invoiceUrl: draft.invoice_url,
      url: draft.invoice_url
    });
  } catch (e){
    console.error('[draft create] error:', e?.response?.data || e.message);
    try { setCorsOnError(req, res); } catch {}
    return res.status(500).json({ error: 'internal' });
  }
}

// 4) Montera alla endpoints som frontend testar → samma handler
const DRAFT_ROUTES = [
  '/draft-order/create',
  '/api/draft-order/create',
  '/draft/create',
  '/api/draft/create',
  '/shopify/draft-order/create',
  '/api/shopify/draft-order/create',
  '/invoice/create',
  '/api/invoice/create',
  '/draft-order/create-upload-only'
];
DRAFT_ROUTES.forEach(p => app.post(p, handleDraftCreate));



/* ========= SLUT PRESSIFY DRAFT ORDER ========= */
// ===== NY ROUTE (DIN) – placerad direkt efter "SLUT PRESSIFY DRAFT ORDER" =====
app.all('/din/nya/route', async (req, res) => {
  try {
    // Din helt fristående logik här
    return res.json({ ok: true });
  } catch (e) {
    // behåll samma felmönster
    console.error('/din/nya/route error:', e?.response?.data || e.message);
    setCorsOnError(req, res);
    return res.status(500).json({ error: 'Internal error' });
  }
});
// ===== SLUT NY ROUTE (DIN) =====


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
  const digestHex = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(ordered).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(digestHex, 'hex'), Buffer.from(String(hmac || ''), 'hex'));
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
  const hmacHeader = String(req.get('X-Shopify-Hmac-Sha256') || '');
  const digest = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody, 'utf8')
    .digest('base64');

  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));
  } catch {
    return false;
  }
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
  { metafield: { id: metafieldId, ...payload.metafield } },
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
    setCorsOnError(req, res);
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
// ---------------- HELPER-FUNKTIONER FÖR ORDER-PROPERTIES ----------------
function arrToMapByName(props = []) {
  // Gör uppslag både case-sens och lowercased för smidiga hits
  const m = new Map();
  for (const p of props) {
    if (!p || typeof p.name !== 'string') continue;
    const name = String(p.name);
    const val = p.value ?? '';
    m.set(name, val);
    m.set(name.toLowerCase(), val);
  }
  return m;
}

function pickFirstNonEmpty(map, keys = []) {
  for (const k of keys) {
    const v = map.get(k) ?? map.get(String(k).toLowerCase());
    if (v != null && String(v).trim() !== '') return String(v);
  }
  return null;
}

function buildPrettyProperties(propsMap) {
  // Bygg en prydlig, konsekvent lista för admin/UIs
  const out = [];
  const add = (name, keyList) => {
    const v = pickFirstNonEmpty(propsMap, keyList);
    if (v) out.push({ name, value: v });
  };

  add('Storlek (BxH)', ['Storlek (BxH)', 'Storlek', 'size']);
  add('Material',      ['Material']);
  add('Finish',        ['Finish']);
  add('Antal',         ['Antal', 'qty', 'quantity']);
  add('Tryckfil',      ['Tryckfil', 'fileName', 'filnamn']); // säkerställs alltid nedan också

  return out;
}
// ---------------- SLUT HELPER-FUNKTIONER ----------------

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

  // === BLOCK A: Välj fraktmetod + hämta/merga ledtider för alla rader (arbetsdagar) ===
  const chosenMethod = (() => {
    const sl = Array.isArray(order.shipping_lines) && order.shipping_lines[0] ? order.shipping_lines[0] : null;
    const t = String(sl?.code || sl?.title || '').toLowerCase();
    return /express/.test(t) ? 'express' : 'standard';
  })();

  // Beräkna sammanlagt fönster från alla rader via befintlig helper
  const win = await pressifyComputeWindowsFromCart(lineItems);
  const pickedWindow = chosenMethod === 'express' ? (win?.exp || null) : (win?.std || null);

  // Fallback till globala defaults om inget metafält fanns på produkterna
  const merged = pickedWindow && Number.isFinite(pickedWindow.minDays) && Number.isFinite(pickedWindow.maxDays)
    ? { minDays: pickedWindow.minDays, maxDays: pickedWindow.maxDays }
    : (chosenMethod === 'express' ? PRESSIFY_DEFAULT_EXP : PRESSIFY_DEFAULT_STD);

  // Baslinje = processed_at eller created_at (00:00 ej nödvändigt att forceras här)
  const baselineISO = String(order.processed_at || order.created_at || new Date().toISOString());
  const baseDate = new Date(baselineISO);
  const etaFrom = pressifyAddBusinessDays(baseDate, merged.minDays);
  const etaTo   = pressifyAddBusinessDays(baseDate, merged.maxDays);
  const etaLabel = pressifySvShortRange(etaFrom, etaTo);
  // === SLUT BLOCK A ===

  // Mappa varje radpost till ett projekt – SPARA ALLA PROPERTIES (pretty först)
  const newProjects = await Promise.all(lineItems.map(async (item) => {
    // A) Läs ALLA properties från raden och normalisera (behåll allt icke-tomt)
    const rawProps = Array.isArray(item.properties) ? item.properties : [];
    const allClean = rawProps
      .filter(p => p && typeof p.name === 'string')
      .map(p => ({ name: String(p.name), value: String(p.value ?? '') }))
      .filter(p => p.value.trim() !== '');

    // B) Bygg uppslagskarta på allClean (används av alias + övriga fält)
    const m = arrToMapByName(allClean);

    // C) Derivera nyckelfält
    const tryckfil = pickFirstNonEmpty(m, ['Tryckfil','_tryckfil','fileName','filnamn']);
    const instructionsProp = pickFirstNonEmpty(m, ['Instruktioner','Instructions','instructions','_instructions','Önskemål','onskemal']);
    const previewFromProp = pickFirstNonEmpty(m, ['preview_img','_preview_img']);
    const fallback = tryckfil ? (temporaryStorage[tryckfil] || {}) : {};
    const preview_img = previewFromProp || fallback.previewUrl || null;
    const cloudinaryPublicId = fallback.cloudinaryPublicId || null;

    // D) “Pretty” alias först …
    const pretty = buildPrettyProperties(m);

    // … följt av ALLA övriga properties utan dubbletter (namn-match, case-insensitivt)
    const picked = new Set(pretty.map(p => p.name.toLowerCase()));
    const rest = allClean.filter(p => !picked.has(p.name.toLowerCase()));
    let properties = [...pretty, ...rest];

    // E) Säkerställ Tryckfil i listan om den saknas
    if (tryckfil && !properties.some(p => p.name.toLowerCase() === 'tryckfil')) {
      properties.push({ name: 'Tryckfil', value: tryckfil });
    }

    // ⭐ Artwork-token
    const { token: artworkToken, tid } = generateArtworkToken(orderId, item.id);
    await registerTokenInRedis(artworkToken, {
      kind: 'artwork',
      orderId: Number(orderId),
      lineItemId: Number(item.id),
      iat: Date.now(),
      tid
    });

    return {
      orderId,
      lineItemId:   item.id,
      productId:    item.product_id,
      productTitle: item.title,
      variantId:    item.variant_id,
      variantTitle: item.variant_title,
      quantity:     item.quantity,
      properties,
      preview_img,
      cloudinaryPublicId,
      instructions: instructionsProp ?? null,
      customerId,
      orderNumber,
      status: 'Väntar på korrektur',
      tag:    'Väntar på korrektur',
      date: new Date().toISOString(),
      artworkToken,                       // ← KOMMA VIKTIGT
      // === NYTT: dynamiskt leveransfönster (fram till godkänd korrektur)
      delivery: {
        v: 1,
        chosen: chosenMethod,              // 'standard' | 'express'
        window: {
          minDays: merged.minDays,
          maxDays: merged.maxDays,
          fromISO: etaFrom.toISOString().slice(0,10),
          toISO:   etaTo.toISOString().slice(0,10),
          label:   etaLabel
        },
        dynamicBase: {
          orderProcessedAt: baselineISO,
          computedAt: new Date().toISOString()
        },
        fixed: null
      }
    };
  }));





  if (newProjects.length === 0) return res.sendStatus(200);
  // 🔹 ENRICH: injicera productHandle per projekt (utan att ändra befintlig logik)
// ... efter newProjects och enrich-blocket:
let enrichedProjects = newProjects;
try {
  const ids = newProjects.map(p => p.productId).filter(Boolean);
  const handleMap = await getProductHandlesById(ids);
  enrichedProjects = newProjects.map(p => ({
    ...p,
    ...(handleMap[p.productId] ? { productHandle: handleMap[p.productId] } : {})
  }));
} catch (e) {
  console.warn('order-created enrich productHandle:', e?.response?.data || e.message);
}
try {
  // 1) Läs befintliga metafält
  const existing = await axios.get(
    `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
    { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
  );

 const currentMetafield = (existing.data.metafields || []).find(
  mf => mf.namespace === ORDER_META_NAMESPACE && mf.key === ORDER_META_KEY
);

 // === Idempotent upsert per (orderId + lineItemId) för att undvika dubbletter ===
 function upsertProjects(existingArr, newArr) {
    const byKey = new Map();
    for (const p of Array.isArray(existingArr) ? existingArr : []) {
      const k = `${p?.orderId || ''}:${p?.lineItemId || ''}`;
      if (!k.includes(':')) continue;
      byKey.set(k, p);
    }
    for (const n of Array.isArray(newArr) ? newArr : []) {
      const k = `${n?.orderId || ''}:${n?.lineItemId || ''}`;
      if (!k.includes(':')) continue;
      const prev = byKey.get(k);
      if (prev) {
        byKey.set(k, {
          ...prev,
          ...n,
          // behåll ev. redan skapade värden som inte ska skrivas över vid retry
          shares: prev.shares ?? n.shares,
         latestToken: prev.latestToken ?? n.latestToken,
         latestShareUrl: prev.latestShareUrl ?? n.latestShareUrl,
          delivery: {
            ...(n.delivery || {}),
            fixed: (prev.delivery && prev.delivery.fixed)
              ? prev.delivery.fixed
              : (n.delivery ? n.delivery.fixed : null),
          },
        });
      } else {
        byKey.set(k, n);
      }
   }
   return Array.from(byKey.values());
  }

  // 2) Kombinera idempotent (befintligt + enrichedProjects)
  let combined;
  if (currentMetafield && currentMetafield.value) {
    try {
      const existingData = JSON.parse(currentMetafield.value);
     combined = upsertProjects(existingData, enrichedProjects);
    } catch (e) {
      console.warn('Kunde inte tolka gammal JSON:', e);
      combined = upsertProjects([], enrichedProjects);
    }
  } else {
    combined = upsertProjects([], enrichedProjects);
  }

  // 3) Spara combined
  if (currentMetafield) {
    await axios.put(
      `https://${SHOP}/admin/api/2025-07/metafields/${currentMetafield.id}.json`,
      { metafield: { id: currentMetafield.id, type: 'json', value: JSON.stringify(combined) } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
  } else {
    await axios.post(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
     { metafield: { namespace: ORDER_META_NAMESPACE, key: ORDER_META_KEY, type: 'json', value: JSON.stringify(combined) } },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
  }

  console.log('✅ Metafält sparat!');
  try { await cacheOrderProjects(orderId, combined); } catch {}

  // 4) Activity-log använder samma combined (som nu innehåller productHandle)
  try {
    const customerName = ((order.customer?.first_name || '') + ' ' + (order.customer?.last_name || '')).trim() || 'Kund';
    const customerActor = { type: 'customer', name: customerName, id: customerId ? `customer:${customerId}` : undefined };
    const ts = order.processed_at || order.created_at || new Date().toISOString();

    const firstEntries = combined.map(p => {
      let fileName = '';
      try { fileName = (p.properties || []).find(x => x && x.name === 'Tryckfil')?.value || ''; } catch {}
      return {
        ts,
        actor: customerActor,
        action: 'file.uploaded',
        order_id: orderId,
        line_item_id: p.lineItemId,
        product_title: p.productTitle,
        project_id: fileName || undefined,
        data: Object.assign({}, fileName ? { fileName } : {}, p.instructions ? { instructions: String(p.instructions) } : {}),
        correlation_id: `order.created:${orderId}:${p.lineItemId}`
      };
    });

    await appendActivity(orderId, firstEntries);
  } catch (e) {
    console.warn('order-created → appendActivity misslyckades:', e?.response?.data || e.message);
  }

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
    const q = `customer_id:${customerId} status:any`;
    const query = `
      query OrdersWithProof($first:Int!,$q:String!,$ns:String!,$key:String!){
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
    const data = await shopifyGraphQL(query, { first: 50, q, ns: ORDER_META_NAMESPACE, key: ORDER_META_KEY });
    if (data.errors) throw new Error('GraphQL error');

    const edges = data?.data?.orders?.edges || [];
    const results = [];
    for (const e of edges) {
      const orderId = Number(gidToId(e.node.id));
      let arr = [];
      try { arr = e.node.metafield?.value ? JSON.parse(e.node.metafield.value) : []; } catch { arr = []; }
      const awaiting = (arr || [])
        .filter(p => String(p?.status) === 'Korrektur redo')
        .map(p => ({ ...p, orderId }));
      results.push(...awaiting);
    }

    if (results.length === 0) {
      return res.json({ message: 'Just nu har du ingenting att godkänna', projects: [] });
    }
    return res.json({ message: 'Godkänn korrektur', projects: results });
  } catch (err) {
    console.error('❌ Fel vid hämtning av korrektur (GraphQL):', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Internt serverfel' });
  }
});

// Uppdatera korrektur-status (när du laddar upp korrekturbild) — TOKENS + SNAPSHOT (inkluderar senaste eventet)
app.post('/proof/upload', async (req, res) => {
  const { orderId, lineItemId, previewUrl, proofNote } = req.body;
  if (!orderId || !lineItemId || !previewUrl) {
    return res.status(400).json({ error: 'orderId, lineItemId och previewUrl krävs' });
  }

  try {
    // 1) Läs order-created
    const { metafieldId, projects } = await readOrderProjects(orderId);
    if (!metafieldId) return res.status(404).json({ error: 'Metafält hittades inte' });

    // 2) Uppdatera preview/status
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

    // 3) Förbered data för activity-entry (innan snapshot)
    const projAfter = nextProjects.find(p => String(p.lineItemId) === String(lineItemId)) || {};
    const fileName = (() => {
      try { return (projAfter.properties || []).find(x => x && x.name === 'Tryckfil')?.value || ''; } catch { return ''; }
    })();
    const nowTs = new Date().toISOString();

    // 4) Skriv in activity “proof.uploaded” FÖRST
    try {
      await appendActivity(orderId, [{
        ts: nowTs,
        actor: { type: 'admin', name: 'Pressify' },
        action: 'proof.uploaded',
        order_id: Number(orderId),
        line_item_id: Number(lineItemId),
        product_title: projAfter.productTitle || '',
        project_id: fileName || undefined,
        data: Object.assign({ previewUrl }, (proofNote && proofNote.trim() ? { note: proofNote.trim() } : {})),
        correlation_id: `proof.uploaded:${orderId}:${lineItemId}:${previewUrl}`
      }]);
    } catch (e) {
      console.warn('/proof/upload → appendActivity misslyckades:', e?.response?.data || e.message);
    }

    // 5) Läs aktivitetsloggen EFTER att vi lagt in “proof.uploaded” och bygg snapshot
    const { log } = await getActivityLog(orderId);
    const snapActivity = sliceActivityForLine(log, lineItemId);
    const snap = { ...safeProjectFields(projAfter), activity: snapActivity, hideActivity: false };

    // 6) Generera token
    const tid = newTid();
    const token = signTokenPayload({ kind: 'proof', orderId: Number(orderId), lineItemId: Number(lineItemId), tid, iat: Date.now() });

    // 7) Rotera shares[] och spara snapshot
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
      return { ...p, shares: [share, ...superseded].slice(0, 10), latestToken: tid, latestShareUrl: `${STORE_BASE}${PUBLIC_PROOF_PATH}?token=${encodeURIComponent(token)}` };
    });

    // 8) Spara tillbaka i SAMMA metafält
    await writeOrderProjects(metafieldId, rotated);
    // +++ NYTT: cache till Redis (10 dagar) +++
    try { await cacheOrderProjects(orderId, rotated); } catch {}
// ---- NYTT: uppdatera order-sammanfattning i Redis ----
try {
  const projForCid = rotated.find(p => String(p.lineItemId) === String(lineItemId));
  const customerIdForIndex = projForCid?.customerId ? Number(projForCid.customerId) : null;
  await touchOrderSummary(customerIdForIndex, Number(orderId), {
    processedAt: new Date().toISOString(),
    metafield: JSON.stringify(rotated || [])
  });
} catch {}

    // 9) Svara med token + URL
    const url = `${STORE_BASE}${PUBLIC_PROOF_PATH}?token=${encodeURIComponent(token)}`;
    const backendShare = `${HOST}/proof/share/${encodeURIComponent(token)}`;
    return res.json({ ok: true, token, url, backendShare });

  } catch (err) {
    console.error('❌ Fel vid /proof/upload:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Kunde inte uppdatera korrektur' });
  }
});

// Godkänn korrektur (med frysning av leveransdatum)
app.post('/proof/approve', async (req, res) => {
  const { orderId, lineItemId } = req.body;
  if (!orderId || !lineItemId) return res.status(400).json({ error: 'orderId och lineItemId krävs' });

  try {
    // 1) Läs orderns projekt-metafält
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

    const metafield = (data.metafields || []).find(mf => mf.namespace === ORDER_META_NAMESPACE && mf.key === ORDER_META_KEY);
    if (!metafield) return res.status(404).json({ error: 'Metafält hittades inte' });

    // 2) Uppdatera status + preview_img
    let projects = [];
    try { projects = JSON.parse(metafield.value || '[]'); } catch { projects = []; }

    projects = projects.map(p => {
      if (String(p.lineItemId) === String(lineItemId)) {
        return {
          ...p,
          status: 'I produktion',
          preview_img: p.previewUrl || p.preview_img || null
        };
      }
      return p;
    });

   // 3) === BLOCK C: Frys leveransdatum (behåll MIN–MAX) ===
try {
  const idx = projects.findIndex(p => String(p.lineItemId) === String(lineItemId));
  if (idx !== -1) {
    const prj = projects[idx];

    // Bara om dynamiskt fönster finns och inte redan är fryst
    if (prj && prj.delivery && !prj.delivery.fixed && prj.delivery.window && prj.delivery.dynamicBase) {
      const base = new Date(prj.delivery.dynamicBase.orderProcessedAt || prj.date || new Date());
      base.setHours(0, 0, 0, 0);

      const today = new Date();
      today.setHours(0, 0, 0, 0);

      // Räkna antal passerade arbetsdagar (mån–fre)
      let delta = 0;
      const d = new Date(base);
      while (d < today) {
        d.setDate(d.getDate() + 1);
        const wd = d.getDay(); // 0=sön, 6=lör
        if (wd !== 0 && wd !== 6) delta++;
      }

      // Frys BOTH: from = base + (minDays + delta), to = base + (maxDays + delta)
      const minDays = Number(prj.delivery.window.minDays || 0);
      const maxDays = Number(prj.delivery.window.maxDays || 0);

      const fromDate = pressifyAddBusinessDays(base, minDays + delta);
      const toDate   = pressifyAddBusinessDays(base, maxDays + delta);

      prj.delivery.fixed = {
        fromISO: fromDate.toISOString().slice(0, 10),  // "YYYY-MM-DD"
        toISO:   toDate.toISOString().slice(0, 10),    // "YYYY-MM-DD"
        label:   pressifySvShortRange(fromDate, toDate),
        fixedAt: new Date().toISOString()
      };

      projects[idx] = prj; // skriv tillbaka mutationen
    }
  }
} catch (freezeErr) {
  console.warn('BLOCK C (freeze ETA) misslyckades:', freezeErr?.response?.data || freezeErr.message);
}
// === SLUT BLOCK C ===


    // 4) PUT: skriv tillbaka hela projektlistan
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
  try { await cacheOrderProjects(orderId, prj2); } catch {}
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
  mf.namespace === ORDER_META_NAMESPACE && mf.key === ORDER_META_KEY
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
// +++ NYTT: cache till Redis (10 dagar) +++
try { await cacheOrderProjects(orderId, projects); } catch {}

// ---- NYTT: uppdatera order-sammanfattning i Redis ----
try {
  const projForCid = (projects || []).find(p => String(p.lineItemId) === String(lineItemId));
  const customerIdForIndex = projForCid?.customerId ? Number(projForCid.customerId) : null;
  await touchOrderSummary(customerIdForIndex, Number(orderId), {
    processedAt: new Date().toISOString(),
    metafield: JSON.stringify(projects || [])
  });
} catch {}

    
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
    setCorsOnError(req, res);
    return res.status(500).json({ error: 'Internal error' });
  }
});
// ===== REFERLINK: hämta eller skapa per-kund slug + redirect =====
app.get('/proxy/link', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'not_logged_in' });

    const cidRaw = String(loggedInCustomerId);
    const customerId = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;

    // Läs JSON-metafältet referlink.referlink
    let { metafieldId, value } = await readCustomerReferlink(customerId);

    // Skapa om saknas
    if (!value || !value.slug) {
      const slug = makeSlugFromCustomerId(customerId);
      value = referlinkJsonFor(slug);
      await writeCustomerReferlink(customerId, metafieldId, value);
      await ensureRootRedirectToHome(value.slug); // /<slug> → /
    }

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, referlink: value });
  } catch (e) {
    console.error('GET /proxy/link:', e?.response?.data || e.message);
    return res.status(500).json({ error: 'internal' });
  }
});
// ============================================================
// ALIAS-ROUTES när App Proxy INTE har "/proxy" i Proxy URL
// Ex: Shopify proxar /apps/orders-meta/link → din server /link
// Vi skickar internt vidare till den säkrade /proxy/link (utan redirect).
// ============================================================
function forward(toPath) {
  return (req, res, next) => {
    const origUrl = req.url;
    const qs = origUrl.includes('?') ? origUrl.slice(origUrl.indexOf('?')) : '';
    req.url = `${toPath}${qs}`;
    return app._router.handle(req, res, (err) => {
      req.url = origUrl;
      if (err) return next(err);
    });
  };
}


// 1) /link  → /proxy/link
app.get('/link', forward('/proxy/link'));

// 2) /orders-meta/link  → /proxy/link
app.get('/orders-meta/link', forward('/proxy/link'));

// 3) /orders-meta/avatar (GET/POST) → /proxy/orders-meta/avatar
app.all('/orders-meta/avatar', forward('/proxy/orders-meta/avatar'));

// Duplicerad path om din butik använder /proxy/orders-meta/...
app.get('/proxy/orders-meta/link', forward('/proxy/link'));

// 4) /orders-meta/rename (POST) → /proxy/orders-meta/rename
app.post('/orders-meta/rename', forward('/proxy/orders-meta/rename'));

// 5) /apps/orders-meta/rename (POST) → /proxy/orders-meta/rename
app.post('/apps/orders-meta/rename', forward('/proxy/orders-meta/rename'));


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
    setCorsOnError(req, res);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// 🔹 Hjälp: hämta product.handle för en lista av product_id (unik, liten volym per order)
const HANDLE_CACHE_TTL = 5 * 60 * 1000;
const __productHandleCache = new Map(); // productId -> { at, value:string }

async function getProductHandlesById(productIds = []) {
  const uniq = Array.from(new Set((productIds || []).filter(Boolean).map(String)));
  const out = Object.create(null);

  const missing = [];
  for (const pid of uniq) {
    const hit = __productHandleCache.get(pid);
    if (hit && (Date.now() - hit.at) < HANDLE_CACHE_TTL) {
      if (hit.value) out[pid] = hit.value;
    } else {
      missing.push(pid);
    }
  }
  if (missing.length === 0) return out;

  const chunk = (arr, n) => arr.reduce((a, _, i) => (i % n ? a : [...a, arr.slice(i, i+n)]), []);
  for (const group of chunk(missing, 250)) {
    try {
      const ids = group.map(id => toGid('Product', id));
      const query = `
        query ProductHandles($ids:[ID!]!) {
          nodes(ids:$ids) { ... on Product { id handle } }
        }`;
      const data = await shopifyGraphQL(query, { ids });
      const nodes = data?.data?.nodes || [];
      for (const n of nodes) {
        if (n && n.id) {
          const id = gidToId(n.id);
          const handle = n.handle || null;
          if (handle) {
            out[id] = handle;
            __productHandleCache.set(id, { at: Date.now(), value: handle });
          }
        }
      }
    } catch (e) {
      // Fallback: REST för det som saknas
      await Promise.all(group.map(async (pid) => {
        if (out[pid] !== undefined) return;
        try {
          const { data } = await axios.get(
            `https://${SHOP}/admin/api/2025-07/products/${pid}.json?fields=handle`,
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
          const handle = data?.product?.handle || null;
          if (handle) {
            out[pid] = handle;
            __productHandleCache.set(pid, { at: Date.now(), value: handle });
          }
        } catch (err) {
          console.warn('getProductHandlesById (fallback):', pid, err?.response?.data || err.message);
        }
      }));
    }
  }
  return out;
}




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
function toGid(kind, id) {
  return `gid://shopify/${kind}/${String(id)}`;
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
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(204).end();

    const limit = Math.min(parseInt(req.query.first || '25', 10), 50);
    const scope = String(req.query.scope || '').toLowerCase();

    // 🔹 NYTT: ultrasnabb Redis-snapshot (<=100 ms)
    try {
      const cidRaw = String(loggedInCustomerId || '');
      const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;

      const preferMs = (String(req.query.snapshot || '') === '1') ? 300 : 100; // valfritt: snapshot=1 tillåter lite längre väntan
      const snap = await Promise.race([
        tryReadOrdersFromRedis(cidNum, limit),
        new Promise(r => setTimeout(() => r(null), preferMs)),
      ]);

      if (Array.isArray(snap) && snap.length) {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('x-source', 'redis-snapshot');
        return res.json({ orders: snap });
      }
    } catch (_) {
    }



    // ===== NYTT: ADMIN-LÄGE (scope=all) – hämta ALLA ordrar och filtrera bort levererade =====
if (scope === 'all') {
  const ok = await isAdminCustomer(loggedInCustomerId);
  if (!ok) return res.status(403).json({ error: 'Forbidden' });

  // Först: GraphQL
  try {
    const query = `
      query OrdersWithMetafield($first: Int!, $q: String!, $ns: String!, $key: String!) {
        orders(first: $first, query: $q, sortKey: CREATED_AT, reverse: true) {
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
    // Viktigt: skicka in 'q' – t.ex. status:any
    const gqlVars = {
      first: limit,
      q: 'status:any',
      ns: ORDER_META_NAMESPACE,
      key: ORDER_META_KEY
    };
    const data = await shopifyGraphQL(query, gqlVars);
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
          // ... efter vi hämtat orders med REST:
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
    fulfillmentStatus: o.fulfillment_status || null,
    displayFulfillmentStatus: null
  });

  await sleep(650); // samma paus här
}


          const filtered = out.filter(o => !isDeliveredOrderShape(o));

          res.setHeader('Cache-Control', 'no-store');
          return res.json({ orders: filtered, admin: true });
        } catch (restErr) {
          console.error('Admin REST fallback error:', restErr?.response?.data || restErr.message);
          setCorsOnError(req, res);
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
          fulfillmentStatus
          displayFulfillmentStatus
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
  metafield: e.node.metafield ? e.node.metafield.value : null,
  fulfillmentStatus: e.node.fulfillmentStatus || null,
  displayFulfillmentStatus: null
}));
// ---- NYTT: seeda Redis med färska order-sammanfattningar ----
try {
   if (WRITE_ORDERS_TO_REDIS) {
    const cidRaw = String(loggedInCustomerId || '');
    const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;
    await seedOrdersToRedis(cidNum, out);
  }
} catch {}
// ---- /NYTT ----

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
  metafield: mf ? mf.value : null,
  fulfillmentStatus: o.fulfillment_status || null,
  displayFulfillmentStatus: null
});
      }

      res.setHeader('Cache-Control', 'no-store');
      return res.json({ orders: out });
    } catch (err) {
      console.error('proxy/orders-meta error:', err?.response?.data || err.message);
      setCorsOnError(req, res);
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
      setCorsOnError(req, res);
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
      setCorsOnError(req, res);
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
// Bakåtkompatibilitet: acceptera tokens utan 'kind' (äldre länkar), men kräva kind:'proof' om den finns
if (!payload || (payload.kind && payload.kind !== 'proof')) {
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
    setCorsOnError(req, res);
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
    try { await cacheOrderProjects(orderId, next); } catch {}

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

// ===== RENAME: byt värdet på line item property "Tryckfil" via App Proxy =====
app.post('/proxy/orders-meta/rename', async (req, res) => {
  try {
    // 1) Säkerhet: App Proxy-signatur + inloggad kund
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) return res.status(401).json({ error: 'not_logged_in' });

    // 2) Body-validering
    const orderId   = String(req.body?.orderId   || '').trim();
    const lineItemId= String(req.body?.lineItemId|| '').trim();
    const oldName   = String(req.body?.oldName   ?? '').trim();
    const newName   = String(req.body?.newName   ?? '').trim();
    if (!orderId || !lineItemId || !newName) {
      return res.status(400).json({ error: 'missing_params' });
    }

    // 3) Ägarcheck: kunden måste äga ordern
    const { data } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const order = data?.order;
    if (!order) return res.status(404).json({ error: 'order_not_found' });

    const cidRaw = String(loggedInCustomerId);
    const cidNum = cidRaw.startsWith('gid://') ? cidRaw.split('/').pop() : cidRaw;
    const ownerId = String(order?.customer?.id || '');
    if (!ownerId.endsWith(cidNum)) {
      return res.status(403).json({ error: 'forbidden_not_owner' });
    }

    // 4) Läs & uppdatera projekten i SAMMA metafält (order-created)
    const { metafieldId, projects } = await readOrderProjects(orderId);
    if (!metafieldId) return res.status(404).json({ error: 'metafield_not_found' });

    const idx = (projects || []).findIndex(p => String(p.lineItemId) === String(lineItemId));
    if (idx < 0) return res.status(404).json({ error: 'line_item_not_found' });

    const proj = projects[idx] || {};
    const props = Array.isArray(proj.properties) ? proj.properties.slice() : [];

    let touched = false;
    const nextProps = props.map(pr => {
      if (!pr || typeof pr !== 'object') return pr;
      const nm = String(pr.name || '').toLowerCase();
      if (nm === 'tryckfil') {
        // Byt bara värdet
        if (String(pr.value || '') !== newName) {
          touched = true;
          return { ...pr, value: newName };
        } else {
          touched = true; // redan samma namn → idempotent OK
          return pr;
        }
      }
      return pr;
    });

    if (!touched) {
      // Hittade ingen "Tryckfil"-property i projektet
      return res.status(404).json({ error: 'property_not_found' });
    }

    // Bevara övriga fält oförändrade; uppdatera ev. fallback "tryckfil" om det fanns
    const nextProj = {
      ...proj,
      properties: nextProps,
      ...(Object.prototype.hasOwnProperty.call(proj, 'tryckfil') ? { tryckfil: newName } : {})
    };
    const nextProjects = projects.slice();
    nextProjects[idx] = nextProj;

    await writeOrderProjects(metafieldId, nextProjects);
try { await cacheOrderProjects(orderId, nextProjects); } catch {}
    // ---- NYTT: uppdatera order-sammanfattning i Redis ----
try {
  const metaStr = JSON.stringify(nextProjects || []);
  await touchOrderSummary(cidNum, Number(orderId), {
    processedAt: new Date().toISOString(),
    metafield: metaStr
  });
} catch {}

    // 5) Activity-logg (kund agerade)
    try {
      const cust = await getCustomerNameByOrder(orderId);
      await appendActivity(orderId, [{
        ts: new Date().toISOString(),
        actor: { type: 'customer', name: cust.name, id: cust.id },
        action: 'file.renamed',
        order_id: Number(orderId),
        line_item_id: Number(lineItemId),
        product_title: proj.productTitle || '',
        project_id: oldName || undefined,
        data: { from: oldName || null, to: newName },
        correlation_id: `file.renamed:${orderId}:${lineItemId}:${crypto.createHash('sha256').update(`${oldName}→${newName}`).digest('hex')}`
      }]);
    } catch (e) {
      console.warn('/proxy/orders-meta/rename → appendActivity misslyckades:', e?.response?.data || e.message);
    }

    // 6) Invalidera 20s micro-cachen för den här kunden (så /apps/orders-meta reflekterar bytet)
    try {
      const prefix = `${cidNum}:`;
      for (const key of ordersMetaCache.keys()) {
        if (key.startsWith(prefix)) ordersMetaCache.delete(key);
      }
    } catch {}

    return res.json({ ok: true });
  } catch (err) {
    console.error('POST /proxy/orders-meta/rename:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'internal' });
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
app.post('/proxy/order/cancel', forward('/proxy/orders-meta/order/cancel'));

/* ====== END SIMPLE CANCEL VIA APP PROXY ====== */

// ===== ADMIN: Backfill för alla kunder (skapa referlink om saknas) =====
app.post('/admin/referlink/backfill', async (req, res) => {
  try {
    if (!BACKFILL_SECRET || req.get('x-backfill-secret') !== BACKFILL_SECRET) {
      return res.status(403).json({ error: 'forbidden' });
    }

    let url = `https://${SHOP}/admin/api/2025-07/customers.json?limit=250&fields=id`;
    let created = 0, skipped = 0, errors = 0;

    while (url) {
      const r = await axios.get(url, { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } });
      const customers = r.data.customers || [];

      for (const c of customers) {
        try {
          const customerId = c.id;
          let { metafieldId, value } = await readCustomerReferlink(customerId);
          if (value && value.slug) { skipped++; continue; }
          const slug = makeSlugFromCustomerId(customerId);
          value = referlinkJsonFor(slug);
          await writeCustomerReferlink(customerId, metafieldId, value);
          await ensureRootRedirectToHome(slug);
          created++;
        } catch (e) {
          errors++;
          console.warn('backfill customer failed:', e?.response?.data || e.message);
        }
      }

      // Paginering via Link-header
      const link = r.headers['link'] || r.headers['Link'];
      const next = (link || '').split(',').find(p => p.includes('rel="next"'));
      if (next) {
        const m = next.match(/<([^>]+)>/);
        url = m ? m[1] : null;
      } else {
        url = null;
      }
    }

    return res.json({ ok: true, created, skipped, errors });
  } catch (e) {
    console.error('POST /admin/referlink/backfill:', e?.response?.data || e.message);
    return res.status(500).json({ error: 'internal' });
  }
});
// ===== ADMIN: Backfill artworkToken in order-created (säker, idempotent) =====
// Använd samma BACKFILL_SECRET-header som referlink-backfill.
// Två lägen:
//  - Enstaka order: POST /admin/order-created/backfill-artwork-token { orderId }
//  - Bulk (frivilligt): POST /admin/order-created/backfill-artwork-token?since=YYYY-MM-DD  (paginera status:any)
app.post('/admin/order-created/backfill-artwork-token', async (req, res) => {
  try {
    if (!BACKFILL_SECRET || req.get('x-backfill-secret') !== BACKFILL_SECRET) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const since = (req.query.since || '').trim(); // valfritt filter för bulk
    const singleOrderId = req.body && req.body.orderId ? String(req.body.orderId).trim() : '';

    // Hjälpare: säkerställ token per projekt i en order
    async function ensureTokensOnOrder(orderId) {
  const { metafieldId, projects } = await readOrderProjects(orderId);
  if (!metafieldId || !Array.isArray(projects) || projects.length === 0) {
    return { orderId, updated: 0, skipped: true };
  }

  let changed = 0;
  const next = [];
  for (const p of (projects || [])) {
    if (p && !p.artworkToken && p.lineItemId != null) {
      const { token, tid } = generateArtworkToken(orderId, p.lineItemId);
      // registrera i Redis för pass-by-reference
      await registerTokenInRedis(token, {
        kind: 'artwork',
        orderId: Number(orderId),
        lineItemId: Number(p.lineItemId),
        iat: Date.now(),
        tid
      });
      changed++;
      next.push({ ...p, artworkToken: token });
    } else {
      next.push(p);
    }
  }

  if (changed > 0) {
    await writeOrderProjects(metafieldId, next);
  }
  return { orderId, updated: changed, skipped: false };
}

// ...

if (singleOrderId) {
  const out = await ensureTokensOnOrder(singleOrderId);
  return res.json({ ok: true, mode: 'single', out });
}


    // Bulk: hämta ordrar via REST (status:any), ev. filtrera på created_at>=since
    let url = `https://${SHOP}/admin/api/2025-07/orders.json?status=any&limit=250&fields=id,created_at`;
    if (since) url += `&created_at_min=${encodeURIComponent(since)}`;

    const results = { ok: true, mode: 'bulk', processed: 0, updated: 0, errors: 0 };
    while (url) {
      const r = await axios.get(url, { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } });
      const orders = r.data.orders || [];
      for (const o of orders) {
        try {
          const r = await ensureTokensOnOrder(o.id);
          results.processed++;
          results.updated += (r.updated || 0);
          // Liten paus för att vara snäll mot API:t
          await sleep(150);
        } catch (e) {
          results.errors++;
          console.warn('backfill artworkToken failed:', o.id, e?.response?.data || e.message);
        }
      }

      // Paginering via Link-header
      const link = r.headers['link'] || r.headers['Link'];
      const next = (link || '').split(',').find(p => p.includes('rel="next"'));
      if (next) {
        const m = next.match(/<([^>]+)>/);
        url = m ? m[1] : null;
      } else {
        url = null;
      }
    }

    return res.json(results);
  } catch (e) {
    console.error('POST /admin/order-created/backfill-artwork-token:', e?.response?.data || e.message);
    return res.status(500).json({ error: 'internal' });
  }
});

// ===== NY ROUTE (DIN) – placerad strax före globala felhanteraren =====
app.get('/din/health/ping', (req, res) => {
  // fullständigt frikopplad, påverkar inget
  res.json({ pong: true, at: new Date().toISOString() });
});
// ===== SLUT NY ROUTE (DIN) =====
// ===== Pressify Carrier Service: DATUM I FRAKTALTERNATIV (utan Plus) =====
// Denna kod lägger till EN rate-callback och EN register-endpoint.
// Den påverkar INGET annat i din app. Alltid två rater, alltid ett svar (failsafe).

const PRESSIFY_CARRIER_ROUTE = '/carrier/pressify/rates';
const PRESSIFY_REGISTER_ROUTE = '/carrier/pressify/register';

const PRESSIFY_CARRIER_NAME   = 'Pressify Delivery Dates'; // visas i Admin
const PRESSIFY_CURRENCY       = 'SEK';
const PRESSIFY_EXPRESS_ORE    = 24900; // 249 kr i öre
const PRESSIFY_STANDARD_ORE   = 0;     // 0 kr
const PRESSIFY_DEFAULT_STD    = { minDays: 2, maxDays: 4 };
const PRESSIFY_DEFAULT_EXP    = { minDays: 0, maxDays: 1 };
const PRESSIFY_MS_PER_DAY     = 86_400_000;

function pressifyFmtDateUTC(d) {
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const HH = String(d.getUTCHours()).padStart(2, '0');
  const MM = String(d.getUTCMinutes()).padStart(2, '0');
  const SS = String(d.getUTCSeconds()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd} ${HH}:${MM}:${SS} +0000`;
}
function pressifyAddBusinessDays(startDate, days) {
  // Räkna i UTC-noon för att undvika DST-strul, men vi formatterar i sv-SE/Stockholm sen
  const d = new Date(Date.UTC(
    startDate.getUTCFullYear(),
    startDate.getUTCMonth(),
    startDate.getUTCDate(),
    12, 0, 0
  ));
  if (!Number.isInteger(days) || days <= 0) return d;
  let remaining = days;
  while (remaining > 0) {
    d.setUTCDate(d.getUTCDate() + 1);
    const dow = d.getUTCDay(); // 0=Sun, 6=Sat
    if (dow !== 0 && dow !== 6) remaining--;
  }
  return d;
}

function pressifySvShortRange(from, to) {
  const fmt = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Europe/Stockholm',
    weekday: 'short',
    day: 'numeric',
    month: 'short'
  });
  const clean = s => String(s).replace(/\./g, ''); // "sep." -> "sep"
  const a = clean(fmt.format(from));
  const b = clean(fmt.format(to));
  return (a === b) ? a : `${a} - ${b}`;
}

function pressifyMergeWindow(agg, next) {
  if (!next) return agg;
  const ok = v => Number.isInteger(v) && v >= 0;
  let nmin = ok(next.minDays) ? next.minDays : null;
  let nmax = ok(next.maxDays) ? next.maxDays : null;
  if (nmin === null && nmax === null) return agg;
  if (nmin === null) nmin = nmax;
  if (nmax === null) nmax = nmin;
  if (nmin > nmax) [nmin, nmax] = [nmax, nmin];

  if (!agg) return { minDays: nmin, maxDays: nmax };
  // Viktigt: låt långsammaste rad styra start → max av minDays
  return {
    minDays: Math.max(agg.minDays, nmin),
    maxDays: Math.max(agg.maxDays, nmax)
  };
}



async function pressifyFetchShippingMeta(productId) {
  try {
    const url = `https://${SHOP}/admin/api/2025-07/products/${productId}/metafields.json`;
    const resp = await axios.get(url, { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } });
    const mfs = resp.data?.metafields || [];
    const mf = mfs.find(m => m.namespace === 'custom' && m.key === 'shipping');
    if (!mf?.value) return null;
    try { return JSON.parse(mf.value); } catch { return null; }
  } catch (e) {
    console.error('pressifyFetchShippingMeta error', productId, e?.response?.data || e.message);
    return null;
  }
}
const __variantToProductCache = new Map();

async function pressifyResolveProductIdsFromItems(items) {
  const pids = new Set();
  const toLookup = new Set(); // variant→produkt-uppslag via Admin

  for (const it of Array.isArray(items) ? items : []) {
    if (it?.requires_shipping === false) continue;

    // 2a) Försök läsa PRODUCT-ID direkt (vanligt fält eller dolt property)
    const pidRaw =
      it?.product_id ??
      pickIdFromItemProps(it, ['_product_id','product_id','productId']);
    const pid = toPlainId(pidRaw);
    if (pid) {
      pids.add(pid);
      continue; // klart för denna rad
    }

    // 2b) Annars: ta VARIANT-ID (vanligt fält eller dolt property) och slå upp product_id
    const vidRaw =
      it?.variant_id ??
      pickIdFromItemProps(it, ['_variant_id','variant_id','variantId']);
    const vid = toPlainId(vidRaw);
    if (!vid) continue;

    if (__variantToProductCache.has(vid)) {
      pids.add(__variantToProductCache.get(vid));
    } else {
      toLookup.add(vid);
    }
  }

  if (toLookup.size > 0) {
    const headers = { 'X-Shopify-Access-Token': ACCESS_TOKEN };
    await Promise.all([...toLookup].map(async (vid) => {
      try {
        const { data } = await axios.get(
          `https://${SHOP}/admin/api/2025-07/variants/${vid}.json`,
          { headers }
        );
        const pid = toPlainId(data?.variant?.product_id);
        if (pid) {
          __variantToProductCache.set(vid, pid);
          pids.add(pid);
        }
      } catch (e) {
        console.error('variant→product lookup fail', vid, e?.response?.data || e.message);
      }
    }));
  }

  return [...pids];
}

function pickIdFromItemProps(it, keys = []) {
  try {
    const props = Array.isArray(it?.properties) ? it.properties
                  : (it?.properties ? propsObjToArray(it.properties) : []);
    const map = new Map((props || []).map(p => [String(p?.name || '').toLowerCase(), String(p?.value ?? '').trim()]));
    for (const k of keys) {
      const v = map.get(String(k).toLowerCase());
      if (v) return v;
    }
  } catch {}
  return null;
}
function toPlainId(v){
  const s = String(v ?? '').trim();
  if (!s) return '';
  // stöd både rena siffror och GID:er som "gid://shopify/Product/123456789"
  const m = s.match(/(\d+)\s*$/);
  return m ? m[1] : '';
}

// Batch: hämta custom.shipping för en lista av products via Admin GraphQL
async function pressifyFetchShippingMetaBatch(productIds = []) {
  const ids = [...new Set((productIds || []).filter(Boolean).map(String))];
  if (ids.length === 0) return [];

  const gids = ids.map(id => `gid://shopify/Product/${id}`);
  const query = `
    query ShippingMeta($ids:[ID!]!) {
      nodes(ids:$ids) {
        ... on Product {
          id
          metafield(namespace:"custom", key:"shipping") { value }
        }
      }
    }`;
  try {
    const data = await shopifyGraphQL(query, { ids: gids });
    const nodes = data?.data?.nodes || [];

    // Bygg en map productId -> parsed JSON (eller null)
    const byId = Object.create(null);
    for (const n of nodes) {
      const pid = (n?.id || '').split('/').pop();
      let cfg = null;
      if (n?.metafield?.value) {
        try { cfg = JSON.parse(n.metafield.value); } catch { cfg = null; }
      }
      byId[pid] = cfg;
    }
    // Returnera i samma ordning som inkom
    return ids.map(id => byId[id] ?? null);
  } catch (e) {
    console.error('pressifyFetchShippingMetaBatch error:', e?.response?.data || e.message);
    return ids.map(() => null);
  }
}


// ====== RATE CALLBACK – Shopify kallar denna i checkout (även draft checkout)
// ====== RATE CALLBACK – Shopify kallar denna i checkout (även draft checkout)
app.post(PRESSIFY_CARRIER_ROUTE, async (req, res) => {
  try {
    const rateReq = req.body?.rate;
    const items = Array.isArray(rateReq?.items) ? rateReq.items : [];

// Unika product_id som kräver frakt (fallback via variant → produkt)
// Samla fönster från VARIANT eller PRODUCT (variant har företräde)
const { std, exp, dbg } = await pressifyComputeWindowsFromCart(items);
console.log('[pressify rates] dbg', JSON.stringify(dbg));

// Fallback endast om ingen rad hade giltiga metafält
let useStd = std || null;
let useExp = exp || null;
if (!useStd) useStd = PRESSIFY_DEFAULT_STD;
if (!useExp) useExp = PRESSIFY_DEFAULT_EXP;

// Datum från "nu" i arbetsdagar (mån–fre) enligt metafälten
const now = new Date();
const stdFrom = pressifyAddBusinessDays(now, useStd.minDays);
const stdTo   = pressifyAddBusinessDays(now, useStd.maxDays);
const expFrom = pressifyAddBusinessDays(now, useExp.minDays);
const expTo   = pressifyAddBusinessDays(now, useExp.maxDays);


    // Beskrivningsrad i kassan (ex: "tis 23 sep - ons 24 sep")
    const stdDesc = pressifySvShortRange(stdFrom, stdTo);
    const expDesc = pressifySvShortRange(expFrom, expTo);

    // Exakt två rater, titlar utan datum – och utan min/max_delivery_date
    const rates = [
      {
        service_name: 'Standard frakt',
        service_code: 'STANDARD',
        total_price: String(PRESSIFY_STANDARD_ORE),
        currency: PRESSIFY_CURRENCY,
        description: stdDesc,
        phone_required: false
      },
      {
        service_name: 'Expressfrakt',
        service_code: 'EXPRESS',
        total_price: String(PRESSIFY_EXPRESS_ORE),
        currency: PRESSIFY_CURRENCY,
        description: expDesc,
        phone_required: false
      }
    ];

    return res.json({ rates });
  } catch (e) {
    // Failsafe: defaults i arbetsdagar
    try {
      const now = new Date();
      const dfStdFrom = pressifyAddBusinessDays(now, PRESSIFY_DEFAULT_STD.minDays);
      const dfStdTo   = pressifyAddBusinessDays(now, PRESSIFY_DEFAULT_STD.maxDays);
      const dfExpFrom = pressifyAddBusinessDays(now, PRESSIFY_DEFAULT_EXP.minDays);
      const dfExpTo   = pressifyAddBusinessDays(now, PRESSIFY_DEFAULT_EXP.maxDays);

      const stdDesc = pressifySvShortRange(dfStdFrom, dfStdTo);
      const expDesc = pressifySvShortRange(dfExpFrom, dfExpTo);

      return res.json({
        rates: [
          { service_name: 'Standard frakt', service_code: 'STANDARD', total_price: String(PRESSIFY_STANDARD_ORE), currency: PRESSIFY_CURRENCY, description: stdDesc, phone_required: false },
          { service_name: 'Expressfrakt',  service_code: 'EXPRESS',  total_price: String(PRESSIFY_EXPRESS_ORE), currency: PRESSIFY_CURRENCY, description: expDesc, phone_required: false }
        ]
      });
    } catch {
      return res.json({ rates: [] });
    }
  }
});


// ===== REGISTER (engångs) – skapar/uppdaterar CarrierService i butiken
// Anropa:  POST https://DIN-HOST/carrier/pressify/register?token=SHOPIFY_WEBHOOK_SECRET
app.post(PRESSIFY_REGISTER_ROUTE, async (req, res) => {
  try {
    // 1) Enkel auth så bara du kan trigga registret
    if (!req.query || req.query.token !== SHOPIFY_WEBHOOK_SECRET) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // 2) Bygg callback URL till din rate-endpoint
    const callbackUrl = `${(HOST || '').replace(/\/$/, '')}${PRESSIFY_CARRIER_ROUTE}`;
    const headers = {
      'X-Shopify-Access-Token': ACCESS_TOKEN,
      'Content-Type': 'application/json'
    };

    // 3) Hämta ev. befintlig CarrierService
    const listUrl = `https://${SHOP}/admin/api/2025-07/carrier_services.json`;
    const { data: listData } = await axios.get(listUrl, { headers });
    const existing = (listData?.carrier_services || []).find(cs => cs.name === PRESSIFY_CARRIER_NAME);

    // 4) Payload – håll den minimal och stabil
    const payload = {
      carrier_service: {
        name: PRESSIFY_CARRIER_NAME,
        callback_url: callbackUrl,
        active: true,
        service_discovery: true,     // låt Shopify fråga oss dynamiskt
        carrier_service_type: 'api'  // viktigt för externa carriers
      }
    };

    // 5) Skapa eller uppdatera
    if (existing) {
      const { data: updData } = await axios.put(
        `https://${SHOP}/admin/api/2025-07/carrier_services/${existing.id}.json`,
        payload,
        { headers }
      );
      return res.json({
        ok: true,
        mode: 'updated',
        id: updData?.carrier_service?.id || existing.id,
        callback_url: updData?.carrier_service?.callback_url || callbackUrl
      });
    } else {
      const { data: crtData } = await axios.post(
        `https://${SHOP}/admin/api/2025-07/carrier_services.json`,
        payload,
        { headers }
      );
      return res.json({
        ok: true,
        mode: 'created',
        id: crtData?.carrier_service?.id,
        callback_url: crtData?.carrier_service?.callback_url || callbackUrl
      });
    }
  } catch (err) {
    console.error('PRESSIFY_REGISTER_ROUTE error:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Internal error' });
  }
});



async function pressifyComputeWindowsFromCart(items = []) {
  const variants = Array.from(new Set(
    (items || [])
      .map(it => it?.variant_id ?? pickIdFromItemProps(it, ['_variant_id','variant_id','variantId']))
      .filter(Boolean)
      .map(v => toPlainId(v))
  ));

  const products = await pressifyResolveProductIdsFromItems(items);

  if (variants.length === 0 && products.length === 0) {
    return { std: null, exp: null, dbg: { reason: 'no_ids' } };
  }

  const ids = [
    ...products.map(id => `gid://shopify/Product/${id}`),
    ...variants.map(id => `gid://shopify/ProductVariant/${id}`)
  ];

  const query = `
    query ShipMeta($ids:[ID!]!) {
      nodes(ids:$ids) {
        id
        ... on Product {
          metafield(namespace:"custom", key:"shipping"){ value }
        }
        ... on ProductVariant {
          metafield(namespace:"custom", key:"shipping"){ value }
          product { id }
        }
      }
    }`;

  const data = await shopifyGraphQL(query, { ids });
  const nodes = data?.data?.nodes || [];

  const pWin = Object.create(null); // productId -> window JSON
  const vWin = Object.create(null); // variantId -> window JSON
  const v2p  = Object.create(null); // variantId -> productId

  for (const n of nodes) {
    const gid = String(n?.id || '');
    const parts = gid.split('/');
    const type = parts[parts.length - 2] || ''; // "Product" | "ProductVariant"
    const id   = parts[parts.length - 1] || ''; // "12345"

    let cfg = null;
    try { cfg = n?.metafield?.value ? JSON.parse(n.metafield.value) : null; } catch {}

    if (type === 'Product' && id) {
      pWin[id] = cfg;
    } else if (type === 'ProductVariant' && id) {
      vWin[id] = cfg;
      const pGid = n?.product?.id;
      if (pGid) {
        const pid = pGid.split('/').pop();
        if (pid) v2p[id] = pid;
      }
    }
  }

  const toInt = (v) => {
    const n = Number(String(v ?? '').replace(',', '.'));
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
  };
  const coerce = (win) => {
    if (!win || typeof win !== 'object') return null;
    // stöder minDays/maxDays och alias min/max/min_days/max_days samt "3" (sträng)
    let min = toInt(win.minDays ?? win.min ?? win.min_days);
    let max = toInt(win.maxDays ?? win.max ?? win.max_days);
    if (min == null && typeof win === 'string') min = toInt(win);
    if (max == null && typeof win === 'string') max = toInt(win);
    if (min == null || max == null) return null;
    return { minDays: min, maxDays: max };
  };

  // Läs variant först, annars fall tillbaka till produkt
  const windowsPerItem = (items || []).map(it => {
    const vid = toPlainId(it?.variant_id ?? pickIdFromItemProps(it, ['_variant_id','variant_id','variantId']));
    const pid = toPlainId(it?.product_id ?? pickIdFromItemProps(it, ['_product_id','product_id','productId']) ?? (vid ? v2p[vid] : null));
    const vCfg = vid && vWin[vid] ? vWin[vid] : null;
    const pCfg = pid && pWin[pid] ? pWin[pid] : null;
    const src  = vCfg || pCfg || null;

    return {
      std: coerce(src?.standard || src?.std || null),
      exp: coerce(src?.express  || src?.exp || null)
    };
  });

  // Merga över alla rader: min av min, max av max
  const merge = (arr, key) => {
    let min = null, max = null;
    for (const it of arr) {
      const w = it[key];
      if (!w) continue;
      if (min == null || w.minDays < min) min = w.minDays;
      if (max == null || w.maxDays > max) max = w.maxDays;
    }
    return (min != null && max != null) ? { minDays: min, maxDays: max } : null;
  };

  const std = merge(windowsPerItem, 'std');
  const exp = merge(windowsPerItem, 'exp');

  return { std, exp, dbg: { variants, products, haveStd: !!std, haveExp: !!exp } };
}


// Global felhanterare – sist i filen (före app.listen), men vi lägger en TIDIG också:
app.use((err, req, res, next) => {
  try { setCorsOnError(req, res); } catch {}
  const status = err?.status || 500;
  res.status(status).json({ error: err?.message || 'Internal error' });
});

// Starta servern
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Kör på port ${PORT}`);
});
