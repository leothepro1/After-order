

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
const { Pool } = require('pg'); // 🔌 Postgres-klient

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


const SHOP = process.env.SHOP;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET; 

// 🔽 Nya env för Partner-app & Proxy
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
// --- Postmark config (env) ---
const POSTMARK_SERVER_TOKEN = process.env.POSTMARK_SERVER_TOKEN || process.env.POSTMARK_TOKEN || '';
const POSTMARK_FROM = process.env.POSTMARK_FROM || process.env.POSTMARK_SENDER || 'info@pressify.se';
const POSTMARK_STREAM = process.env.POSTMARK_STREAM || 'outbound';
const POSTMARK_TEMPLATE_ALIAS_PROOF_UPLOADED =
  process.env.POSTMARK_TEMPLATE_ALIAS_PROOF_UPLOADED || process.env.POSTMARK_TEMPLATE_PROOF_READY || 'proof-uploaded';
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET; // används för App Proxy + OAuth-verifiering
const SCOPES = process.env.SCOPES || 'read_orders,read_customers,write_customers,read_metafields,write_app_proxy';
const HOST = (process.env.HOST || 'https://after-order-1.onrender.com').replace(/\/$/, '');
const ORDER_META_NAMESPACE = process.env.ORDER_META_NAMESPACE || 'order-created';
const ORDER_META_KEY = process.env.ORDER_META_KEY || 'order-created';

// === Postgres (orders_snapshot) =========================================
const DATABASE_URL = process.env.DATABASE_URL || '';
const PG_POOL_MAX = parseInt(process.env.PG_POOL_MAX || '10', 10);

let pgPool = null;

if (!DATABASE_URL) {
  console.warn('[pg] DATABASE_URL saknas – Postgres är inaktiverat');
} else {
  pgPool = new Pool({
    connectionString: DATABASE_URL,
    max: PG_POOL_MAX,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    // Render Postgres brukar kräva SSL; du kan styra med PG_SSL=false om du vill stänga av
    ssl: process.env.PG_SSL === 'false' ? false : { rejectUnauthorized: false }
  });

  pgPool.on('error', (err) => {
    console.error('[pg] Ohanterat pool-fel:', err);
  });
}

// Generell helper för SELECT/INSERT/UPDATE mot Postgres
async function pgQuery(text, params) {
  if (!pgPool) {
    throw new Error('pgPool inte initialiserad – saknar DATABASE_URL');
  }
  const client = await pgPool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

// Tabellnamn för våra snapshots
const ORDERS_SNAPSHOT_TABLE = 'orders_snapshot';

// Se till att tabellen + index finns vid uppstart
async function ensureOrdersSnapshotTable() {
  if (!pgPool) {
    console.warn('[orders_snapshot] Hoppar över init – pgPool saknas');
    return;
  }

  const ddl = `
    CREATE TABLE IF NOT EXISTS ${ORDERS_SNAPSHOT_TABLE} (
      order_id       BIGINT PRIMARY KEY,
      customer_id    BIGINT,
      customer_email TEXT,
      created_at     TIMESTAMPTZ NOT NULL,
      updated_at     TIMESTAMPTZ NOT NULL,
      metafield_raw  TEXT NOT NULL,
      metafield_json JSONB NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_orders_snapshot_customer_id
      ON ${ORDERS_SNAPSHOT_TABLE}(customer_id);

    CREATE INDEX IF NOT EXISTS idx_orders_snapshot_customer_email
      ON ${ORDERS_SNAPSHOT_TABLE}(lower(customer_email));

    CREATE INDEX IF NOT EXISTS idx_orders_snapshot_created_at
      ON ${ORDERS_SNAPSHOT_TABLE}(created_at DESC);
  `;

  await pgQuery(ddl);
}

// Styr om backfill ska köras automatiskt när servern startar
// (du kan sätta ORDERS_SNAPSHOT_BACKFILL_ON_BOOT=false i Render om du vill pausa den)
const ORDERS_SNAPSHOT_BACKFILL_ON_BOOT =
  String(process.env.ORDERS_SNAPSHOT_BACKFILL_ON_BOOT || 'true') === 'true';

let __ordersSnapshotBackfillStarted = false;

// Backfill: hämta ALLA ordrar från Shopify, läs order-metafältet (ORDER_META_NAMESPACE/ORDER_META_KEY)
// och spegla till Postgres via upsertOrderSnapshotFromMetafield.
// Metafältets JSON (value) används som exakt sanning – vi rör inte strukturen, vi speglar den bara.
async function backfillOrdersSnapshotAllOrders() {
  if (!pgPool) {
    console.warn('[orders_snapshot] backfill: pgPool saknas, hoppar över');
    return;
  }
  if (!SHOP || !ACCESS_TOKEN) {
    console.warn('[orders_snapshot] backfill: SHOP/ACCESS_TOKEN saknas, hoppar över');
    return;
  }

  console.log('[orders_snapshot] backfill: startar (boot)…');

  let url = `https://${SHOP}/admin/api/2025-07/orders.json?status=any&limit=100`;
  let processed = 0;
  let skipped = 0;
  let errors = 0;

  while (url) {
    let resp;
    try {
      resp = await axios.get(url, { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } });
    } catch (e) {
      console.error('[orders_snapshot] backfill: kunde inte hämta orders:', e?.response?.data || e.message);
      break;
    }

    const orders = resp.data?.orders || [];
    if (!orders.length) break;

    for (const order of orders) {
      try {
        const orderId = order.id;

        // Läs metafälten för just den här ordern
        const mfResp = await axios.get(
          `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );

        const metafields = mfResp.data?.metafields || [];
        const mf = metafields.find(
          (m) => m.namespace === ORDER_META_NAMESPACE && m.key === ORDER_META_KEY
        );

        // Om ordern inte har ditt order-metafält hoppar vi över den
        if (!mf || !mf.value) {
          skipped++;
          continue;
        }

        // Viktigt: mf.value är EXAKT samma JSON-sträng som frontend redan använder.
        // upsertOrderSnapshotFromMetafield tar hand om att spara både raw-string + JSONB i Postgres.
        await upsertOrderSnapshotFromMetafield(order, mf.value);
        processed++;
      } catch (e) {
        errors++;
        console.warn(
          '[orders_snapshot] backfill: misslyckades för order',
          (order && order.id) || '?',
          e?.response?.data || e.message
        );
      }
    }

    // Paginering via Link-header (Shopify REST)
    const link = resp.headers['link'] || resp.headers['Link'];
    if (!link) {
      url = null;
    } else {
      const nextPart = link
        .split(',')
        .map((p) => p.trim())
        .find((p) => p.includes('rel="next"'));
      if (!nextPart) {
        url = null;
      } else {
        const m = nextPart.match(/<([^>]+)>/);
        url = m ? m[1] : null;
      }
    }
  }

  console.log('[orders_snapshot] backfill: klar', {
    processed,
    skipped,
    errors
  });
}

// Start-funktion: triggas EN gång vid uppstart, efter att tabellen finns
function startOrdersSnapshotBackfillOnBoot() {
  if (!ORDERS_SNAPSHOT_BACKFILL_ON_BOOT) {
    console.log('[orders_snapshot] backfill: ORDERS_SNAPSHOT_BACKFILL_ON_BOOT=false – hoppar över vid boot');
    return;
  }
  if (__ordersSnapshotBackfillStarted) return;
  __ordersSnapshotBackfillStarted = true;

  // Kör i bakgrunden – blockar inte serverstarten
  backfillOrdersSnapshotAllOrders().catch((err) => {
    console.error('[orders_snapshot] backfill: oväntat fel:', err?.message || err);
  });
}

// Kör init/migration vid start, och därefter backfill (en gång)
ensureOrdersSnapshotTable()
  .then(() => {
    startOrdersSnapshotBackfillOnBoot();
  })
  .catch((err) => {
    console.error('[orders_snapshot] init-fel:', err?.message || err);
  });
// ========================================================================

// överst bland konfig:
// Publik butik (för delningslänkar 

// ===== Pressify: order-scope / team / rabatt på ordernivå =====
const PRESSIFY_NS = 'pressify';
const PRESSIFY_SCOPE_KEY = 'scope';
const PRESSIFY_TEAM_ID_KEY = 'team_id';
const PRESSIFY_TEAM_NAME_KEY = 'team_name';
const PRESSIFY_DISCOUNT_CODE_KEY = 'discount_code';
const PRESSIFY_DISCOUNT_SAVED_KEY = 'discount_saved';



/**
 * Normaliserar scope/team från payloadet som kommer från cart.js
 * scope: "personal" (default) eller "team"
 */
function pfExtractScopeFromPayload(body = {}) {
  const rawScope = String(body.scope || '').toLowerCase();
  const scope = rawScope === 'team' ? 'team' : 'personal';

  const teamId = scope === 'team' && body.teamId
    ? String(body.teamId)
    : null;

  const teamName = scope === 'team' && body.teamName
    ? String(body.teamName)
    : null;

  return { scope, teamId, teamName };
}

/**
 * Normaliserar ett teamId:
 *  - "gid://shopify/Customer/9582772027730" → "9582772027730"
 *  - "9582772027730"                        → "9582772027730"
 */
function pfNormalizeTeamId(raw) {
  if (raw == null) return null;
  try {
    const s = String(raw).trim();
    if (!s) return null;
    const parts = s.split('/');
    return parts[parts.length - 1] || null;
  } catch {
    return raw != null ? String(raw) : null;
  }
}

/**
 * Läser ORDER_META-JSON (array med projekt) och plockar ut:
 *  - _pf_scope ("personal" | "team")
 *  - _pf_team_id (som ren siffra)
 *  - _pf_team_name
 *
 * Default: { scope: "personal", teamId: null, teamName: null }
 */
function pfExtractScopeFromOrderProjects(projectsRaw) {
  let scope = 'personal';
  let teamId = null;
  let teamName = null;

  if (!projectsRaw) {
    return { scope, teamId, teamName };
  }

  let arr = [];
  try {
    if (typeof projectsRaw === 'string') {
      arr = JSON.parse(projectsRaw || '[]') || [];
    } else if (Array.isArray(projectsRaw)) {
      arr = projectsRaw;
    } else if (typeof projectsRaw === 'object') {
      // om någon gång ett objekt sparats direkt
      arr = [projectsRaw];
    }
  } catch {
    arr = [];
  }

  if (!Array.isArray(arr)) {
    return { scope, teamId, teamName };
  }

  for (const p of arr) {
    if (!p || typeof p !== 'object') continue;

    const rawScope = String(
      p._pf_scope ||
      p.scope ||
      p.pressify_scope ||
      ''
    ).toLowerCase();

    if (rawScope !== 'team') continue;

    const rawTeamId =
      p._pf_team_id ??
      p.teamId ??
      p.team_id ??
      p.pressify_team_id ??
      null;

    const rawTeamName =
      p._pf_team_name ??
      p.teamName ??
      p.team_name ??
      p.pressify_team_name ??
      null;

    scope = 'team';
    teamId = pfNormalizeTeamId(rawTeamId);
    teamName = rawTeamName != null ? String(rawTeamName) : null;
    break;
  }

  return { scope, teamId, teamName };
}

/**
 * Bygger:
 *  - note_attributes:
 *      pf_scope, pf_team_id, pf_team_name,
 *      discount_code, discount_saved
 *  - metafields (namespace "pressify"):
 *      scope, team_id, team_name, discount_code, discount_saved
 *
 *  OBS: ändrar inte priser – rabatten är redan inräknad i custom-priserna.
 */
function pfBuildDraftOrderMeta(baseDraft = {}, body = {}) {
  const { scope, teamId, teamName } = pfExtractScopeFromPayload(body);

  // Behåll ev. befintliga note_attributes / metafields
  const note_attributes = Array.isArray(baseDraft.note_attributes)
    ? baseDraft.note_attributes.slice()
    : [];

  const metafields = Array.isArray(baseDraft.metafields)
    ? baseDraft.metafields.slice()
    : [];

  // ---- NOTE ATTRIBUTES: scope + team ----
  if (scope === 'team') {
    note_attributes.push({ name: 'pf_scope', value: 'team' });
    if (teamId)   note_attributes.push({ name: 'pf_team_id', value: teamId });
    if (teamName) note_attributes.push({ name: 'pf_team_name', value: teamName });
  } else {
    // Personlig workspace
    note_attributes.push({ name: 'pf_scope', value: 'personal' });
  }

  // ---- NOTE ATTRIBUTES: rabatt-loggning ----
  if (body.discountCode) {
    note_attributes.push({
      name: 'discount_code',
      value: String(body.discountCode)
    });
  }

  if (Number.isFinite(Number(body.discountSaved))) {
    note_attributes.push({
      name: 'discount_saved',
      value: String(Number(body.discountSaved).toFixed(2))
    });
  }

  // ---- METAFIELDS: scope/team ----
  metafields.push({
    namespace: PRESSIFY_NS,
    key: PRESSIFY_SCOPE_KEY,
    type: 'single_line_text_field',
    value: scope
  });

  if (scope === 'team' && teamId) {
    metafields.push({
      namespace: PRESSIFY_NS,
      key: PRESSIFY_TEAM_ID_KEY,
      type: 'single_line_text_field',
      value: teamId
    });

    if (teamName) {
      metafields.push({
        namespace: PRESSIFY_NS,
        key: PRESSIFY_TEAM_NAME_KEY,
        type: 'single_line_text_field',
        value: teamName
      });
    }
  }

  // ---- METAFIELDS: rabatt-loggning ----
  if (body.discountCode) {
    metafields.push({
      namespace: PRESSIFY_NS,
      key: PRESSIFY_DISCOUNT_CODE_KEY,
      type: 'single_line_text_field',
      value: String(body.discountCode)
    });
  }

  if (Number.isFinite(Number(body.discountSaved))) {
    metafields.push({
      namespace: PRESSIFY_NS,
      key: PRESSIFY_DISCOUNT_SAVED_KEY,
      type: 'number_decimal',
      value: Number(body.discountSaved).toFixed(2)
    });
  }

  return { note_attributes, metafields };
}
// överst bland konfig:
// Publik butik (för delningslänkar till Shopify-sidan)
const STORE_BASE = (process.env.STORE_BASE || 'https://pressify.se').replace(/\/$/, '');

const PUBLIC_PROOF_PATH = process.env.PUBLIC_PROOF_PATH || '/pages/proof';
function adminHeaders(extra = {}) {
  return { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type':'application/json', ...extra };
}
async function adminGet(url, cfg={})   { return axios.get(url,   { ...cfg, headers: adminHeaders(cfg.headers) }); }
async function adminPost(url, data, cfg={}) { return axios.post(url, data, { ...cfg, headers: adminHeaders(cfg.headers) }); }
async function adminPut(url, data, cfg={})  { return axios.put(url, data,  { ...cfg, headers: adminHeaders(cfg.headers) }); }
async function adminDel(url, cfg={})   { return axios.delete(url, { ...cfg, headers: adminHeaders(cfg.headers) }); }

/* ===== REFERLINK CONFIG ===== */
const REFER_NS  = 'referlink';
const REFER_KEY = 'referlink';          // JSON-metafält: {{ customer.metafields.referlink.referlink }}
const SLUG_SECRET = process.env.SLUG_SECRET || 'CHANGE_ME_LONG_RANDOM';
const BACKFILL_SECRET = process.env.BACKFILL_SECRET || '';
const TEAMS_NS  = 'teams';
const TEAMS_KEY = 'teams';             
const B32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'; 
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

// --- Helper: skicka e-post via Postmark Template (axios) ---
async function postmarkSendEmail({ to, alias, model }) {
  if (!POSTMARK_SERVER_TOKEN || !to || !alias) return;
  try {
    await axios.post(
      'https://api.postmarkapp.com/email/withTemplate',
      {
        From: POSTMARK_FROM,
        To: to,
        TemplateAlias: alias,
        TemplateModel: model,
        MessageStream: POSTMARK_STREAM
      },
      {
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Postmark-Server-Token': POSTMARK_SERVER_TOKEN
        },
        timeout: 5000
      }
    );
  } catch (e) {
    console.warn('[postmarkSendEmail]', e?.response?.data || e.message);
  }
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

// Shopify Admin throttle – håll oss säkert under 2 rps per process
const ADMIN_MIN_DELAY_MS = 600;       // ca 1.6 rps i snitt
const ADMIN_JITTER_MS    = 50;        // ±50ms jitter för att sprida anrop
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

      const now     = Date.now();
      const elapsed = now - __adminLastAt;

      // Lägg på lite jitter så att vi inte ligger *exakt* på gränsen
      const jitter      = (Math.random() * 2 - 1) * ADMIN_JITTER_MS; // -50 .. +50 ms
      const targetDelay = ADMIN_MIN_DELAY_MS + jitter;
      const wait        = Math.max(0, targetDelay - elapsed);

      if (wait > 0) {
        await sleep(wait);
      }

      next.resolve();               // släpp igenom requesten
      __adminLastAt = Date.now();   // uppdatera senast-körning
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

// Response-interceptor: mjuk retry på 429 med Retry-After (max 1 retry)
axios.interceptors.response.use(
  (res) => res,
  async (error) => {
    const { response, config } = error || {};
    if (response && response.status === 429 && isShopAdminUrl(config)) {
      config.__retryCount = (config.__retryCount || 0) + 1;

      // Max 1 retry per request för att undvika retry-storm
      if (config.__retryCount <= 1) {
        const ra = parseFloat(response.headers?.['retry-after']) || 1;
        await sleep(ra * 1000);
        return axios(config);
      }

      console.warn(
        '[Shopify Admin] 429 trots retry, ger upp för att undvika rate-limit-storm.',
        { url: config.url, method: config.method, retryCount: config.__retryCount }
      );
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

// Hjälpare: hitta en befintlig kund i Shopify via e-postadress
async function findCustomerIdByEmail(email) {
  if (!isValidEmail(email)) return null;

  try {
    const q   = 'email:' + email.trim();
    const url = `https://${SHOP}/admin/api/2025-07/customers/search.json?query=${encodeURIComponent(q)}`;
    const { data } = await axios.get(url, {
      headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
    });

    const customers = Array.isArray(data?.customers) ? data.customers : [];
    if (!customers.length) return null;

    const first = customers[0];
    return first && first.id ? String(first.id) : null;
  } catch (err) {
    console.error('findCustomerIdByEmail error for', email, err?.response?.data || err.message);
    return null;
  }
}

// Hjälpare: se till att befintliga kunder får memberships[] uppdaterat när de bjuds in till ett team
async function syncTeamMembershipForExistingCustomers(teamCustomerId, teamName, emails) {
  if (!Array.isArray(emails) || !emails.length) return;

  const unique = Array.from(new Set(
    emails
      .map(e => String(e || '').trim().toLowerCase())
      .filter(isValidEmail)
  ));

  for (const email of unique) {
    const cid = await findCustomerIdByEmail(email);
    if (!cid) continue;

    const cidNum = String(cid).split('/').pop();

    try {
      const current = await readCustomerTeams(cidNum);
      let value = current?.value;

      if (!value || typeof value !== 'object') {
        value = {};
      }
      if (!Array.isArray(value.memberships)) {
        value.memberships = [];
      }

      const alreadyMember = value.memberships.some(
        (m) => Number(m.teamCustomerId) === Number(teamCustomerId)
      );
      if (alreadyMember) continue;

      const isFirst = value.memberships.length === 0;
      value.memberships.push({
        teamCustomerId: teamCustomerId,
        teamName: teamName || null,
        role: 'member',
        isDefault: isFirst
      });

      await writeCustomerTeams(cidNum, value);
    } catch (err) {
      console.error(
        'syncTeamMembershipForExistingCustomers error for',
        email,
        err?.response?.data || err.message
      );
    }
  }
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
const baseDraft = {
  ...incoming,
  line_items: cleanLines,
  ...(body.note ? { note: body.note } : {}),
  taxes_included: shopCfg.taxes_included,
  tags: incoming.tags ? String(incoming.tags) : 'pressify,draft-checkout'
};

// Pressify: scope/team + rabattkod i note_attributes + metafields
const { note_attributes, metafields } = pfBuildDraftOrderMeta(baseDraft, body);

payloadToShopify = {
  draft_order: {
    ...baseDraft,
    ...(note_attributes.length ? { note_attributes } : {}),
    ...(metafields.length ? { metafields } : {})
  }
};
}

  if (!payloadToShopify) {
      const items = Array.isArray(body.lineItems) ? body.lineItems :
                    Array.isArray(body.lines)     ? body.lines     : [];
      if (!items.length) {
        return res.status(400).json({ error: 'Inga rader i payload' });
      }

      const shopCfg = await getShopTaxConfig();
      const line_items = await buildCustomLinesFromGeneric(items);

      // Basdraft utan rabatt på raderna – litar på custom-priser från cart.js
      const baseDraft = {
        line_items,
        ...(body.note ? { note: body.note } : {}),
        ...(body.customerId ? { customer: { id: body.customerId } } : {}),
        taxes_included: shopCfg.taxes_included,
        tags: 'pressify,draft-checkout'
      };

      // Pressify: scope/team + rabattkod i note_attributes + metafields
      const { note_attributes, metafields } = pfBuildDraftOrderMeta(baseDraft, body);

      payloadToShopify = {
        draft_order: {
          ...baseDraft,
          ...(note_attributes.length ? { note_attributes } : {}),
          ...(metafields.length ? { metafields } : {})
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

// ===== Postgres helpers för orders_snapshot =============================

// ===== Postgres helpers för orders_snapshot =============================

// Normalisera metafältet så vi både får exakt raw-string och JSON–objektet
function normalizeOrderMetafieldForSnapshot(metafieldValue) {
  // Fall 1: metafältet är en JSON-sträng (vanligt från Shopify Admin)
  if (typeof metafieldValue === 'string') {
    const raw = metafieldValue;
    let json = null;

    try {
      const parsed = JSON.parse(raw);
      // Vi accepterar endast objekt/arrayer som JSONB – om det är en "dubbelencodad" sträng
      // eller något annat (t.ex. bara en textsträng), sätter vi json = null
      // för att undvika Postgres-fel.
      if (parsed && typeof parsed === 'object') {
        json = parsed;
      } else {
        json = null;
      }
    } catch {
      json = null;
    }

    return { raw, json };
  }

  // Fall 2: inget värde alls – vi sparar 'null' som text och NULL som JSONB
  if (metafieldValue == null) {
    return { raw: 'null', json: null };
  }

  // Fall 3: metafältet är redan ett objekt/array (t.ex. vår egen "combined" i order-created)
  // Här kan vi tryggt spara både raw-string och JSONB.
  const json = metafieldValue;
  const raw = JSON.stringify(metafieldValue);
  return { raw, json };
}


// Plocka ut tidsstämplar från Shopify-order (fallback till now)
function extractOrderTimestamps(order) {
  const created = order?.created_at || order?.processed_at || new Date().toISOString();
  const updated = order?.updated_at || created;
  return { createdAt: created, updatedAt: updated };
}

// Upsert: spara snapshot av order + metafält i Postgres
async function upsertOrderSnapshotFromMetafield(order, metafieldValue) {
  if (!pgPool) return; // om DB är nere vill vi INTE krascha webhooks

  try {
    const orderId = Number(order?.id);
    if (!orderId || Number.isNaN(orderId)) return;

    const customerId = order?.customer?.id ? Number(order.customer.id) : null;
    const customerEmail =
      order?.email ||
      order?.customer?.email ||
      null;

    const { createdAt, updatedAt } = extractOrderTimestamps(order);
    const { raw, json } = normalizeOrderMetafieldForSnapshot(metafieldValue);

    await pgQuery(
      `INSERT INTO ${ORDERS_SNAPSHOT_TABLE} (
         order_id,
         customer_id,
         customer_email,
         created_at,
         updated_at,
         metafield_raw,
         metafield_json
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (order_id) DO UPDATE SET
         customer_id    = EXCLUDED.customer_id,
         customer_email = EXCLUDED.customer_email,
         created_at     = LEAST(${ORDERS_SNAPSHOT_TABLE}.created_at, EXCLUDED.created_at),
         updated_at     = EXCLUDED.updated_at,
         metafield_raw  = EXCLUDED.metafield_raw,
         metafield_json = EXCLUDED.metafield_json`,
      [
        orderId,
        customerId,
        customerEmail,
        createdAt,
        updatedAt,
        raw,
        json
      ]
    );
  } catch (e) {
    console.warn('[orders_snapshot] upsertOrderSnapshotFromMetafield failed:', e?.message || e);
  }
}

// Läs snapshot för en enskild order
async function readOrderSnapshot(orderId) {
  if (!pgPool) return null;
  try {
    const oid = Number(orderId);
    const { rows } = await pgQuery(
      `SELECT
         order_id,
         customer_id,
         customer_email,
         created_at,
         updated_at,
         metafield_raw,
         metafield_json
       FROM ${ORDERS_SNAPSHOT_TABLE}
       WHERE order_id = $1`,
      [oid]
    );
    return rows[0] || null;
  } catch (e) {
    console.warn('[orders_snapshot] readOrderSnapshot failed:', e?.message || e);
    return null;
  }
}

// Läs senaste N ordrar för en kund (för t.ex. orders-listor i frontend)
async function listOrderSnapshotsForCustomer(customerId, limit = 50) {
  if (!pgPool) return [];
  try {
    const cid = Number(customerId);
    const lim = Number.isFinite(Number(limit)) ? Number(limit) : 50;

    const { rows } = await pgQuery(
      `SELECT
         order_id,
         customer_id,
         customer_email,
         created_at,
         updated_at,
         metafield_raw,
         metafield_json
       FROM ${ORDERS_SNAPSHOT_TABLE}
       WHERE customer_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [cid, lim]
    );
    return rows || [];
  } catch (e) {
    console.warn('[orders_snapshot] listOrderSnapshotsForCustomer failed:', e?.message || e);
    return [];
  }
}
// ========================================================================


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

// --- NYTT: tolka både _px_origin och _noproof för att hoppa korrektur ---
const pxOriginVal =
  (allClean.find(p => p.name.toLowerCase() === '_px_origin')?.value || '')
    .trim()
    .toLowerCase();

const noproofVal =
  (allClean.find(p => p.name.toLowerCase() === '_noproof')?.value || '')
    .trim()
    .toLowerCase();

// "sant" om inte uttryckligen falskt/nej/0
const isTruthy = v =>
  !!v && v !== '0' && v !== 'false' && v !== 'nej' && v !== 'no' && v !== 'null' && v !== 'undefined';

const skipProof = (pxOriginVal === 'noproof') || isTruthy(noproofVal);

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
  status: skipProof ? 'I produktion' : 'Väntar på korrektur',
  tag:    skipProof ? 'I produktion' : 'Väntar på korrektur',
  date: new Date().toISOString(),
  artworkToken,
  delivery: {
    v: 1,
    chosen: chosenMethod,
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
      {
        metafield: {
          namespace: ORDER_META_NAMESPACE,
          key: ORDER_META_KEY,
          type: 'json',
          value: JSON.stringify(combined)
        }
      },
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
  }

  console.log('✅ Metafält sparat!');
  try { await cacheOrderProjects(orderId, combined); } catch {}

  // 🔄 NYTT: spegla order + metafält till Postgres-snapshot
  try {
    // metafältet (combined) är fortfarande "sanningen" – vi använder samma struktur här
    await upsertOrderSnapshotFromMetafield(order, combined);
  } catch (e) {
    console.warn('[orders_snapshot] order-created → snapshot misslyckades:', e?.message || e);
  }

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

app.post('/webhooks/order-updated', async (req, res) => {
  console.log('📬 Webhook order-updated mottagen');

  if (!verifyShopifyRequest(req)) {
    console.warn('❌ Ogiltig Shopify-signatur (order-updated)!');
    return res.sendStatus(401);
  }

  try {
    const order = req.body;
    const orderId = order && order.id;

    if (!orderId) {
      console.warn('[orders_snapshot] order-updated: saknar order.id i payload');
      return res.sendStatus(400);
    }

    // Hämta det aktuella order-metafältet från Shopify – metafältet är alltid sanningen
    const mfResp = await axios.get(
      `https://${SHOP}/admin/api/2025-07/orders/${orderId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );

    const metafields = (mfResp.data && mfResp.data.metafields) || [];
    const mf = metafields.find(
      (m) => m.namespace === ORDER_META_NAMESPACE && m.key === ORDER_META_KEY
    );

    if (!mf || !mf.value) {
      console.log('[orders_snapshot] order-updated: inget order-metafält att spegla, hoppar över', orderId);
      return res.sendStatus(200);
    }

    // Spegla exakt samma metafält-value till vår Postgres-snapshot
    try {
      await upsertOrderSnapshotFromMetafield(order, mf.value);
      console.log('[orders_snapshot] order-updated: snapshot uppdaterad', orderId);
    } catch (e) {
      console.warn('[orders_snapshot] order-updated → snapshot misslyckades:', e?.message || e);
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('[orders_snapshot] Fel vid webhook/order-updated:', err?.response?.data || err.message);
    res.sendStatus(500);
  }
});

// Hämta korrektur-status för kund
// Hämta korrektur-status för kund (Postgres först, Shopify fallback)
app.get('/pages/korrektur', async (req, res) => {
  const customerId = req.query.customerId;
  if (!customerId) {
    return res.status(400).json({ error: 'customerId krävs' });
  }

  try {
    const customerIdNum = Number(customerId);

    /* ==========================================================
     * 1) Försök läsa från Postgres / orders_snapshot först
     * ========================================================== */
    let snapshotProjects = [];
    try {
      const snapshots = await listOrderSnapshotsForCustomer(customerIdNum, 50);
      if (snapshots && snapshots.length) {
        console.log(
          '[orders_snapshot] /pages/korrektur: använder snapshots för kund',
          customerIdNum,
          'count=',
          snapshots.length
        );

        for (const snap of snapshots) {
          const orderId = Number(snap.order_id || snap.orderId);
          let arr = [];

          // Föredra JSONB om den finns
          if (snap.metafield_json && Array.isArray(snap.metafield_json)) {
            arr = snap.metafield_json;
          } else if (snap.metafield_json && typeof snap.metafield_json === 'object') {
            // Om du någon gång skulle spara som { projects:[...] } etc.
            if (Array.isArray(snap.metafield_json.projects)) {
              arr = snap.metafield_json.projects;
            } else {
              arr = [];
            }
          } else if (snap.metafield_raw) {
            try {
              arr = JSON.parse(snap.metafield_raw);
            } catch {
              arr = [];
            }
          } else {
            arr = [];
          }

          const awaiting = (arr || [])
            .filter((p) => String(p?.status) === 'Korrektur redo')
            .map((p) => ({
              ...p,
              orderId
            }));

          if (awaiting.length) {
            snapshotProjects.push(...awaiting);
          }
        }

        if (snapshotProjects.length === 0) {
          // Det finns snapshots, men inget med status "Korrektur redo"
          return res.json({
            message: 'Just nu har du ingenting att godkänna',
            projects: []
          });
        }

        // ✅ Returnera direkt från Postgres – ingen Shopify-läsning
        return res.json({
          message: 'Godkänn korrektur',
          projects: snapshotProjects
        });
      }
    } catch (e) {
      console.warn(
        '[orders_snapshot] /pages/korrektur: listOrderSnapshotsForCustomer misslyckades – faller tillbaka till Shopify',
        e?.message || e
      );
      // vi faller vidare till Shopify-fallback nedan
    }

    /* ==========================================================
     * 2) Fallback: hämta från Shopify GraphQL + fyll snapshots
     * ========================================================== */
    console.warn(
      '[orders_snapshot] /pages/korrektur: inga snapshots för kund – använder Shopify-fallback första gången',
      { customerId: customerIdNum }
    );

    const q = `customer_id:${customerId} status:any`;
    const query = `
      query OrdersWithProof($first:Int!,$q:String!,$ns:String!,$key:String!){
        orders(first:$first, query:$q, sortKey:CREATED_AT, reverse:true){
          edges{
            node{
              id
              name
              processedAt
              createdAt
              updatedAt
              customer {
                id
                email
              }
              metafield(namespace:$ns, key:$key){ value }
            }
          }
        }
      }
    `;

    const data = await shopifyGraphQL(query, {
      first: 50,
      q,
      ns: ORDER_META_NAMESPACE,
      key: ORDER_META_KEY
    });
    if (data.errors) throw new Error('GraphQL error');

    const edges = data?.data?.orders?.edges || [];
    const results = [];

    for (const e of edges) {
      const node = e.node;
      const orderId = Number(gidToId(node.id));
      let arr = [];
      try {
        arr = node.metafield?.value ? JSON.parse(node.metafield.value) : [];
      } catch {
        arr = [];
      }

      // 🔄 Seeda snapshot i Postgres om vi har ett metafältsvärde
      if (node.metafield && typeof node.metafield.value === 'string' && node.metafield.value.trim()) {
        const customerIdForOrder = node.customer?.id
          ? Number(gidToId(node.customer.id))
          : customerIdNum || null;

        const orderStub = {
          id: orderId,
          customer: {
            id: customerIdForOrder,
            email: node.customer?.email || null
          },
          email: node.customer?.email || null,
          // Anpassa till extractOrderTimestamps-helpern (klarar både snake/camel i praktiken)
          created_at: node.createdAt || node.processedAt || new Date().toISOString(),
          processed_at: node.processedAt || node.createdAt || new Date().toISOString(),
          updated_at:
            node.updatedAt ||
            node.processedAt ||
            node.createdAt ||
            new Date().toISOString()
        };

        try {
          await upsertOrderSnapshotFromMetafield(orderStub, node.metafield.value);
          console.log(
            '[orders_snapshot] /pages/korrektur: snapshot upsert via Shopify-fallback',
            orderId
          );
        } catch (e2) {
          console.warn(
            '[orders_snapshot] /pages/korrektur: upsertOrderSnapshotFromMetafield misslyckades i fallback',
            e2?.message || e2
          );
        }
      }

      const awaiting = (arr || [])
        .filter((p) => String(p?.status) === 'Korrektur redo')
        .map((p) => ({
          ...p,
          orderId
        }));

      if (awaiting.length) {
        results.push(...awaiting);
      }
    }

    if (results.length === 0) {
      return res.json({
        message: 'Just nu har du ingenting att godkänna',
        projects: []
      });
    }

    return res.json({
      message: 'Godkänn korrektur',
      projects: results
    });
  } catch (err) {
    console.error(
      '❌ Fel vid hämtning av korrektur (/pages/korrektur):',
      err?.response?.data || err.message || err
    );
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
    try {
  // Vänta lite grann så att metafältsskrivningen hinner persisteras på Shopify
  setTimeout(async () => {
    try {
      // 1) Hämta orderns email från Shopify (standardfält)
      const { data: oRes } = await axios.get(
        `https://${SHOP}/admin/api/2025-07/orders/${orderId}.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const o = oRes?.order || {};
      const toEmail = o.email || o.customer?.email || null;
      if (!toEmail) return;

      // 2) Hitta den uppdaterade raden i det vi precis skrev (rotated)
      //    (vi använder rotated eftersom den innehåller latestShareUrl m.m.)
      let proj = null;
      try {
        proj = (rotated || []).find(p => String(p.lineItemId) === String(lineItemId)) || null;
      } catch {}

      // 3) Bygg TemplateModel exakt som mallen förväntar sig
      const item_values = Array.isArray(proj?.properties)
        ? proj.properties
            .filter(p => p && typeof p.name === 'string' && !p.name.startsWith('_'))
            .map(p => p.value)
            .filter(Boolean)
        : [];

      const model = {
        order_name: o.name || proj?.orderNumber || `#${orderId}`,
        item_title: proj?.productTitle || '',
        item_preview_url: proj?.previewUrl || proj?.preview_img || '',
        item_values,
        item_instructions: proj?.instructions || '',
        // Länka till just den specifika token-URL vi precis genererade
        links_proof: proj?.latestShareUrl || url,
        // valfritt (visas bara om din mall har {{#brand_logo_url}})
        brand_logo_url: 'https://res.cloudinary.com/dmgmoisae/image/upload/f_auto,q_auto/v1759407646/Pressify_logotyp_mn81jp.png'
      };

      await postmarkSendEmail({
        to: toEmail,
        alias: POSTMARK_TEMPLATE_ALIAS_PROOF_UPLOADED,
        model
      });
    } catch (e) {
      console.warn('[proof.upload email] send failed:', e?.response?.data || e.message);
    }
  }, 900); // ~0.9 s buffert; justera vid behov
} catch (e) {
  console.warn('[proof.upload email] schedule failed:', e?.message || e);
}
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
  if (String(p.lineItemId) !== String(lineItemId)) return p;

  // Samma logik som innan: sätt status + preview_img till godkända bilden
  const newImg = p.previewUrl || p.preview_img || null;
  const next = { ...p, status: 'I produktion', preview_img: newImg };

  // BONUS (minimal): om property "_preview_img" finns → uppdatera dess value
  if (newImg && Array.isArray(p.properties)) {
    next.properties = p.properties.map(prop =>
      (prop && prop.name === '_preview_img')
        ? { ...prop, value: newImg }
        : prop
    );
  }

  return next;
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

// ===== APP PROXY: /proxy/avatar (mappar från t.ex. /apps/orders-meta/avatar) =====
app.all('/proxy/avatar', async (req, res) => {
  try {
    // 1) Verifiera App Proxy-signaturen
    const search = req.url.split('?')[1] || '';
    if (!verifyAppProxySignature(search)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // 2) Shopify skickar alltid logged_in_customer_id = PERSONLIGT konto
    const loggedInCustomerIdRaw = req.query.logged_in_customer_id;
    if (!loggedInCustomerIdRaw) {
      return res.status(401).json({ error: 'Not logged in' });
    }

    const normalizeCustomerId = (cid) => {
      if (!cid) return null;
      const s = String(cid);
      return s.startsWith('gid://') ? s.split('/').pop() : s;
    };

    const loggedInCustomerId = normalizeCustomerId(loggedInCustomerIdRaw);

    // ===== GET: hämta avatar för DET PERSONLIGA kontot (legacy-beteende) =====
    if (req.method === 'GET') {
      const { data } = await axios.get(
        `https://${SHOP}/admin/api/2025-07/customers/${loggedInCustomerId}/metafields.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      const mf = (data.metafields || []).find(
        m => m.namespace === 'Profilbild' && m.key === 'Profilbild'
      );
      return res.json({ ok: true, metafield: mf ? mf.value : null });
    }

    // Vi hanterar allt annat via POST
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const body = req.body || {};
    const { action, meta, targetType, teamCustomerId } = body;

    // 3) Bestäm vilket kund-ID som är "target":
    //    - personal  → loggedInCustomerId
    //    - team      → teamCustomerId (från frontend)
    let targetCustomerId = loggedInCustomerId;
    if (String(targetType || '').toLowerCase() === 'team' && teamCustomerId) {
      targetCustomerId = normalizeCustomerId(teamCustomerId);
    }
    if (!targetCustomerId) {
      return res.status(400).json({ error: 'Missing target customer id' });
    }

    // TODO (säkerhet): här kan du lägga in extra koll:
    //  - läs customer.metafields.teams.teams för loggedInCustomerId
    //  - verifiera att loggedInCustomerId är medlem/ägare i det teamCustomerId man försöker ändra

    // 4) Läs befintligt Profilbild-metafält för targetCustomerId
    const { data: mfData } = await axios.get(
      `https://${SHOP}/admin/api/2025-07/customers/${targetCustomerId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const existing = (mfData.metafields || []).find(
      m => m.namespace === 'Profilbild' && m.key === 'Profilbild'
    );

    // ===== action: get (POST-variant för att hämta team-avatar) =====
    if (action === 'get') {
      return res.json({
        ok: true,
        metafield: existing ? existing.value : null
      });
    }

    // ===== action: delete =====
    if (action === 'delete') {
      if (existing) {
        await axios.delete(
          `https://${SHOP}/admin/api/2025-07/metafields/${existing.id}.json`,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
      }
      return res.json({ ok: true, deleted: true });
    }

    // ===== action: save =====
    if (action === 'save') {
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

      let existingValue = {};
      try {
        existingValue = existing && existing.value ? JSON.parse(existing.value) : {};
      } catch {
        existingValue = {};
      }

      const normalizeBool = (v) => {
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        if (typeof v === 'string') return /^(true|1|yes|on)$/i.test(v.trim());
        return false;
      };

      const valueObj = {
        // Bildfält – bevara gamla om de inte skickas
        public_id:  String(meta.public_id ?? existingValue.public_id ?? ''),
        version:    meta.version ?? existingValue.version ?? null,
        secure_url: String(meta.secure_url ?? existingValue.secure_url ?? ''),

        // Övriga fält du redan använder
        selection:  String(meta.selection ?? existingValue.selection ?? ''),
        marketing:  (typeof meta.marketing !== 'undefined')
                      ? normalizeBool(meta.marketing)
                      : (typeof existingValue.marketing !== 'undefined' ? !!existingValue.marketing : false),
        role:       String(meta.role ?? existingValue.role ?? ''),

        updatedAt:  new Date().toISOString()
      };

      const payload = {
        metafield: {
          namespace: 'Profilbild',
          key: 'Profilbild',
          type: 'json',
          value: JSON.stringify(valueObj)
        }
      };

      if (existing) {
        await axios.put(
          `https://${SHOP}/admin/api/2025-07/metafields/${existing.id}.json`,
          { metafield: { id: existing.id, ...payload.metafield } },
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
      } else {
        await axios.post(
          `https://${SHOP}/admin/api/2025-07/customers/${targetCustomerId}/metafields.json`,
          payload,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
      }

      return res.json({ ok: true });
    }

    return res.status(400).json({ error: 'Unknown action' });
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


app.all('/proxy/orders-meta/avatar', async (req, res) => {
  try {
    const search = req.url.split('?')[1] || '';
    if (!verifyAppProxySignature(search)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) {
      return res.status(401).json({ error: 'Not logged in' });
    }

    const normalizeCustomerId = (cid) => {
      if (!cid) return null;
      const s = String(cid);
      return s.startsWith('gid://') ? s.split('/').pop() : s;
    };
    const customerId = normalizeCustomerId(loggedInCustomerId);

    if (req.method !== 'POST') {
      // GET kan du låta vara kvar som tidigare om något annat använder den,
      // men avatar-komponenten använder nu bara metafältet från Liquid.
      if (req.method === 'GET') {
        const mfRes = await axios.get(
          `https://${SHOP}/admin/api/2025-07/customers/${customerId}/metafields.json`,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
        const mf = (mfRes.data.metafields || []).find(m => m.namespace === 'Profilbild' && m.key === 'Profilbild');
        return res.json({ ok: true, metafield: mf ? mf.value : null });
      }
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { action, meta, targetType, teamCustomerId } = req.body || {};
    const tType = (targetType || 'personal').toLowerCase();

    // Läs befintligt metafält
    const mfRes = await axios.get(
      `https://${SHOP}/admin/api/2025-07/customers/${customerId}/metafields.json`,
      { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
    );
    const existing = (mfRes.data.metafields || []).find(
      m => m.namespace === 'Profilbild' && m.key === 'Profilbild'
    );

    let valueObj = {};
    try { valueObj = existing && existing.value ? JSON.parse(existing.value) : {}; } catch { valueObj = {}; }

    valueObj.teams = valueObj.teams || {};

    // ==== DELETE ====
    if (action === 'delete') {
      if (tType === 'team' && teamCustomerId) {
        const tid = String(teamCustomerId);
        if (valueObj.teams[tid]) {
          delete valueObj.teams[tid];
        }
      } else {
        // personlig avatar bort
        delete valueObj.personal;
        // ev. bakåtkomp-fält
        delete valueObj.public_id;
        delete valueObj.secure_url;
        delete valueObj.version;
      }

      const payload = {
        metafield: {
          namespace: 'Profilbild',
          key: 'Profilbild',
          type: 'json',
          value: JSON.stringify(valueObj)
        }
      };

      if (existing) {
        await axios.put(
          `https://${SHOP}/admin/api/2025-07/metafields/${existing.id}.json`,
          { metafield: { id: existing.id, ...payload.metafield } },
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
      } else {
        await axios.post(
          `https://${SHOP}/admin/api/2025-07/customers/${customerId}/metafields.json`,
          payload,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
      }

      return res.json({ ok: true });
    }

    // ==== SAVE ====
    if (action === 'save') {
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

      const normalizeBool = (v) => {
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        if (typeof v === 'string') return /^(true|1|yes|on)$/i.test(v.trim());
        return false;
      };

      if (tType === 'team' && teamCustomerId) {
        const tid = String(teamCustomerId);
        const old = valueObj.teams[tid] || {};
        valueObj.teams[tid] = {
          ...old,
          public_id:  String(meta.public_id ?? old.public_id ?? ''),
          version:    meta.version ?? old.version ?? null,
          secure_url: String(meta.secure_url ?? old.secure_url ?? ''),
          selection:  String(meta.selection ?? old.selection ?? ''),
          marketing:  (typeof meta.marketing !== 'undefined')
                        ? normalizeBool(meta.marketing)
                        : (typeof old.marketing !== 'undefined' ? !!old.marketing : false),
          role:       String(meta.role ?? old.role ?? ''),
          updatedAt:  new Date().toISOString()
        };
      } else {
        const old = valueObj.personal || {};
        valueObj.personal = {
          ...old,
          public_id:  String(meta.public_id ?? old.public_id ?? ''),
          version:    meta.version ?? old.version ?? null,
          secure_url: String(meta.secure_url ?? old.secure_url ?? ''),
          selection:  String(meta.selection ?? old.selection ?? ''),
          marketing:  (typeof meta.marketing !== 'undefined')
                        ? normalizeBool(meta.marketing)
                        : (typeof old.marketing !== 'undefined' ? !!old.marketing : false),
          role:       String(meta.role ?? old.role ?? ''),
          updatedAt:  new Date().toISOString()
        };

        // bakåtkomp till root-fält om något annat läser dem
        valueObj.public_id  = valueObj.personal.public_id;
        valueObj.version    = valueObj.personal.version;
        valueObj.secure_url = valueObj.personal.secure_url;
      }

      const payload = {
        metafield: {
          namespace: 'Profilbild',
          key: 'Profilbild',
          type: 'json',
          value: JSON.stringify(valueObj)
        }
      };

      if (existing) {
        await axios.put(
          `https://${SHOP}/admin/api/2025-07/metafields/${existing.id}.json`,
          { metafield: { id: existing.id, ...payload.metafield } },
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
      } else {
        await axios.post(
          `https://${SHOP}/admin/api/2025-07/customers/${customerId}/metafields.json`,
          payload,
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
        );
      }

      return res.json({ ok: true, value: valueObj });
    }

    return res.status(400).json({ error: 'Unknown action' });
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
    const teamId = req.query.teamId || '';
    const key = `${cid}:${first}:${scope}:${teamId}`;

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

/**
 * Filtrerar orders på workspace-scope:
 *  - scope=personal  → bara personliga (eller orders utan scope-fält)
 *  - scope=team      → bara team-ordrar, filtrerade på teamId (normaliserat)
 *  - övrigt/ingen    → ingen extra filtrering
 *
 * Viktigt:
 *  - teamId kan vara GID eller ren siffra både i query och på ordern.
 *    Vi använder pfNormalizeTeamId för båda.
 */
function applyWorkspaceScopeFilter(list, scopeParam, teamIdParam) {
  const scope = String(scopeParam || '').toLowerCase();
  const wantTeamId = pfNormalizeTeamId(teamIdParam);
  const src = Array.isArray(list) ? list : [];

  if (scope === 'personal') {
    // Allt som inte är markerat som team räknas som personal
    return src.filter(o => (o.scope || 'personal') !== 'team');
  }

  if (scope === 'team') {
    return src.filter(o => {
      if ((o.scope || 'personal') !== 'team') return false;
      if (!wantTeamId) return true;
      const orderTeamId = pfNormalizeTeamId(o.teamId);
      return orderTeamId === wantTeamId;
    });
  }

  return src;
}

// ===== TEAMS: helpers för customer.metafields.teams.teams (JSON) =====
async function readCustomerTeams(customerId) {

  const customerGid = toGid('Customer', customerId);
  const query = `
    query GetCustomerTeams($id: ID!) {
      customer(id: $id) {
        id
        metafield(namespace: "${TEAMS_NS}", key: "${TEAMS_KEY}") {
          id
          value
          type
        }
      }
    }
  `;
  const data = await shopifyGraphQL(query, { id: customerGid });
  const customer = data?.data?.customer || null;
  const mf = customer?.metafield || null;
  if (!mf || !mf.value) {
    // Saknat metafält = solo-konto enligt din modell
    return { metafieldId: null, value: null };
  }
  let parsed = null;
  try {
    parsed = JSON.parse(mf.value);
  } catch {
    parsed = null;
  }
  return { metafieldId: mf.id || null, value: parsed };
}

async function writeCustomerTeams(customerId, valueObj) {
  const customerGid = toGid('Customer', customerId);
  const mutation = `
    mutation SetCustomerTeamsMetafield($input: MetafieldsSetInput!) {
      metafieldsSet(metafields: [$input]) {
        metafields {
          id
          key
          namespace
          type
          value
        }
        userErrors {
          field
          message
        }
      }
    }
  `;
  const input = {
    ownerId: customerGid,
    namespace: TEAMS_NS,
    key: TEAMS_KEY,
    type: 'json',
    value: JSON.stringify(valueObj ?? null)
  };
  const data = await shopifyGraphQL(mutation, { input });
  const result = data?.data?.metafieldsSet;
  const userErrors = result?.userErrors || [];
  if (userErrors.length > 0) {
    const msg = userErrors.map(e => e.message).join('; ');
    throw new Error('Failed to save teams metafield: ' + msg);
  }
  const saved = (result?.metafields || [])[0] || null;
  return saved;
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

// 🔹 Hjälp: bestäm om order ska räknas som levererad (oförändrad)
function isDeliveredOrderShape(o) {
  const disp = String(o.displayFulfillmentStatus || o.display_delivery_status || '').toUpperCase();
  const fs   = String(o.fulfillmentStatus || '').toUpperCase();
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

// 🔹 Hjälp: normalisera kund-ID (GID → numeriskt)
function normalizeCustomerId(cidRaw) {
  if (!cidRaw) return null;
  const s = String(cidRaw).trim();
  if (!s) return null;
  return s.startsWith('gid://') ? s.split('/').pop() : s;
}

app.get('/proxy/orders-meta', async (req, res) => {
  try {
    // 1) Säkerställ att anropet kommer från Shopify App Proxy
    const search = req.url.split('?')[1] || '';
    if (!verifyAppProxySignature(search)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const loggedInCustomerIdRaw = req.query.logged_in_customer_id; // sätts av Shopify
    if (!loggedInCustomerIdRaw) return res.status(204).end();      // ej inloggad kund

    const cidNum = normalizeCustomerId(loggedInCustomerIdRaw);
    if (!cidNum) return res.status(400).json({ error: 'invalid_customer_id' });

    const limit      = Math.min(parseInt(req.query.first || '25', 10), 50);
    const scopeParam = String(req.query.scope || '').toLowerCase();
    const teamIdFilter = String(req.query.teamId || '').trim();

    // ===== ADMIN-LÄGE (scope=all) – oförändrat, kör Shopify Admin =====
    if (scopeParam === 'all') {
      const ok = await isAdminCustomer(cidNum);
      if (!ok) return res.status(403).json({ error: 'Forbidden' });

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
                  tags
                  metafield(namespace: $ns, key: $key) { value }
                  metafields(namespace: "pressify", keys: ["scope", "team_id", "team_name"]) {
                    key
                    value
                  }
                }
              }
            }
          }
        `;

        const q = `status:any`;

        const data = await shopifyGraphQL(query, {
          first: limit,
          q,
          ns: ORDER_META_NAMESPACE,
          key: ORDER_META_KEY
        });

        if (data.errors) {
          throw new Error('GraphQL error');
        }

        const edges = data?.data?.orders?.edges || [];
        const out   = [];

        for (const e of edges) {
          const node = e.node;
          const base = {
            id: parseInt(gidToId(node.id), 10) || gidToId(node.id),
            name: node.name,
            processedAt: node.processedAt,
            metafield: node.metafield ? node.metafield.value : null,
            fulfillmentStatus: node.fulfillmentStatus || null,
            displayFulfillmentStatus: node.displayFulfillmentStatus || null
          };

          let scopeVal = 'personal';
          let teamId   = null;
          let teamName = null;

          const pfMfs = Array.isArray(node.metafields) ? node.metafields : [];
          const scopeMf    = pfMfs.find(m => m && m.key === 'scope');
          const teamIdMf   = pfMfs.find(m => m && m.key === 'team_id');
          const teamNameMf = pfMfs.find(m => m && m.key === 'team_name');

          if (scopeMf && typeof scopeMf.value === 'string') {
            const v = scopeMf.value.toLowerCase();
            scopeVal = v === 'team' ? 'team' : 'personal';
          }
          if (scopeVal === 'team') {
            if (teamIdMf && teamIdMf.value != null) {
              teamId = pfNormalizeTeamId(teamIdMf.value);
            }
            if (teamNameMf && teamNameMf.value != null) {
              teamName = String(teamNameMf.value);
            }
          }

          out.push({ ...base, scope: scopeVal, teamId, teamName });
        }

        const nonDelivered = out.filter(o => !isDeliveredOrderShape(o));

        res.setHeader('Cache-Control', 'no-store');
        return res.json({ orders: nonDelivered, admin: true });
      } catch (err) {
        console.error('proxy/orders-meta admin error:', err?.response?.data || err.message);
        setCorsOnError(req, res);
        return res.status(500).json({ error: 'Internal error' });
      }
    }

    // ===== KUND-/TEAM-LÄGE: Försök Postgres-snapshot först =====
    const canUseSnapshots =
      typeof listOrderSnapshotsForCustomer === 'function' &&
      scopeParam !== 'all';

    if (canUseSnapshots) {
      try {
        const snapshots = await listOrderSnapshotsForCustomer(cidNum, limit);

        if (Array.isArray(snapshots) && snapshots.length > 0) {
          console.log('[orders-meta] ✅ använder Postgres orders_snapshot för customer', cidNum);

          const out = snapshots.map(row => {
            const orderId   = Number(row.order_id);
            const metaRaw   = row.metafield_raw; // exakt samma JSON-sträng som i Shopify-order-metafältet
            const createdAt = row.created_at;

            // Härled scope/team från project-JSON (ORDER_META_NAMESPACE)
            const info = pfExtractScopeFromOrderProjects(metaRaw);

            return {
              id: orderId,
              // OBS: snapshot-tabellen innehåller i dagsläget inte order.name.
              // Om du vill ha exakt ordernummer här, lägg till kolumn order_name i tabellen
              // och fyll den i upsertOrderSnapshotFromMetafield.
              name: null, // behåll property, men låt värdet vara null tills DB utökas
              processedAt: createdAt,
              metafield: metaRaw,
              // fulfillmentStatus och displayFulfillmentStatus finns inte i snapshot ännu
              fulfillmentStatus: null,
              displayFulfillmentStatus: null,
              scope: info.scope || 'personal',
              teamId: info.teamId || null,
              teamName: info.teamName || null
            };
          });

          const scopedOut = applyWorkspaceScopeFilter(out, scopeParam, teamIdFilter);
          res.setHeader('Cache-Control', 'no-store');
          return res.json({ orders: scopedOut });
        } else {
          console.log('[orders-meta] ℹ️ inga snapshots hittades för customer', cidNum, '– fall back till Shopify');
        }
      } catch (e) {
        console.warn('[orders-meta] ⚠️ snapshot-läsning misslyckades, fall back till Shopify:', e?.message || e);
      }
    }

    // ===== Om vi kommer hit → Postgres gav inget → Shopify GraphQL + REST-fallback (som tidigare) =====
    try {
      console.log('[orders-meta] ▶ fall back till Shopify GraphQL för customer', cidNum);

      const rawCustomerIdParam = String(req.query.customerId || '').trim();
      const scopeForQ          = scopeParam;
      const teamIdForQ         = teamIdFilter;

      let q;
      if (scopeForQ === 'team' && rawCustomerIdParam) {
        q = `status:any`;
      } else {
        q = `customer_id:${cidNum} status:any`;
      }

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

      const data = await shopifyGraphQL(query, {
        first: limit,
        q,
        ns: ORDER_META_NAMESPACE,
        key: ORDER_META_KEY
      });

      if (data.errors) {
        throw new Error('GraphQL error');
      }

      const edges = data?.data?.orders?.edges || [];
      const out   = edges.map(e => {
        const node = e.node;
        const metafieldValue = node.metafield ? node.metafield.value : null;

        const base = {
          id: parseInt(gidToId(node.id), 10) || gidToId(node.id),
          name: node.name,
          processedAt: node.processedAt,
          metafield: metafieldValue,
          fulfillmentStatus: node.fulfillmentStatus || null,
          displayFulfillmentStatus: node.displayFulfillmentStatus || null
        };

        const scopeInfo = pfExtractScopeFromOrderProjects(metafieldValue);
        return {
          ...base,
          scope: scopeInfo.scope || 'personal',
          teamId: scopeInfo.teamId || null,
          teamName: scopeInfo.teamName || null
        };
      });

      const scopedOut = applyWorkspaceScopeFilter(out, scopeForQ, teamIdForQ);
      res.setHeader('Cache-Control', 'no-store');
      return res.json({ orders: scopedOut });
    } catch (err) {
      // 🔁 Fallback: befintlig REST-implementation – nu även med snapshot-upsert
      console.warn('proxy/orders-meta GraphQL fallback → REST:', err?.response?.data || err.message);

      try {
        const url = `https://${SHOP}/admin/api/2025-07/orders.json?status=any&customer_id=${encodeURIComponent(cidNum)}&limit=${limit}`;
        const { data } = await axios.get(url, {
          headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
        });

        const orders = data?.orders || [];
        const out    = [];

        for (const o of orders) {
          const mfResp = await axios.get(
            `https://${SHOP}/admin/api/2025-07/orders/${o.id}/metafields.json`,
            { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
          );
          const metafields = mfResp.data?.metafields || [];
          const projectMf  = metafields.find(
            m => m.namespace === ORDER_META_NAMESPACE && m.key === ORDER_META_KEY
          );

          let scopeVal = 'personal';
          let teamId   = null;
          let teamName = null;

          try {
            const value = projectMf ? projectMf.value : null;
            const info  = pfExtractScopeFromOrderProjects(value);
            scopeVal    = info.scope || 'personal';
            teamId      = info.teamId || null;
            teamName    = info.teamName || null;

            // 🟢 NYTT: spegla in i Postgres så framtida läsningar kan gå mot DB
            if (value != null && typeof upsertOrderSnapshotFromMetafield === 'function') {
              try {
                await upsertOrderSnapshotFromMetafield(o, value);
              } catch (upErr) {
                console.warn('[orders-meta] upsertOrderSnapshotFromMetafield misslyckades för order', o.id, upErr?.message || upErr);
              }
            }
          } catch {}

          out.push({
            id: o.id,
            name: o.name,
            processedAt: o.processed_at || o.created_at,
            metafield: projectMf ? projectMf.value : null,
            fulfillmentStatus: o.fulfillment_status || null,
            displayFulfillmentStatus: null,
            scope: scopeVal,
            teamId,
            teamName
          });
        }

        const scopedOut = applyWorkspaceScopeFilter(out, scopeParam, teamIdFilter);
        res.setHeader('Cache-Control', 'no-store');
        return res.json({ orders: scopedOut });
      } catch (err2) {
        console.error('proxy/orders-meta REST fallback error:', err2?.response?.data || err2.message);
        setCorsOnError(req, res);
        return res.status(500).json({ error: 'Internal error' });
      }
    }
  } catch (err) {
    console.error('proxy/orders-meta error (outer):', err?.response?.data || err.message);
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
// AFTER (utdrag ur index.js)

app.post('/proxy/orders-meta/profile/update', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const normalizeCustomerId = (cid) => {
      if (!cid) return null;
      const s = String(cid).trim();
      return s.startsWith('gid://') ? s.split('/').pop() : s;
    };

    const loggedInCustomerIdRaw = req.query.logged_in_customer_id;
    if (!loggedInCustomerIdRaw) {
      return res.status(401).json({ error: 'Not logged in' });
    }
    const loggedInCustomerId = normalizeCustomerId(loggedInCustomerIdRaw);

    const firstName = (req.body.first_name || '').trim();
    const lastName  = (req.body.last_name  || '').trim();
    const email     = (req.body.email      || '').trim();

    const targetTypeRaw     = String(req.body.target_type || '').trim().toLowerCase();
    const teamCustomerIdRaw = String(req.body.team_customer_id || '').trim();

    let targetCustomerId = loggedInCustomerId;
    let isTeamTarget = false;

    if (targetTypeRaw === 'team' && teamCustomerIdRaw) {
      const teamIdNum = normalizeCustomerId(teamCustomerIdRaw);
      if (!teamIdNum) {
        return res.status(400).json({ error: 'Invalid team customer id' });
      }

      // Säkerhet: verifiera att team-kontot verkligen är ett team och att inloggad kund är owner
      const teamMeta = await readCustomerTeams(teamIdNum);
      const teamValue = teamMeta?.value || null;

      if (!teamValue || !teamValue.isTeam) {
        return res.status(400).json({ error: 'not_a_team_account' });
      }
      if (Number(teamValue.ownerCustomerId) !== Number(loggedInCustomerId)) {
        return res.status(403).json({ error: 'not_team_owner' });
      }

      isTeamTarget = true;
      targetCustomerId = teamIdNum;
    }

    if (!targetCustomerId) {
      return res.status(400).json({ error: 'Missing target customer id' });
    }

    const customerPayload = {
      id: targetCustomerId,
      ...(firstName ? { first_name: firstName } : {}),
      ...(!isTeamTarget && lastName  ? { last_name:  lastName  } : {}),
      ...(!isTeamTarget && email     ? { email } : {})
    };

    const upRes = await axios.put(
      `https://${SHOP}/admin/api/2025-07/customers/${targetCustomerId}.json`,
      { customer: customerPayload },
      {
        headers: {
          'X-Shopify-Access-Token': ACCESS_TOKEN,
          'Content-Type': 'application/json'
        }
      }
    );

    // Om vi uppdaterar ett TEAM-konto → synca teamnamnet i metafält
    if (isTeamTarget && firstName) {
      const currentTeamMeta = await readCustomerTeams(targetCustomerId);
      let teamValue = currentTeamMeta.value;
      if (!teamValue || typeof teamValue !== 'object') {
        teamValue = {};
      }
      teamValue.isTeam = true;
      teamValue.teamName = firstName;
      await writeCustomerTeams(targetCustomerId, teamValue);

      const ownerMeta = await readCustomerTeams(loggedInCustomerId);
      let ownerValue = ownerMeta.value;
      if (ownerValue && typeof ownerValue === 'object' && Array.isArray(ownerValue.memberships)) {
        let changed = false;
        ownerValue.memberships = ownerValue.memberships.map((m) => {
          if (Number(m.teamCustomerId) === Number(targetCustomerId)) {
            changed = true;
            return { ...m, teamName: firstName };
          }
          return m;
        });
        if (changed) {
          await writeCustomerTeams(loggedInCustomerId, ownerValue);
        }
      }
    }

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

//
// NYTT: Team-adresser via Admin API (utan session-switch)
//
app.all('/proxy/orders-meta/team-addresses', async (req, res) => {
  try {
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const normalizeCustomerId = (cid) => {
      if (!cid) return null;
      const s = String(cid).trim();
      return s.startsWith('gid://') ? s.split('/').pop() : s;
    };

    const loggedInCustomerIdRaw = req.query.logged_in_customer_id;
    if (!loggedInCustomerIdRaw) {
      return res.status(401).json({ error: 'Not logged in' });
    }
    const loggedInCustomerId = normalizeCustomerId(loggedInCustomerIdRaw);

    const method = req.method.toUpperCase();
    const body   = method === 'GET' ? {} : (req.body || {});
    const action = (body.action || req.query.action || 'list').toLowerCase();

    const teamCustomerIdRaw =
      body.team_customer_id ||
      req.query.team_customer_id ||
      '';

    const teamCustomerId = normalizeCustomerId(teamCustomerIdRaw);
    if (!teamCustomerId) {
      return res.status(400).json({ error: 'Missing team_customer_id' });
    }

    // Säkerhet: verifiera att loggedInCustomerId är owner/admin på teamet
    const teamMeta = await readCustomerTeams(teamCustomerId);
    const teamValue = teamMeta?.value || null;
    if (!teamValue || !teamValue.isTeam) {
      return res.status(400).json({ error: 'not_a_team_account' });
    }
    if (Number(teamValue.ownerCustomerId) !== Number(loggedInCustomerId)) {
      return res.status(403).json({ error: 'not_team_owner' });
    }

    const baseUrl = `https://${SHOP}/admin/api/2025-07/customers/${teamCustomerId}`;

    if (action === 'list') {
      const resp = await axios.get(`${baseUrl}/addresses.json`, {
        headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN }
      });
      const addresses = resp.data?.addresses || [];
      const defaultAddress = addresses.find(a => a.default) || null;

      return res.json({
        ok: true,
        teamCustomerId,
        defaultAddressId: defaultAddress ? defaultAddress.id : null,
        addresses
      });
    }

    if (action === 'create') {
      const addressPayload = {
        first_name: (body.first_name || '').trim(),
        last_name:  (body.last_name  || '').trim(),
        company:    (body.company    || '').trim(),
        address1:   (body.address1   || '').trim(),
        address2:   (body.address2   || '').trim(),
        zip:        (body.zip        || '').trim(),
        city:       (body.city       || '').trim(),
        country:    (body.country    || '').trim() || 'Sweden',
        province:   (body.province   || '').trim(),
        phone:      (body.phone      || '').trim(),
        default:    body.default === '1' || body.default === 'true'
      };

      const resp = await axios.post(
        `${baseUrl}/addresses.json`,
        { address: addressPayload },
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' } }
      );

      return res.json({ ok: true, address: resp.data.address });
    }

    if (action === 'update') {
      const addrIdRaw = body.address_id || body.id;
      const addrId = addrIdRaw ? String(addrIdRaw).trim() : null;
      if (!addrId) {
        return res.status(400).json({ error: 'Missing address_id' });
      }

      const addressPayload = {
        id: addrId,
        ...(body.first_name ? { first_name: body.first_name.trim() } : {}),
        ...(body.last_name  ? { last_name:  body.last_name.trim()  } : {}),
        ...(body.company    ? { company:    body.company.trim()    } : {}),
        ...(body.address1   ? { address1:   body.address1.trim()   } : {}),
        ...(body.address2   ? { address2:   body.address2.trim()   } : {}),
        ...(body.zip        ? { zip:        body.zip.trim()        } : {}),
        ...(body.city       ? { city:       body.city.trim()       } : {}),
        ...(body.country    ? { country:    body.country.trim()    } : {}),
        ...(body.province   ? { province:   body.province.trim()   } : {}),
        ...(body.phone      ? { phone:      body.phone.trim()      } : {})
      };

      const resp = await axios.put(
        `${baseUrl}/addresses/${addrId}.json`,
        { address: addressPayload },
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' } }
      );

      // Default-flagga separat
      if (body.default === '1' || body.default === 'true') {
        await axios.put(
          `${baseUrl}/addresses/${addrId}/default.json`,
          {},
          { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' } }
        );
      }

      return res.json({ ok: true, address: resp.data.address });
    }

    if (action === 'delete') {
      const addrIdRaw = body.address_id || body.id;
      const addrId = addrIdRaw ? String(addrIdRaw).trim() : null;
      if (!addrId) {
        return res.status(400).json({ error: 'Missing address_id' });
      }

      await axios.delete(
        `${baseUrl}/addresses/${addrId}.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );

      return res.json({ ok: true, deletedId: addrId });
    }

    if (action === 'set_default') {
      const addrIdRaw = body.address_id || body.id;
      const addrId = addrIdRaw ? String(addrIdRaw).trim() : null;
      if (!addrId) {
        return res.status(400).json({ error: 'Missing address_id' });
      }

      const resp = await axios.put(
        `${baseUrl}/addresses/${addrId}/default.json`,
        {},
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN, 'Content-Type': 'application/json' } }
      );

      return res.json({ ok: true, address: resp.data.customer_address || null });
    }

    return res.status(400).json({ error: 'Unknown action' });
  } catch (err) {
    console.error('team-addresses error:', err?.response?.data || err.message);
    setCorsOnError(req, res);
    return res.status(500).json({ error: 'Internal error' });
  }
});



// ===== APP PROXY: Pressify Teams – skapa teamkonto =====
// POST /proxy/orders-meta/teams/create  (via Shopify App Proxy: theme anropar /apps/orders-meta/teams/create)
// Body: { teamName, teamEmail? }
// - Skapar ett nytt team-konto (Shopify customer)
// - Sätter teamets metafält (isTeam, teamName, ownerCustomerId, members[owner])
// - Uppdaterar ägarens metafält med memberships[...]
// ===== APP PROXY: Pressify Teams – skapa teamkonto =====
// POST /proxy/orders-meta/teams/create  (via Shopify App Proxy: theme anropar /apps/orders-meta/teams/create)
// Body: { teamName, teamEmail }
// - Skapar ett nytt team-konto (Shopify customer)
// - Sätter teamets metafält (isTeam, teamName, ownerCustomerId, members[owner])
// - Uppdaterar ägarens metafält med memberships[...]
app.post('/proxy/orders-meta/teams/create', async (req, res) => {
  try {
    // 1) Verifiera att anropet kommer via Shopify App Proxy
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }

    // 2) Kräver inloggad kund (ägaren av teamet)
    const loggedInCustomerId = req.query.logged_in_customer_id;
    if (!loggedInCustomerId) {
      return res.status(401).json({ error: 'not_logged_in' });
    }
    const ownerIdStr = String(loggedInCustomerId || '').trim();
    const ownerIdNum = parseInt(ownerIdStr, 10);

    // 3) Läs input från frontend – vi förlitar oss nu på explicit teamEmail
    const teamName = String(req.body?.teamName || '').trim();
    const teamEmailRaw = String(req.body?.teamEmail || '').trim().toLowerCase();

    if (!teamName) {
      return res.status(400).json({ error: 'missing_team_name' });
    }
    if (!teamEmailRaw) {
      return res.status(400).json({ error: 'missing_email_for_team' });
    }
    if (!isValidEmail(teamEmailRaw)) {
      return res.status(400).json({ error: 'invalid_email' });
    }

    const finalTeamEmail = teamEmailRaw;

    // 4) Hämta ägarens e-post (används enbart för members[0].email)
    let ownerEmail = '';
    try {
      const ownerRes = await axios.get(
        `https://${SHOP}/admin/api/2025-07/customers/${ownerIdStr}.json`,
        { headers: { 'X-Shopify-Access-Token': ACCESS_TOKEN } }
      );
      ownerEmail = String(ownerRes.data?.customer?.email || '').trim();
    } catch (e) {
      console.warn('create team: kunde inte läsa ägarens kunddata', e?.response?.data || e.message);
    }

    // 5) Skapa team-kund i Shopify (vanligt customer-konto)
    const createPayload = {
      customer: {
        first_name: teamName,
        email: finalTeamEmail,
        // Hjälp-taggar för admin/översikt – påverkar inte teamlogiken i metafältet
        tags: 'pressify-team',
        note: 'Pressify Teams – teamkonto'
      }
    };

    let createRes;
    try {
      createRes = await axios.post(
        `https://${SHOP}/admin/api/2025-07/customers.json`,
        createPayload,
        {
          headers: {
            'X-Shopify-Access-Token': ACCESS_TOKEN,
            'Content-Type': 'application/json'
          }
        }
      );
    } catch (err) {
      const status = err?.response?.status;
      const data = err?.response?.data;
      console.error('POST /proxy/orders-meta/teams/create create-customer error:', data || err.message);

      // Mappa vanliga Shopify-fel till våra frontend-koder
      if (status === 422 && data && data.errors) {
        const emailErrors = Array.isArray(data.errors.email) ? data.errors.email.join(' ') : String(data.errors.email || '');
        if (/has already been taken/i.test(emailErrors)) {
          return res.status(400).json({ error: 'email_taken' });
        }
        if (/invalid/i.test(emailErrors)) {
          return res.status(400).json({ error: 'invalid_email' });
        }
      }

      return res.status(500).json({ error: 'internal_error' });
    }

    const teamCustomer = createRes.data?.customer;
    if (!teamCustomer || !teamCustomer.id) {
      return res.status(500).json({ error: 'failed_to_create_team_customer' });
    }
    const teamCustomerId = teamCustomer.id;

    // 6) Skriv TEAMS-metafält på TEAM-KONTOT
    // Struktur enligt din modell:
    // {
    //   "isTeam": true,
    //   "teamName": "ICA Maxi",
    //   "ownerCustomerId": 11111,
    //   "members": [
    //     { "customerId": 11111, "email": "agare@...", "role": "owner" }
    //   ]
    // }
    const teamMetaValue = {
      isTeam: true,
      teamName,
      ownerCustomerId: ownerIdNum,
      members: [
        {
          customerId: ownerIdNum,
          email: ownerEmail || finalTeamEmail,
          role: 'owner'
        }
      ]
    };
    await writeCustomerTeams(teamCustomerId, teamMetaValue);

    // 7) Uppdatera TEAMS-metafält på ÄGARENS PERSONLIGA KONTO
    const currentOwnerMeta = await readCustomerTeams(ownerIdNum);
    let ownerValue = currentOwnerMeta.value;
    if (!ownerValue || typeof ownerValue !== 'object') {
      ownerValue = {};
    }

    // Om kontot redan är ett teamkonto ska det inte användas som "personlig" ägare
    if (ownerValue.isTeam) {
      return res.status(400).json({ error: 'owner_is_team_account' });
    }

    if (!Array.isArray(ownerValue.memberships)) {
      ownerValue.memberships = [];
    }

    // Undvik dubbletter om endpointen skulle anropas flera gånger
    const alreadyMember = ownerValue.memberships.some(
      (m) => Number(m.teamCustomerId) === Number(teamCustomerId)
    );

    if (!alreadyMember) {
      const isFirst = ownerValue.memberships.length === 0;
      ownerValue.memberships.push({
        teamCustomerId: teamCustomerId,
        teamName,
        role: 'owner',
        isDefault: isFirst
      });
    }

       await writeCustomerTeams(ownerIdNum, ownerValue);

    // 8) Svar till frontend – UI läser sedan från metafält
    return res.json({
      ok: true,
      team: {
        id: teamCustomerId,
        teamName,
        ownerCustomerId: ownerIdNum
      }
    });
  } catch (err) {
    console.error('POST /proxy/orders-meta/teams/create error:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// NYTT: Bjud in medlemmar till ett befintligt teamkonto
// POST /proxy/orders-meta/teams/invite  (via App Proxy: /apps/orders-meta/teams/invite)
// Body: { teamCustomerId, emails: ["a@...", "b@..."] }
//
// Effekt:
// 1) Alla giltiga mailadresser läggs in i teamets metafält (teamValue.members[])
// 2) För de mailadresser som matchar en befintlig kund uppdateras kundens metafält med memberships[]
app.post('/proxy/orders-meta/teams/invite', async (req, res) => {
  try {
    // 1) Verifiera att anropet kommer via Shopify App Proxy
    if (!verifyAppProxySignature(req.url.split('?')[1] || '')) {
      return res.status(403).json({ error: 'invalid_signature' });
    }

    // 2) Kräver inloggad kund (ägare av teamet)
    const loggedInCustomerIdRaw = req.query.logged_in_customer_id;
    if (!loggedInCustomerIdRaw) {
      return res.status(401).json({ error: 'not_logged_in' });
    }
    const loggedInCustomerId = String(loggedInCustomerIdRaw).split('/').pop();

    const body = req.body || {};

    // 3) Identifiera team-kontot
    const teamCustomerIdRaw =
      body.teamCustomerId ||
      body.team_customer_id ||
      req.query.teamCustomerId ||
      req.query.team_customer_id ||
      null;

    const teamCustomerId = teamCustomerIdRaw
      ? String(teamCustomerIdRaw).split('/').pop()
      : null;

    if (!teamCustomerId) {
      return res.status(400).json({ error: 'missing_team_customer_id' });
    }

    // 4) Plocka ut emails från body
    let emails = Array.isArray(body.emails) ? body.emails : [];
    emails = emails
      .map(e => String(e || '').trim().toLowerCase())
      .filter(Boolean);

    // Ta bort dubbletter
    emails = Array.from(new Set(emails));

    if (!emails.length) {
      return res.status(400).json({ error: 'no_emails' });
    }

    // Extra: filtrera bort uppenbart ogiltiga mail här också
    const validEmails = emails.filter(isValidEmail);
    if (!validEmails.length) {
      return res.status(400).json({ error: 'no_valid_emails' });
    }

    // 5) Läs teamets metafält och kontrollera att inloggad kund är ägare
    const teamMeta = await readCustomerTeams(teamCustomerId);
    const teamValue = teamMeta?.value || null;

    if (!teamValue || !teamValue.isTeam) {
      return res.status(400).json({ error: 'not_a_team_account' });
    }

    if (Number(teamValue.ownerCustomerId) !== Number(loggedInCustomerId)) {
      return res.status(403).json({ error: 'not_team_owner' });
    }

    const members = Array.isArray(teamValue.members) ? teamValue.members.slice() : [];
    const existingEmails = new Set(
      members
        .map(m => String(m && m.email ? m.email : '').trim().toLowerCase())
        .filter(Boolean)
    );

    const added = [];

    // 6) Lägg in alla nya mailadresser som "member" på TEAM-kontot
    validEmails.forEach(email => {
      if (existingEmails.has(email)) return;

      const member = {
        customerId: null, // vi känner inte mottagarens customer-id ännu
        email,
        role: 'member'
      };

      members.push(member);
      existingEmails.add(email);
      added.push(member);
    });

    if (!added.length) {
      return res.json({
        ok: true,
        added: [],
        team: {
          id: teamCustomerId,
          teamName: teamValue.teamName || null
        }
      });
    }

    // 7) Spara uppdaterat team-metakonto
    teamValue.members = members;
    await writeCustomerTeams(teamCustomerId, teamValue);

    // 8) För alla mailadresser vi faktiskt la till: försök koppla mot befintliga kunder
    //    och uppdatera deras personliga metafält med memberships[]
    const addedEmails = added
      .map(m => String(m && m.email ? m.email : '').trim().toLowerCase())
      .filter(Boolean);

    try {
      await syncTeamMembershipForExistingCustomers(
        teamCustomerId,
        teamValue.teamName || null,
        addedEmails
      );
    } catch (e) {
      // Vi loggar men låter själva inbjudan lyckas ändå
      console.error(
        'syncTeamMembershipForExistingCustomers top-level error:',
        e?.response?.data || e.message
      );
    }

    // 9) Svar till frontend – den behöver bara veta att inbjudan är "ok"
    return res.json({
      ok: true,
      added,
      team: {
        id: teamCustomerId,
        teamName: teamValue.teamName || null
      }
    });
  } catch (err) {
    console.error('POST /proxy/orders-meta/teams/invite error:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'internal_error' });
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
    return res.status(500).json({ error: 'Kunde inte hämta projekt' });
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
