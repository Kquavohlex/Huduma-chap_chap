require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { z } = require('zod');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('FATAL: Set JWT_SECRET to a random secret of at least 32 characters.');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('FATAL: Set DATABASE_URL to a PostgreSQL connection string.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const SERVICES = [
  ['Passport application assistance','Government','Guidance with the official passport application process.'],
  ['Visa application assistance','Travel','Guidance preparing information for a visa application.'],
  ['Birth certificate assistance','Government','Guidance on the official birth certificate process.'],
  ['Certificate of Good Conduct assistance','Government','Guidance with the official police clearance application.'],
  ['National ID assistance','Government','Guidance on available official national ID services.'],
  ['KRA PIN assistance','Government','Guidance with KRA PIN registration and account services.'],
  ['KRA tax returns assistance','Government','Help preparing information for eligible tax-return filing.'],
  ['Business registration assistance','Business','Guidance through the official business registration process.'],
  ['NTSA services assistance','Transport','Guidance navigating official NTSA services.'],
  ['HELB services assistance','Education','Guidance navigating available HELB services.'],
  ['Travel medical appointment assistance','Travel','Help arranging a travel medical appointment where available.'],
  ['Travel document assistance','Travel','Guidance preparing travel-related documents.'],
  ['Printing services','Cyber','Document printing service request.'],
  ['Scanning and PDF services','Cyber','Document scanning and PDF preparation.'],
  ['Typing and document formatting','Cyber','Typing and formatting documents.'],
  ['CV and application letter preparation','Career','Help preparing a CV or application letter.'],
  ['Online job application assistance','Career','Guidance submitting an online job application.'],
  ['Passport-size photo service','Cyber','Passport-size photo service, subject to required specifications.']
].map(([name, category, description]) => ({ name, category, description, price: 500 }));

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));

// Enable CORS for cross-origin frontend requests (e.g. GitHub Pages) with cookies/credentials support
const allowedOrigins = [
  process.env.APP_BASE_URL,
  'https://kquavohlex.github.io',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) || !isProd) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '30kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      wallet_balance BIGINT NOT NULL DEFAULT 0 CHECK (wallet_balance >= 0),
      referral_code TEXT NOT NULL UNIQUE,
      referred_by BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL CHECK (type IN ('deposit','service_charge','refund','adjustment')),
      amount BIGINT NOT NULL CHECK (amount > 0),
      status TEXT NOT NULL CHECK (status IN ('pending','completed','failed')),
      reference TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL,
      provider_reference TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      completed_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS wallet_transactions_user_created_idx ON wallet_transactions(user_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS service_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      service_name TEXT NOT NULL,
      price BIGINT NOT NULL CHECK (price = 500),
      details TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'received' CHECK (status IN ('received','in_progress','completed','cancelled')),
      charge_reference TEXT NOT NULL UNIQUE REFERENCES wallet_transactions(reference),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS service_requests_user_created_idx ON service_requests(user_id, created_at DESC);
  `);
}

function makeToken(user) {
  return jwt.sign({ sub: String(user.id), email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function setAuthCookie(res, token) {
  res.cookie('hcc_session', token, {
    httpOnly: true,
    secure: true, // Required for cross-site cookies in modern browsers
    sameSite: 'none', // Allows cross-site cookie passing between GitHub Pages and Render
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

async function auth(req, res, next) {
  try {
    const token = req.cookies.hcc_session;
    if (!token) return res.status(401).json({ error: 'Please log in to continue.' });
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT id,name,email,phone,wallet_balance,referral_code,created_at FROM users WHERE id=$1', [payload.sub]);
    if (!result.rowCount) return res.status(401).json({ error: 'Account not found. Please log in again.' });
    req.user = result.rows[0];
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Your session has expired. Please log in again.' });
  }
}

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, phone: u.phone, walletBalance: Number(u.wallet_balance), referralCode: u.referral_code, createdAt: u.created_at };
}

function normalizePhone(phone) {
  let p = String(phone || '').replace(/[\s()+-]/g, '');
  if (p.startsWith('0')) p = '254' + p.slice(1);
  if (p.startsWith('+')) p = p.slice(1);
  if (!/^254[17]\d{8}$/.test(p)) throw new Error('Enter a valid Kenyan mobile number, for example 0712345678.');
  return p;
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'Huduma Chap Chap API' }));
app.get('/api/services', (_req, res) => res.json({ services: SERVICES }));

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const data = z.object({ name: z.string().trim().min(2).max(100), email: z.string().trim().email().max(254), phone: z.string().min(9).max(20), password: z.string().min(10).max(128), referralCode: z.string().trim().max(30).optional().default('') }).parse(req.body);
    const email = data.email.toLowerCase();
    const phone = normalizePhone(data.phone);
    const passwordHash = await bcrypt.hash(data.password, 12);
    const referral = crypto.randomBytes(5).toString('hex').toUpperCase();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      let referrerId = null;
      if (data.referralCode) {
        const r = await client.query('SELECT id FROM users WHERE referral_code=$1', [data.referralCode.toUpperCase()]);
        if (r.rowCount) referrerId = r.rows[0].id;
      }
      const result = await client.query('INSERT INTO users(name,email,phone,password_hash,referral_code,referred_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,email,phone,wallet_balance,referral_code,created_at', [data.name, email, phone, passwordHash, referral, referrerId]);
      await client.query('COMMIT');
      setAuthCookie(res, makeToken(result.rows[0]));
      res.status(201).json({ user: publicUser(result.rows[0]) });
    } catch (e) { await client.query('ROLLBACK'); if (e.code === '23505') return res.status(409).json({ error: 'An account with this email already exists.' }); throw e; }
    finally { client.release(); }
  } catch (e) { if (e instanceof z.ZodError) return res.status(400).json({ error: 'Check your name, email, phone and password. Password must be at least 10 characters.' }); if (e.message.startsWith('Enter a valid')) return res.status(400).json({ error: e.message }); next(e); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const data = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(128) }).parse(req.body);
    const result = await pool.query('SELECT id,name,email,phone,password_hash,wallet_balance,referral_code,created_at FROM users WHERE email=$1', [data.email.toLowerCase()]);
    if (!result.rowCount || !(await bcrypt.compare(data.password, result.rows[0].password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    const user = result.rows[0]; 
    setAuthCookie(res, makeToken(user)); 
    res.json({ user: publicUser(user) });
  } catch (e) { if (e instanceof z.ZodError) return res.status(400).json({ error: 'Enter a valid email and password.' }); next(e); }
});

app.post('/api/auth/logout', (_req, res) => { 
  res.clearCookie('hcc_session', { httpOnly: true, secure: true, sameSite: 'none', path: '/' }); 
  res.json({ ok: true }); 
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.get('/api/wallet', auth, async (req, res, next) => {
  try {
    const tx = await pool.query("SELECT id,type,amount,status,reference,description,created_at FROM wallet_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 25", [req.user.id]);
    res.json({ balance: Number(req.user.wallet_balance), transactions: tx.rows.map(t => ({ ...t, amount: Number(t.amount) })) });
  } catch (e) { next(e); }
});

app.post('/api/wallet/deposit', auth, async (req, res, next) => {
  const client = await pool.connect();
  let reference;
  try {
    const data = z.object({ amount: z.coerce.number().int().min(50).max(70000), phone: z.string().min(9).max(20) }).parse(req.body);
    const msisdn = normalizePhone(data.phone);
    const username = process.env.TINYPESA_USERNAME;
    const apiKey = process.env.TINYPESA_LINK_API_KEY;
    if (!username || !apiKey) return res.status(503).json({ error: 'M-Pesa deposits are not configured yet. The site owner must add Tinypesa credentials.' });
    reference = 'HCC' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
    await client.query('INSERT INTO wallet_transactions(user_id,type,amount,status,reference,description) VALUES($1,\'deposit\',$2,\'pending\',$3,$4)', [req.user.id, data.amount, reference, 'M-Pesa wallet deposit']);
    const url = `${(process.env.TINYPESA_API_URL || 'https://api.tinypesa.com/api/v1').replace(/\/$/,'')}/express/initialize/?username=${encodeURIComponent(username)}`;
    let providerResponse;
    try {
      const response = await fetch(url, { method: 'POST', headers: { 'Accept':'application/json','Content-Type':'application/json','Apikey':apiKey }, body: JSON.stringify({ amount: data.amount, msisdn, account_no: reference }), signal: AbortSignal.timeout(15000) });
      providerResponse = await response.json().catch(() => ({}));
      if (!response.ok || providerResponse.success === false) throw new Error(providerResponse.message || `Tinypesa returned HTTP ${response.status}`);
    } catch (e) {
      await pool.query("UPDATE wallet_transactions SET status='failed' WHERE reference=$1 AND status='pending'", [reference]);
      return res.status(502).json({ error: 'Could not start the M-Pesa prompt. Check the phone number or try again.', detail: isProd ? undefined : e.message });
    }
    const providerId = providerResponse.request_id || providerResponse.TinyPesaID || null;
    if (providerId) await pool.query('UPDATE wallet_transactions SET provider_reference=$1 WHERE reference=$2', [String(providerId), reference]);
    res.status(202).json({ message: 'M-Pesa prompt initiated. Enter your M-Pesa PIN on your phone. Your wallet is credited only after payment verification.', reference, providerRequestId: providerId });
  } catch (e) { if (e instanceof z.ZodError) return res.status(400).json({ error: 'Enter a deposit amount between KSh 50 and KSh 70,000 and a valid phone number.' }); if (e.message.startsWith('Enter a valid')) return res.status(400).json({ error: e.message }); next(e); }
  finally { client.release(); }
});

app.post('/api/payments/tinypesa', async (req, res) => {
  res.status(200).json({ received: true });
  try {
    const body = req.body || {};
    const reference = String(body.ExternalReference || body.external_reference || body.account_no || '').trim();
    const resultCode = body.ResultCode ?? body.result_code;
    if (!reference || String(resultCode) !== '0') return;
    const pending = await pool.query("SELECT id,user_id,amount,status FROM wallet_transactions WHERE reference=$1 AND type='deposit'", [reference]);
    if (!pending.rowCount || pending.rows[0].status !== 'pending') return;
    const username = process.env.TINYPESA_USERNAME, apiKey = process.env.TINYPESA_LINK_API_KEY;
    if (!username || !apiKey) return;
    const statusUrl = `${(process.env.TINYPESA_API_URL || 'https://api.tinypesa.com/api/v1').replace(/\/$/,'')}/express/get_status/${encodeURIComponent(reference)}/?username=${encodeURIComponent(username)}`;
    const verifyResponse = await fetch(statusUrl, { headers: { 'Accept':'application/json','Apikey':apiKey }, signal: AbortSignal.timeout(12000) });
    if (!verifyResponse.ok) return;
    const verified = await verifyResponse.json();
    if (verified.is_complete !== true) return;
    const verifiedAmount = Math.round(Number(verified.amount));
    if (!Number.isFinite(verifiedAmount) || verifiedAmount !== Number(pending.rows[0].amount)) return;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const tx = await client.query("SELECT id,user_id,amount,status FROM wallet_transactions WHERE reference=$1 AND type='deposit' FOR UPDATE", [reference]);
      if (!tx.rowCount || tx.rows[0].status !== 'pending') { await client.query('ROLLBACK'); return; }
      const amount = Number(tx.rows[0].amount);
      await client.query('UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2', [amount, tx.rows[0].user_id]);
      await client.query("UPDATE wallet_transactions SET status='completed',provider_reference=COALESCE(provider_reference,$1),completed_at=NOW() WHERE id=$2", [String(body.TinyPesaID || verified.id || ''), tx.rows[0].id]);
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); console.error('Tinypesa credit transaction failed:', e.message); }
    finally { client.release(); }
  } catch (e) { console.error('Tinypesa callback verification failed:', e.message); }
});

app.post('/api/enquiries', auth, async (req, res, next) => {
  const parsed = z.object({ serviceName: z.string().min(2).max(150), details: z.string().max(2000).optional().default('') }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Select a valid service and keep details under 2,000 characters.' });
  const service = SERVICES.find(s => s.name === parsed.data.serviceName);
  if (!service) return res.status(400).json({ error: 'That service is not available.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userResult = await client.query('SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
    if (!userResult.rowCount) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Please log in again.' }); }
    const balance = Number(userResult.rows[0].wallet_balance);
    if (balance < 500) { await client.query('ROLLBACK'); return res.status(402).json({ error: 'Insufficient wallet balance. Please deposit at least KSh 500 to enquire about this service.', required: 500, balance }); }
    const reference = 'SVC-' + crypto.randomBytes(10).toString('hex').toUpperCase();
    await client.query('UPDATE users SET wallet_balance=wallet_balance-500 WHERE id=$1', [req.user.id]);
    await client.query("INSERT INTO wallet_transactions(user_id,type,amount,status,reference,description,completed_at) VALUES($1,'service_charge',500,'completed',$2,$3,NOW())", [req.user.id, reference, `Service enquiry: ${service.name}`]);
    const result = await client.query('INSERT INTO service_requests(user_id,service_name,price,details,charge_reference) VALUES($1,$2,500,$3,$4) RETURNING id,service_name,price,details,status,created_at', [req.user.id, service.name, parsed.data.details.trim(), reference]);
    const updated = await client.query('SELECT wallet_balance FROM users WHERE id=$1', [req.user.id]);
    await client.query('COMMIT');
    res.status(201).json({ message: 'Enquiry submitted successfully. KSh 500 has been deducted from your wallet.', request: result.rows[0], balance: Number(updated.rows[0].wallet_balance) });
  } catch (e) { await client.query('ROLLBACK'); next(e); }
  finally { client.release(); }
});

app.get('/api/enquiries', auth, async (req, res, next) => {
  try { const result = await pool.query('SELECT id,service_name,price,details,status,created_at FROM service_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user.id]); res.json({ requests: result.rows }); }
  catch (e) { next(e); }
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, _req, res, _next) => {
  console.error(err.stack || err.message || err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

initDb().then(() => app.listen(PORT, () => console.log(`Huduma Chap Chap listening on port ${PORT}`))).catch(err => { console.error('Database initialization failed:', err); process.exit(1); });
