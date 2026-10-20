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
  return jwt.sign({ sub: String(
