# Huduma Chap Chap — real backend starter

This project includes a client-facing website, Express backend, PostgreSQL database tables, secure password hashing, HTTP-only login cookies, server-side KSh 500 service charges, and a Tinypesa STK Push deposit flow.

## What is implemented

- Server-backed account registration/login (bcrypt password hashing; HTTP-only JWT cookie).
- PostgreSQL persistence for users, balances, wallet transactions, and service requests.
- All 18 services have a server-defined price of KSh 500.
- Enquiries use a PostgreSQL transaction and row lock. The server rejects insufficient balances and atomically deducts KSh 500 plus creates the service request and ledger row.
- Deposit initiation calls Tinypesa from the backend. API keys are never sent to the browser.
- Tinypesa callback is acknowledged, then verified server-to-server using Tinypesa's transaction-status endpoint and the unique `account_no` reference before crediting the wallet. Amount must match the pending transaction; completed deposits cannot be credited twice.
- Client dashboard shows balance, wallet activity, and requests.

## Not yet implemented / credentials needed

- This code has not been deployed or live-tested with your Tinypesa account. It is not live until you deploy it, provision PostgreSQL, and configure valid Tinypesa credentials and callback settings.
- You must complete Tinypesa onboarding/KYC as required and obtain your **link username** and **link API key**.
- Configure the callback/IPN URL in the Tinypesa dashboard to `https://YOUR-PUBLIC-DOMAIN/api/payments/tinypesa`. The callback URL is configured on the Tinypesa link/IPN, not passed in the STK initialize body.
- The app does not implement withdrawals, automatic referral payouts, admin panel, refunds, SMS/email notifications, or government-agency API integrations.
- A successful KSh 500 enquiry charge is this website's service fee; official government fees, where applicable, are separate and should be disclosed to clients.
- The Tinypesa docs say callbacks do not have an HMAC/signature header. This implementation independently checks the status with Tinypesa and reconciles the reference and amount before crediting, but you should monitor payment events and test thoroughly before accepting customers' money.

## Run locally

1. Install Node.js 20+ and PostgreSQL.
2. Create a PostgreSQL database named `huduma_chap_chap`.
3. Copy `.env.example` to `.env` and set `DATABASE_URL`, a long random `JWT_SECRET`, and your Tinypesa values.
4. Run `npm install`.
5. Run `npm start`.
6. Open `http://localhost:3000`.

The server creates its database tables automatically on startup. For local use, set `DATABASE_SSL=false`. Do not commit `.env` or share API keys in screenshots/chats.

## Deploy for a beginner (Render + PostgreSQL)

1. Create a GitHub repository and upload the contents of this project (not the ZIP itself). Ensure `.env` is not uploaded.
2. In Render, create a managed PostgreSQL database. Copy its **Internal Database URL** if the web service will use the same Render region; otherwise use the External URL and TLS as instructed by Render.
3. Create a Render **Web Service** connected to your GitHub repository. Runtime: Node. Build command: `npm install`. Start command: `npm start`.
4. Add environment variables in Render → service → Environment:
   - `NODE_ENV` = `production`
   - `DATABASE_URL` = the PostgreSQL connection string
   - `DATABASE_SSL` = `true` if required by your database provider
   - `JWT_SECRET` = a long random secret (32+ characters)
   - `APP_BASE_URL` = your exact public site URL, e.g. `https://your-service.onrender.com`
   - `TINYPESA_API_URL` = `https://api.tinypesa.com/api/v1`
   - `TINYPESA_USERNAME` = your Tinypesa link username
   - `TINYPESA_LINK_API_KEY` = your Tinypesa link API key
5. Deploy. Open `https://YOUR-SERVICE.onrender.com/api/health`; it should return `{"ok":true,...}`.
6. In Tinypesa dashboard, configure the link's callback URL/IPN to `https://YOUR-SERVICE.onrender.com/api/payments/tinypesa`. The callback must be publicly reachable over HTTPS.
7. Test with a small deposit and verify the wallet transaction before inviting customers. Make sure your Tinypesa link is configured to receive the payments and its KYC/limits permit your intended use.
8. Keep your database on a persistent managed service and understand its pricing/backups. Do not rely on an ephemeral filesystem for balances.

## Important security and product notes

- The app does not collect or store M-Pesa PINs.
- Wallet balance changes are made only by the server.
- Use HTTPS in production. Never publish `.env`, API keys, or database passwords.
- The callback has no documented signature. Verification is server-to-server against Tinypesa's status API, but this is still a payment integration that needs live end-to-end testing and monitoring.
- This is a backend starter, not a substitute for a security review, business compliance, clear terms/refund policy, privacy notice, or testing with your exact Tinypesa account.
