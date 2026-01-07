````md
# ESH ENC Server (Encryption & Password Service)

A hardened **Node.js/Express** backend used by **UltraShop / ESH** to:
- **Encrypt / decrypt** payloads (AES) for store-related data
- **Encrypt / decrypt IPFS payloads** with a dedicated secret
- **Register wallet addresses** and issue a **16-digit password**
- **Verify passwords** for gated actions
- Provide **health monitoring**, **rate limiting**, **CORS allowlist**, and **security headers**

> ⚠️ **Important:** This server is protected by an `x-api-key` header. Every request must include a valid API key.

---

## Features

- **AES encryption/decryption** via `crypto-js`
- **Two encryption modes**
  - `type: "ipfs"` — uses `IPFS_ENC` secret
  - default mode — derives a key from `ULTIMATEDEAL_STORE_SECRETKEY` (SHA256)
- **Address registration**
  - Registers a store address once
  - Generates a **16-digit password** stored in `passwords.json`
- **Password verification endpoint**
- **Security & Stability**
  - `helmet` security headers + strict CSP
  - `express-rate-limit` with Cloudflare-aware IP resolution
  - CORS allowlist
  - request + connection tracking
  - winston logging to console + files (`error.log`, `combined.log`)
  - graceful shutdown + automatic restart backoff

---

## API Authentication

All routes require:

- Header: `x-api-key: <YOUR_API_KEY>`

If missing/invalid → `401 Unauthorized`.

---

## Endpoints

### `GET /health`
Returns server state, memory usage, active connections, and request counters.

**Response includes:**
- uptime / startTime
- memory usage
- active connections
- total/failed requests
- last errors
- serverState info

---

### `POST /api/encrypt`
Encrypts `data` and returns `encryptedData`.

#### 1) IPFS mode
**Body**
```json
{
  "type": "ipfs",
  "data": "any string"
}
````

**Response**

```json
{ "encryptedData": "..." }
```

#### 2) Default mode (address-based)

**Body**

```json
{
  "data": "any string",
  "address1": "0x...",
  "address2": "0x..."
}
```

**Response**

```json
{ "encryptedData": "..." }
```

> Notes:
>
> * `address1` and `address2` must be valid Ethereum addresses.
> * Result is returned as Base64 wrapping an AES string.

---

### `POST /api/decrypt`

Decrypts `encryptedData` and returns `decryptedData`.

#### 1) IPFS mode

**Body**

```json
{
  "type": "ipfs",
  "encryptedData": "..."
}
```

**Response**

```json
{ "decryptedData": "original string" }
```

#### 2) Default mode (address-based)

**Body**

```json
{
  "encryptedData": "...",
  "address1": "0x...",
  "address2": "0x..."
}
```

**Response**

```json
{ "decryptedData": "original string" }
```

#### 3) Password-gated mode (`type: "default"`)

Requires a valid 16-digit password registered for `address2`.

**Body**

```json
{
  "type": "default",
  "encryptedData": "...",
  "address1": "0x...",
  "address2": "0x...",
  "password": "1234567890123456"
}
```

**Response**

```json
{ "decryptedData": "original string" }
```

If password mismatch:

```json
{ "error": "Invalid password for the given address" }
```

---

### `POST /api/register-address`

Registers an address and returns a 16-digit password.

**Body**

```json
{
  "address": "0x..."
}
```

**Response**

```json
{
  "success": true,
  "address": "0x...",
  "password": "1234567890123456"
}
```

If already registered:

```json
{ "error": "Address already registered" }
```

---

### `POST /api/verify-password`

Verifies a password for an address.

**Body**

```json
{
  "address": "0x...",
  "password": "1234567890123456"
}
```

**Response**

```json
{ "valid": true }
```

---

## Allowed Origins (CORS)

This server only allows requests from:

* `http://localhost:5173`
* `https://www.your-website.com`
* `https://your-website.com`

Any other origin → `403` with a CORS error.

---

## Setup

### 1) Install

```bash
npm install
```

### 2) Environment Variables

Create a `.env` file:

```bash
# Server
PORT=3000
NODE_ENV=production

# Required - API auth
API_KEY=change_me_to_a_strong_key

# Required - used for IPFS encryption mode
IPFS_ENC=IPFS-enc-secret-key

# Required - used for default encryption key derivation
ULTIMATEDEAL_STORE_SECRETKEY=your-enc-secret-key-from-email-server-must-be-the-same
```

**Never commit `.env`**.

---

## Run

### Development

```bash
node encserver.js
```

### Production (recommended)

```bash
use run.bat to run the server on cloudflare
```

---

## Logs

* `combined.log` — all logs
* `error.log` — error-only logs

Both files are capped at **5MB** and rotate up to **5 files**.

---

## Files

* `passwords.json`

  * Auto-created if missing
  * Stores `{ [lowercasedAddress]: "16-digit-password" }`

> ⚠️ Keep this file secure. Anyone with access can validate passwords.

---

## Security Notes

* Always use HTTPS behind a reverse proxy (Cloudflare / Nginx).
* Keep `API_KEY`, `IPFS_ENC`, and `ULTIMATEDEAL_STORE_SECRETKEY` private.
* Consider moving `passwords.json` to a database for multi-instance deployments.
* Current server binds to `127.0.0.1` (localhost). For remote access behind a proxy, you may need to bind to `0.0.0.0`.

---

## Example cURL

### Health

```bash
curl -H "x-api-key: YOUR_KEY" http://127.0.0.1:3000/health
```

### Encrypt (default)

```bash
curl -X POST http://127.0.0.1:3000/api/encrypt \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_KEY" \
  -d '{"data":"hello","address1":"0x1111111111111111111111111111111111111111","address2":"0x2222222222222222222222222222222222222222"}'
```

### Decrypt (default)

```bash
curl -X POST http://127.0.0.1:3000/api/decrypt \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_KEY" \
  -d '{"encryptedData":"...","address1":"0x1111111111111111111111111111111111111111","address2":"0x2222222222222222222222222222222222222222"}'
```

### Register Address

```bash
curl -X POST http://127.0.0.1:3000/api/register-address \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_KEY" \
  -d '{"address":"0x2222222222222222222222222222222222222222"}'
```

### Verify Password

```bash
curl -X POST http://127.0.0.1:3000/api/verify-password \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_KEY" \
  -d '{"address":"0x2222222222222222222222222222222222222222","password":"1234567890123456"}'
```

---

## License

MIT.

```
```
