# API Reference

## Base URL

```
http://localhost:8080/api
```

## Current Phase: Phase 3 (Unencrypted)

Token registration currently accepts plaintext tokens. Encryption will be added in Phase 4.

## Endpoints

### Health Check

Check if the server is running.

```http
GET /api/health
```

**Response**
```json
{
  "status": "ok"
}
```

---

### Server Info

Get server version and encryption status.

```http
GET /api/info
```

**Response (Phase 3 - Unencrypted)**
```json
{
  "version": "0.2.0",
  "encryption_enabled": false,
  "note": "Token encryption will be enabled in a future phase"
}
```

**Response (Phase 4 - Encrypted, Future)**
```json
{
  "server_pubkey": "02b0b5fbc14b11279c415601e74c592b86a54cef4cfdd7b6e60382db83e68855c7",
  "version": "0.3.0",
  "encryption_enabled": true,
  "encrypted_token_size": 281
}
```

---

### Server Status

Get server status including token statistics.

```http
GET /api/status
```

**Response**
```json
{
  "status": "running",
  "version": "0.2.0",
  "tokens": {
    "total": 5,
    "android": 3,
    "ios": 2
  }
}
```

---

### Register Token

Register a device token for a specific trade.

```http
POST /api/register
Content-Type: application/json
```

**Request Body (Phase 3 - Plaintext)**
```json
{
  "trade_pubkey": "a1b2c3d4e5f6...64 hex chars...",
  "token": "fcm-device-token-string",
  "platform": "android"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `trade_pubkey` | string | 64-character hex public key of the trade |
| `token` | string | FCM/APNs device token |
| `platform` | string | `"android"` or `"ios"` |

**Success Response (200)**
```json
{
  "success": true,
  "message": "Token registered successfully",
  "platform": "android"
}
```

**Error Response (400)**
```json
{
  "success": false,
  "message": "Invalid trade_pubkey format (expected 64 hex characters)",
  "platform": null
}
```

**Possible Errors**
| Error | Description |
|-------|-------------|
| Invalid trade_pubkey format | Not 64 hex characters |
| Token cannot be empty | Empty token string provided |
| Invalid platform | Platform not "android" or "ios" |

---

### Unregister Token

Remove a registered token for a trade.

```http
POST /api/unregister
Content-Type: application/json
```

**Request Body**
```json
{
  "trade_pubkey": "a1b2c3d4e5f6...64 hex chars..."
}
```

**Success Response (200)**
```json
{
  "success": true,
  "message": "Token unregistered successfully"
}
```

**Not Found Response (200)**
```json
{
  "success": true,
  "message": "Token not found (may have already been unregistered)"
}
```

---

## Example: cURL

### Get Server Info
```bash
curl http://localhost:8080/api/info
```

### Register Token (Phase 3 - Plaintext)
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "trade_pubkey": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
    "token": "dMw5ABC123:APA91bHtest-fcm-token-here",
    "platform": "android"
  }'
```

### Unregister Token
```bash
curl -X POST http://localhost:8080/api/unregister \
  -H "Content-Type: application/json" \
  -d '{
    "trade_pubkey": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
  }'
```

### Check Status
```bash
curl http://localhost:8080/api/status
```

---

## Error Codes

| HTTP Status | Meaning |
|-------------|---------|
| 200 | Success |
| 400 | Bad Request - Invalid input |
| 500 | Internal Server Error |

All responses are JSON with `Content-Type: application/json`.

---

## Phase 4: Encrypted Token Format (Future)

When encryption is enabled in Phase 4, the register endpoint will accept encrypted tokens:

**Request Body (Phase 4 - Encrypted)**
```json
{
  "trade_pubkey": "a1b2c3d4e5f6...64 hex chars...",
  "encrypted_token": "base64_encoded_encrypted_token"
}
```

The `encrypted_token` field will contain a base64-encoded blob with the following structure:

```
┌─────────────────────┬────────────┬─────────────────────────────────┐
│ Ephemeral Pubkey    │   Nonce    │          Ciphertext             │
│     (33 bytes)      │ (12 bytes) │  (220 + 16 = 236 bytes)         │
└─────────────────────┴────────────┴─────────────────────────────────┘
```

See [cryptography.md](./cryptography.md) for the full encryption specification.
