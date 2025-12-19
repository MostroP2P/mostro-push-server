# API Reference

## Base URL

```
http://localhost:8080/api
```

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

Get server public key and version. The public key is needed by clients to encrypt tokens.

```http
GET /api/info
```

**Response**
```json
{
  "server_pubkey": "02b0b5fbc14b11279c415601e74c592b86a54cef4cfdd7b6e60382db83e68855c7",
  "version": "0.2.0",
  "encrypted_token_size": 281
}
```

| Field | Type | Description |
|-------|------|-------------|
| `server_pubkey` | string | Compressed secp256k1 public key (33 bytes, hex encoded) |
| `version` | string | Server version |
| `encrypted_token_size` | number | Expected size of encrypted token in bytes |

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
  "server_pubkey": "02b0b5fbc14b11279c415601e74c592b86a54cef4cfdd7b6e60382db83e68855c7",
  "tokens": {
    "total": 5,
    "android": 3,
    "ios": 2
  }
}
```

---

### Register Token

Register an encrypted device token for a specific trade.

```http
POST /api/register
Content-Type: application/json
```

**Request Body**
```json
{
  "trade_pubkey": "a1b2c3d4e5f6...64 hex chars...",
  "encrypted_token": "base64_encoded_encrypted_token"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `trade_pubkey` | string | 64-character hex public key of the trade |
| `encrypted_token` | string | Base64-encoded encrypted token (281 bytes when decoded) |

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
| Invalid base64 encoding | encrypted_token is not valid base64 |
| Invalid encrypted token size | Decoded token is not 281 bytes |
| Failed to decrypt token | Decryption failed (wrong key, corrupted data) |
| Invalid platform identifier | Platform byte not recognized |

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

## Encrypted Token Format

The `encrypted_token` field must contain a base64-encoded blob with the following structure:

```
┌─────────────────────┬────────────┬─────────────────────────────────┐
│ Ephemeral Pubkey    │   Nonce    │          Ciphertext             │
│     (33 bytes)      │ (12 bytes) │  (220 + 16 = 236 bytes)         │
└─────────────────────┴────────────┴─────────────────────────────────┘
                                            │
                                            ▼
                              ┌─────────────────────────────┐
                              │   Decrypted Payload         │
                              │   (220 bytes, padded)       │
                              ├─────────────────────────────┤
                              │ Platform (1 byte)           │
                              │ Token Length (2 bytes, BE)  │
                              │ Device Token (variable)     │
                              │ Random Padding (remainder)  │
                              └─────────────────────────────┘
```

**Total Size**: 33 + 12 + 220 + 16 = **281 bytes**

**Platform Byte Values**
| Value | Platform |
|-------|----------|
| 0x01 | iOS |
| 0x02 | Android |

---

## Example: cURL

### Get Server Info
```bash
curl http://localhost:8080/api/info
```

### Register Token
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "trade_pubkey": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
    "encrypted_token": "Aq0LX7wUsREnwUVgHnTFkrhqVc70z917bmA4LbgOaIVcxwAAAAAAAAAAAA..."
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
