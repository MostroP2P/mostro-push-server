# Configuration Guide

## Environment Variables

The server is configured via environment variables. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SERVER_PRIVATE_KEY` | 32-byte hex private key for token decryption | `ccc61d16dfd10fbcca1322fdf5fed6cb1863db4e27030ae164dbcbfcc263154d` |
| `NOSTR_RELAYS` | Comma-separated list of Nostr relay URLs | `wss://relay.mostro.network` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MOSTRO_PUBKEY` | `dbe0b1be...` | Hex pubkey of Mostro daemon to listen for |
| `FIREBASE_PROJECT_ID` | `mostro` | Firebase project ID |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | - | Path to Firebase service account JSON |
| `FCM_ENABLED` | `true` | Enable Firebase Cloud Messaging |
| `UNIFIEDPUSH_ENABLED` | `true` | Enable UnifiedPush support |
| `SERVER_HOST` | `0.0.0.0` | HTTP server bind address |
| `SERVER_PORT` | `8080` | HTTP server port |
| `TOKEN_TTL_HOURS` | `48` | Token expiration time in hours |
| `CLEANUP_INTERVAL_HOURS` | `1` | How often to clean expired tokens |
| `RATE_LIMIT_PER_MINUTE` | `60` | Max requests per minute |
| `BATCH_DELAY_MS` | `5000` | Batch delay for notifications |
| `COOLDOWN_MS` | `60000` | Cooldown between batches |
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |

---

## Generating a Server Private Key

Generate a secure random 32-byte hex key:

```bash
openssl rand -hex 32
```

Output example:
```
ccc61d16dfd10fbcca1322fdf5fed6cb1863db4e27030ae164dbcbfcc263154d
```

**Important**: Keep this key secret! Anyone with this key can decrypt device tokens.

---

## Firebase Configuration

### 1. Create Service Account

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your project
3. Go to **Project Settings** → **Service accounts**
4. Click **Generate new private key**
5. Save the JSON file securely

### 2. Configure Server

```bash
# Create secrets directory
mkdir -p secrets

# Move service account file
mv ~/Downloads/your-project-firebase-adminsdk-xxxxx.json secrets/service-account.json

# Add to .gitignore
echo "secrets/" >> .gitignore
```

### 3. Set Environment Variable

```bash
FIREBASE_SERVICE_ACCOUNT_PATH=./secrets/service-account.json
FIREBASE_PROJECT_ID=your-project-id
```

---

## Example .env File

```bash
# Nostr Configuration
NOSTR_RELAYS=wss://relay.mostro.network
MOSTRO_PUBKEY=0a537332f2d569059add3fd2e376e1d6b8c1e1b9f7a999ac2592b4afbba74a00

# Server Keypair (KEEP SECRET!)
SERVER_PRIVATE_KEY=ccc61d16dfd10fbcca1322fdf5fed6cb1863db4e27030ae164dbcbfcc263154d

# Firebase Configuration
FIREBASE_PROJECT_ID=mostro-test
FIREBASE_SERVICE_ACCOUNT_PATH=./secrets/service-account.json
FCM_ENABLED=true

# UnifiedPush
UNIFIEDPUSH_ENABLED=false

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Token Store
TOKEN_TTL_HOURS=48
CLEANUP_INTERVAL_HOURS=1

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
BATCH_DELAY_MS=5000
COOLDOWN_MS=60000

# Logging
RUST_LOG=info
```

---

## Client Configuration

The mobile client needs to know:

1. **Push Server URL**: Where to register tokens
2. **Server Public Key**: Fetched from `/api/info` endpoint

### Flutter Client (config.dart)

```dart
class Config {
  // Push notification server
  static const String pushServerUrl = String.fromEnvironment(
    'PUSH_SERVER_URL',
    defaultValue: 'https://push.mostro.network',
  );
}
```

For local testing:
```dart
defaultValue: 'http://192.168.1.7:8080',
```

---

## Firewall Configuration

If running locally and testing from a mobile device on the same network:

```bash
# Allow incoming connections on port 8080
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT

# Or with ufw
sudo ufw allow 8080/tcp
```

---

## Logging

Control log verbosity with `RUST_LOG`:

```bash
# Minimal logging
RUST_LOG=warn

# Standard logging
RUST_LOG=info

# Debug logging (includes token operations)
RUST_LOG=debug

# Trace logging (very verbose)
RUST_LOG=trace

# Module-specific logging
RUST_LOG=mostro_push_backend=debug,actix_web=info
```

---

## Production Checklist

- [ ] Generate unique `SERVER_PRIVATE_KEY`
- [ ] Configure Firebase service account
- [ ] Set `RUST_LOG=info` or `warn`
- [ ] Use HTTPS (reverse proxy with nginx/caddy)
- [ ] Set appropriate `TOKEN_TTL_HOURS`
- [ ] Configure firewall rules
- [ ] Set up monitoring/alerting
- [ ] Backup server private key securely
