# Deployment Guide

## Prerequisites

- Rust 1.70+ installed
- Firebase project with Cloud Messaging enabled
- Access to Nostr relay(s)

## Building for Production

```bash
# Clone repository
git clone https://github.com/MostroP2P/mostro-push-server.git
cd mostro-push-server

# Build release binary
cargo build --release

# Binary location
ls -la target/release/mostro-push-backend
```

## Configuration

### 1. Generate Server Keys

```bash
# Generate a secure private key
openssl rand -hex 32 > server_private_key.txt

# View the key (keep this secret!)
cat server_private_key.txt
```

### 2. Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create or select a project
3. Enable Cloud Messaging
4. Go to **Project Settings** → **Service accounts**
5. Click **Generate new private key**
6. Save the JSON file

```bash
mkdir -p /etc/mostro-push/secrets
mv ~/Downloads/firebase-adminsdk-*.json /etc/mostro-push/secrets/service-account.json
chmod 600 /etc/mostro-push/secrets/service-account.json
```

### 3. Create Environment File

```bash
cat > /etc/mostro-push/.env << 'EOF'
# Nostr
NOSTR_RELAYS=wss://relay.mostro.network
MOSTRO_PUBKEY=dbe0b1be7aafd3cfba92d7463571bf438f09d24f4e021d9fe208ed0ab5823711

# Server Keys
SERVER_PRIVATE_KEY=<your-generated-key>

# Firebase
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_SERVICE_ACCOUNT_PATH=/etc/mostro-push/secrets/service-account.json
FCM_ENABLED=true

# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=8080

# Token Store
TOKEN_TTL_HOURS=48
CLEANUP_INTERVAL_HOURS=1

# Logging
RUST_LOG=info
EOF

chmod 600 /etc/mostro-push/.env
```

## Systemd Service

Create `/etc/systemd/system/mostro-push.service`:

```ini
[Unit]
Description=Mostro Push Notification Server
After=network.target

[Service]
Type=simple
User=mostro
Group=mostro
WorkingDirectory=/opt/mostro-push
ExecStart=/opt/mostro-push/mostro-push-backend
EnvironmentFile=/etc/mostro-push/.env
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/mostro-push/data

[Install]
WantedBy=multi-user.target
```

### Install and Start

```bash
# Create user
sudo useradd -r -s /bin/false mostro

# Create directories
sudo mkdir -p /opt/mostro-push/data
sudo chown -R mostro:mostro /opt/mostro-push

# Copy binary
sudo cp target/release/mostro-push-backend /opt/mostro-push/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable mostro-push
sudo systemctl start mostro-push

# Check status
sudo systemctl status mostro-push
sudo journalctl -u mostro-push -f
```

## Reverse Proxy (Nginx)

For HTTPS termination, use nginx:

```nginx
# /etc/nginx/sites-available/push.mostro.network
server {
    listen 80;
    server_name push.mostro.network;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name push.mostro.network;

    ssl_certificate /etc/letsencrypt/live/push.mostro.network/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/push.mostro.network/privkey.pem;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/push.mostro.network /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d push.mostro.network
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/mostro-push-backend /usr/local/bin/

EXPOSE 8080

CMD ["mostro-push-backend"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  mostro-push:
    build: .
    ports:
      - "8080:8080"
    environment:
      - NOSTR_RELAYS=wss://relay.mostro.network
      - MOSTRO_PUBKEY=${MOSTRO_PUBKEY}
      - SERVER_PRIVATE_KEY=${SERVER_PRIVATE_KEY}
      - FIREBASE_PROJECT_ID=${FIREBASE_PROJECT_ID}
      - FIREBASE_SERVICE_ACCOUNT_PATH=/secrets/service-account.json
      - FCM_ENABLED=true
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8080
      - RUST_LOG=info
    volumes:
      - ./secrets:/secrets:ro
      - ./data:/app/data
    restart: unless-stopped
```

```bash
# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f
```

## Monitoring

### Health Check Endpoint

```bash
# Simple health check
curl -f http://localhost:8080/api/health || exit 1
```

### Prometheus Metrics (TODO)

Future versions will expose `/metrics` endpoint for Prometheus scraping.

### Log Monitoring

```bash
# Watch logs in real-time
journalctl -u mostro-push -f

# Search for errors
journalctl -u mostro-push --since "1 hour ago" | grep -i error
```

## Backup and Recovery

### What to Backup

1. **Server Private Key** - Critical! Without this, clients cannot register tokens
2. **Firebase Service Account** - Required for FCM
3. **Configuration** - `.env` file

### Backup Script

```bash
#!/bin/bash
BACKUP_DIR="/backup/mostro-push/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp /etc/mostro-push/.env "$BACKUP_DIR/"
cp -r /etc/mostro-push/secrets "$BACKUP_DIR/"

# Encrypt backup
tar czf - "$BACKUP_DIR" | gpg -c > "$BACKUP_DIR.tar.gz.gpg"
rm -rf "$BACKUP_DIR"

echo "Backup created: $BACKUP_DIR.tar.gz.gpg"
```

### Recovery

```bash
# Decrypt and extract
gpg -d backup.tar.gz.gpg | tar xzf -

# Restore files
cp .env /etc/mostro-push/
cp -r secrets /etc/mostro-push/

# Restart service
systemctl restart mostro-push
```

## Troubleshooting

### Server Won't Start

```bash
# Check configuration
cat /etc/mostro-push/.env

# Verify Firebase credentials
cat /etc/mostro-push/secrets/service-account.json | jq .client_email

# Check logs
journalctl -u mostro-push -n 100
```

### FCM Not Working

```bash
# Verify FCM is enabled
grep FCM_ENABLED /etc/mostro-push/.env

# Check service account path
ls -la /etc/mostro-push/secrets/service-account.json

# Test OAuth2 manually (check logs for token errors)
RUST_LOG=debug systemctl restart mostro-push
```

### No Tokens Registered

1. Check client can reach server: `curl https://push.mostro.network/api/health`
2. Verify server pubkey matches client expectation
3. Check firewall rules
4. Review client logs for registration errors

### Nostr Connection Issues

```bash
# Check relay connectivity
websocat wss://relay.mostro.network

# Verify MOSTRO_PUBKEY is correct
grep MOSTRO_PUBKEY /etc/mostro-push/.env
```

## Security Checklist

- [ ] Server private key stored securely (not in repo)
- [ ] Firebase credentials have minimal permissions
- [ ] HTTPS enabled via reverse proxy
- [ ] Firewall configured (only 443 exposed)
- [ ] Service runs as non-root user
- [ ] Logs don't contain sensitive data
- [ ] Regular backups of private key
- [ ] Rate limiting configured
