# Deployment

The reference deployment target is Fly.io. The repo also ships a `Dockerfile` and a `docker-compose.yml` for local containerized runs and for use with other PaaS providers.

## Fly.io (reference)

`fly.toml` provisions:

- App `mostro-push-server`, region `gru` (São Paulo)
- One VM, `512 MB` RAM, 1 shared CPU
- Internal port `8080`, HTTPS forced at the edge
- `auto_start_machines = true`, `min_machines_running = 1`
- Hard connection limit of `25` per machine

The 25-connection hard limit is the inbound capacity ceiling. The `/api/notify` spawn pool (50 permits) is independent and bounds concurrent outbound dispatch tasks, not inbound connections.

### First-time setup

```bash
flyctl auth login
flyctl launch --no-deploy   # reads fly.toml, creates the app, no deploy yet
```

### Configure secrets

`deploy-fly.sh` verifies required Fly secrets and runs `flyctl deploy`. It
does not set secret values, and it exits before deploying if a required
secret is missing. Provision secrets out-of-band and never commit production
values to the repo.

Generate a fresh server key for every production deployment:

```bash
server_private_key="$(openssl rand -hex 32)"

flyctl secrets set -a mostro-push-server \
  SERVER_PRIVATE_KEY="${server_private_key}" \
  NOSTR_RELAYS="wss://relay.mostro.network" \
  FIREBASE_PROJECT_ID="your-project-id" \
  FIREBASE_SERVICE_ACCOUNT_JSON="$(cat /path/to/firebase-service-account.json)" \
  FCM_ENABLED="true" \
  UNIFIEDPUSH_ENABLED="false" \
  SERVER_HOST="0.0.0.0" \
  SERVER_PORT="8080" \
  TOKEN_TTL_HOURS="48" \
  CLEANUP_INTERVAL_HOURS="1" \
  NOTIFY_TRUST_PROXY_HEADERS="true" \
  RUST_LOG="info"

unset server_private_key
```

`deploy-fly.sh` requires these secret names to exist before deploy:

- `NOSTR_RELAYS`
- `SERVER_PRIVATE_KEY`
- `FIREBASE_PROJECT_ID`
- one of `FIREBASE_SERVICE_ACCOUNT_JSON` or `FIREBASE_SERVICE_ACCOUNT_PATH`

Deploy after the secrets exist:

```bash
./deploy-fly.sh
```

`NOTIFY_TRUST_PROXY_HEADERS=true` is correct on Fly because requests reach the app behind the Fly edge proxy, which sets `Fly-Client-IP`. On any deployment where the app is reachable directly, leave this `false`; otherwise an attacker can rotate that header per request and defeat the per-IP limiter.

### Provisioning the Firebase service account

The credential is **not** in the image. It used to be: the `Dockerfile` copied
`secrets/` into a layer, which published the private key to anyone able to pull
the image — `docker save` and `docker history` reach it without ever running the
container. `.dockerignore` now also keeps `secrets/` out of the build context
entirely, which matters because Fly builds on a remote builder by default.

Two ways to supply it at runtime, and exactly one is needed:

| Variable | Use when |
|---|---|
| `FIREBASE_SERVICE_ACCOUNT_JSON` | The credential itself. Preferred on Fly.io, where a secret already *is* an environment variable. |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | A path to a file mounted into the runtime. Preferred for docker-compose, systemd and Kubernetes. |

`FIREBASE_SERVICE_ACCOUNT_JSON` takes precedence when both are set. An empty
value is treated as absent, so a half-configured deployment falls back to the
path form instead of failing.

The inline form is the default on Fly for a specific reason: the container now
runs as UID 10001, and a file the platform mounts carries ownership and mode
this project does not control. An environment variable is readable by the
process whatever its UID.

```bash
flyctl secrets set -a mostro-push-server \
  FIREBASE_SERVICE_ACCOUNT_JSON="$(cat /path/to/firebase-service-account.json)"
```

**Sequencing matters.** If neither variable is set the server still starts:
`main.rs` logs the failure and runs without FCM, because a listener and an HTTP
API without push are more useful than no server at all. The result is an
instance that accepts registrations and delivers nothing. `deploy-fly.sh`
refuses to deploy when no credential secret exists, but if you deploy by other
means, set the secret **before** rolling out an image built from this Dockerfile.

Confirm it took after the first deploy:

```bash
flyctl logs -a mostro-push-server | grep -i "FCM service initialized"
```

An `FCM notifications are DISABLED` line at `error` level means the credential
did not arrive.

### Rotate `SERVER_PRIVATE_KEY`

If a `SERVER_PRIVATE_KEY` value has ever been committed, pasted into issue
trackers, sent in chat, or printed in logs, treat it as compromised. The old
key that was previously present in `deploy-fly.sh` is public and must never
be reused.

Rotate it by generating a new value and replacing only the Fly secret:

```bash
server_private_key="$(openssl rand -hex 32)"
flyctl secrets set -a mostro-push-server SERVER_PRIVATE_KEY="${server_private_key}"
unset server_private_key
```

After rotation, redeploy and confirm the app starts:

```bash
./deploy-fly.sh
curl https://mostro-push-server.fly.dev/api/health
```

### Subsequent deploys

```bash
./deploy-fly.sh
```

Secrets persist; only re-run `flyctl secrets set` when a value changes.

### Operations

```bash
flyctl status                        # app + machine status
flyctl logs                          # streaming logs
flyctl logs -a mostro-push-server    # explicit app filter
flyctl secrets list                  # list configured secret names
flyctl ssh console                   # shell into the running VM
flyctl scale vm shared-cpu-1x --memory 512
```

### Verifying a deploy

```bash
curl https://mostro-push-server.fly.dev/api/health
curl https://mostro-push-server.fly.dev/api/info
curl https://mostro-push-server.fly.dev/api/status
```

After every deploy, also run the [dispute-chat verification runbook](./verification/dispute-chat.md) to confirm the Nostr listener path still delivers a silent push end-to-end.

## Docker

Build the image:

```bash
docker build -t mostro-push-backend .
```

Run with `docker-compose`:

```bash
docker-compose up -d
docker-compose logs -f
```

`docker-compose.yml` points `FIREBASE_SERVICE_ACCOUNT_PATH` at `/secrets/firebase-service-account.json`, the in-image copy of `secrets/` described above. Name your service-account file accordingly before building, or keep its own name and pass it at run time:

```bash
FIREBASE_SERVICE_ACCOUNT_FILE=my-project-adminsdk.json docker-compose up -d
```

Only the file name is configurable, not the full path: the value has to resolve inside the container, so a host-side path from your `.env` must not leak into it. Verify what Compose resolved before starting:

```bash
docker-compose config | grep FIREBASE_SERVICE_ACCOUNT_PATH
```

`./data` is bind-mounted to `/data` so the UnifiedPush endpoint store survives container recreation. The binary runs with `/` as its working directory and writes the store to `data/unifiedpush_endpoints.json`, which lands at `/data/unifiedpush_endpoints.json` inside the container.

The compose file ships with `UNIFIEDPUSH_ENABLED=false` to match the binary default. The UnifiedPush dispatch path POSTs to the client-supplied device token treated as a URL, so enabling it is an explicit operator decision.

## Reverse proxy (nginx)

If the server is fronted by nginx instead of the Fly edge, terminate TLS at nginx and forward to `127.0.0.1:8080`. Set `NOTIFY_TRUST_PROXY_HEADERS=true` only if nginx is configured to set `Fly-Client-IP` or to put the client IP at the rightmost segment of `X-Forwarded-For`.

```nginx
server {
    listen 80;
    server_name push.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name push.example.com;

    ssl_certificate     /etc/letsencrypt/live/push.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/push.example.com/privkey.pem;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout    60s;
        proxy_read_timeout    60s;
    }
}
```

## Systemd (bare-metal)

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

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/mostro-push/data

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /bin/false mostro
sudo mkdir -p /opt/mostro-push/data
sudo cp target/release/mostro-push-backend /opt/mostro-push/
sudo chown -R mostro:mostro /opt/mostro-push

sudo systemctl daemon-reload
sudo systemctl enable --now mostro-push
sudo journalctl -u mostro-push -f
```

## Persistence

The only on-disk state is `data/unifiedpush_endpoints.json`, written atomically (temp file + rename). The token store and FCM access-token cache are in-memory and cleared on restart. UnifiedPush endpoints survive restarts because they are external addresses owned by clients; tokens do not, because clients re-register them after each session.

## Backup

There is no database to back up. Operationally important inputs are:

- The Firebase service account JSON, held in `FIREBASE_SERVICE_ACCOUNT_JSON` or at `FIREBASE_SERVICE_ACCOUNT_PATH` (regenerate via Firebase Console if lost)
- The contents of `flyctl secrets list` (or the `.env` file on bare-metal)
- `data/unifiedpush_endpoints.json` if you want UnifiedPush registrations to survive a host migration; clients will re-register on next use otherwise

## Troubleshooting

### Server fails to start

The most common cause is `NOSTR_RELAYS` unset. Check `flyctl logs` or the systemd journal for `Failed to load configuration`.

```bash
flyctl logs
journalctl -u mostro-push -n 100
```

### FCM not delivering

```bash
flyctl ssh console
ls -la /secrets/                          # confirm the JSON is at the configured path
flyctl secrets list | grep FIREBASE       # confirm path env var is set
RUST_LOG=debug flyctl deploy              # redeploy with debug logging to see OAuth exchange
```

### `/api/notify` always 429s

Either the per-IP or per-pubkey limiter is hitting. Check `Retry-After` and the response body — 429 bodies are byte-identical between the two paths, so distinguish by reproducing in isolation:

- Hit `/api/notify` once with a fresh `trade_pubkey` from a fresh client IP. Still 429? The per-IP limiter is hitting upstream of you (your egress IP is shared).
- Hit `/api/notify` 11 times in 2 seconds with the same `trade_pubkey`. The 11th should 429 — that confirms the per-pubkey burst (10) is enforced.

### Listener silently drops events

Run the [dispute-chat verification runbook](./verification/dispute-chat.md). The most likely regression is a re-introduced `.authors(...)` filter on the Nostr `Filter`; the runbook includes a grep that fails if that line is present.
