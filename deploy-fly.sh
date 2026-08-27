#!/bin/bash

# Fly.io deploy wrapper. Secrets must be provisioned out-of-band with
# `flyctl secrets set`; this script only verifies that required names exist.

set -euo pipefail

APP_NAME="${FLY_APP_NAME:-mostro-push-server}"
REQUIRED_SECRETS=(
  NOSTR_RELAYS
  SERVER_PRIVATE_KEY
  FIREBASE_PROJECT_ID
)

# The Firebase credential no longer ships inside the image, so it must arrive
# at runtime. Either form works and exactly one is enough:
#   FIREBASE_SERVICE_ACCOUNT_JSON - the credential itself (preferred on Fly)
#   FIREBASE_SERVICE_ACCOUNT_PATH - a path to a file mounted into the machine
CREDENTIAL_SECRETS=(
  FIREBASE_SERVICE_ACCOUNT_JSON
  FIREBASE_SERVICE_ACCOUNT_PATH
)

die() {
    echo "Error: $*" >&2
    exit 1
}

echo "Starting Fly.io deploy for ${APP_NAME}..."

if ! command -v flyctl > /dev/null 2>&1; then
    die "flyctl is not installed. Install with: curl -L https://fly.io/install.sh | sh"
fi

if ! flyctl auth whoami > /dev/null 2>&1; then
    die "not authenticated in Fly.io. Run: flyctl auth login"
fi

echo "Checking required Fly secrets..."

if ! configured_secret_names="$(flyctl secrets list -a "${APP_NAME}" | awk 'NR > 1 { print $1 }')"; then
    die "failed to list Fly secrets for ${APP_NAME}"
fi

missing_secrets=()
for secret in "${REQUIRED_SECRETS[@]}"; do
    if ! grep -qx "${secret}" <<< "${configured_secret_names}"; then
        missing_secrets+=("${secret}")
    fi
done

if (( ${#missing_secrets[@]} > 0 )); then
    echo "Missing required Fly secrets for ${APP_NAME}:" >&2
    printf '  - %s\n' "${missing_secrets[@]}" >&2
    echo "Set them with flyctl secrets set before deploying. See docs/deployment.md." >&2
    exit 1
fi

# Without one of these the server still starts, but FCM is disabled and every
# push is silently dropped. Fail here rather than discover it in the logs.
credential_present=false
for secret in "${CREDENTIAL_SECRETS[@]}"; do
    if grep -qx "${secret}" <<< "${configured_secret_names}"; then
        credential_present=true
        break
    fi
done

if [[ "${credential_present}" != true ]]; then
    echo "No Firebase credential secret is set for ${APP_NAME}." >&2
    echo "Set exactly one of:" >&2
    printf '  - %s\n' "${CREDENTIAL_SECRETS[@]}" >&2
    echo "The credential is no longer baked into the image. See docs/deployment.md." >&2
    exit 1
fi

echo "Deploying..."
flyctl deploy -a "${APP_NAME}"

echo "Deploy complete."
echo ""
echo "Useful commands:"
echo "  flyctl status -a ${APP_NAME}"
echo "  flyctl logs -a ${APP_NAME}"
echo "  flyctl ssh console -a ${APP_NAME}"
echo "  flyctl secrets list -a ${APP_NAME}"
echo "  flyctl open -a ${APP_NAME}"
echo ""
echo "App URL: https://${APP_NAME}.fly.dev"
