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

FLY_CONFIG="${FLY_CONFIG:-fly.toml}"

# The Firebase credential no longer ships inside the image, so it must arrive at
# runtime. On Fly a secret already *is* an environment variable, so the inline
# form needs nothing else.
#
# FIREBASE_SERVICE_ACCOUNT_PATH only names a file; something else has to put one
# there. It is accepted only once fly.toml declares [[files]] or [mounts],
# because otherwise the path resolves to nothing, FCM starts disabled and every
# push is dropped in silence. A leftover PATH secret from before this change is
# exactly that case.
CREDENTIAL_SECRETS=(FIREBASE_SERVICE_ACCOUNT_JSON)
if [[ -f "${FLY_CONFIG}" ]] \
   && grep -Eq '^[[:space:]]*\[\[?(files|mounts)\]\]?' "${FLY_CONFIG}"; then
    CREDENTIAL_SECRETS+=(FIREBASE_SERVICE_ACCOUNT_PATH)
fi

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
    echo "No usable Firebase credential secret is set for ${APP_NAME}." >&2
    echo "Set one of:" >&2
    printf '  - %s\n' "${CREDENTIAL_SECRETS[@]}" >&2
    if (( ${#CREDENTIAL_SECRETS[@]} == 1 )); then
        echo "FIREBASE_SERVICE_ACCOUNT_PATH does not count here: ${FLY_CONFIG} declares" >&2
        echo "no [[files]] or [mounts] section, so no file would exist at that path." >&2
    fi
    echo "The credential is no longer baked into the image. See docs/deployment.md." >&2
    exit 1
fi

echo "Deploying..."
# Same config the credential check above read, so the two cannot diverge.
flyctl deploy -a "${APP_NAME}" -c "${FLY_CONFIG}"

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
