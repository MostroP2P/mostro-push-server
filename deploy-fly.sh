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
# there. [[files]] is the one declarative way to do that on Fly, so the path
# form is accepted only once fly.toml declares it. A [mounts] table does not
# count: it attaches an empty volume and says nothing about the credential.
# Without either, the path resolves to nothing, FCM starts disabled and every
# push is dropped in silence — which is what a PATH secret left over from when
# the image carried the credential would do today.
#
# The match stops at "a [[files]] entry exists". Whether its guest_path is the
# one FIREBASE_SERVICE_ACCOUNT_PATH points at cannot be checked from here:
# `flyctl secrets list` returns names, never values. The declared paths are
# printed so the operator can confirm that last step.
CREDENTIAL_SECRETS=(FIREBASE_SERVICE_ACCOUNT_JSON)
declared_guest_paths=""
if [[ -f "${FLY_CONFIG}" ]] \
   && grep -Eq '^[[:space:]]*\[\[files\]\]' "${FLY_CONFIG}"; then
    CREDENTIAL_SECRETS+=(FIREBASE_SERVICE_ACCOUNT_PATH)
    declared_guest_paths="$(grep -E '^[[:space:]]*guest_path[[:space:]]*=' "${FLY_CONFIG}" \
        | sed -E 's/^[[:space:]]*guest_path[[:space:]]*=[[:space:]]*//; s/^["'"'"']//; s/["'"'"']$//')"
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
        echo "FIREBASE_SERVICE_ACCOUNT_PATH does not count here: ${FLY_CONFIG} declares no" >&2
        echo "[[files]] section, so nothing would create a file at that path." >&2
    fi
    echo "The credential is no longer baked into the image. See docs/deployment.md." >&2
    exit 1
fi

# Accepted on the strength of [[files]] alone. Surface the paths it declares so
# a guest_path that does not match the secret is caught here, not in the logs.
if [[ -n "${declared_guest_paths}" ]] \
   && grep -qx "FIREBASE_SERVICE_ACCOUNT_PATH" <<< "${configured_secret_names}" \
   && ! grep -qx "FIREBASE_SERVICE_ACCOUNT_JSON" <<< "${configured_secret_names}"; then
    echo "Using FIREBASE_SERVICE_ACCOUNT_PATH. ${FLY_CONFIG} writes these guest paths:" >&2
    printf '  - %s\n' ${declared_guest_paths} >&2
    echo "The secret must name one of them, or FCM will start disabled." >&2
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
