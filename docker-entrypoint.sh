#!/bin/sh
# Volumes (a Fly volume, a Docker named volume) are attached to /app/data
# owned by root, and the server runs as UID 10001, so it could not create the
# token store there. Starting as root only long enough to hand the directory
# over, then dropping privileges for good, keeps the server itself
# unprivileged.
set -eu

DATA_DIR=/app/data
RUNTIME_UID=10001
RUNTIME_GID=10001

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown -R "$RUNTIME_UID:$RUNTIME_GID" "$DATA_DIR"
    exec setpriv --reuid="$RUNTIME_UID" --regid="$RUNTIME_GID" --clear-groups -- "$@"
fi

exec "$@"
