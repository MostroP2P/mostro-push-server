#!/bin/bash

# Script para hacer deploy de mostro-push-server en Fly.io
# Asegúrate de estar autenticado: flyctl auth login

set -e

echo "🚀 Iniciando deploy en Fly.io..."

# Verificar que flyctl está instalado
if ! command -v flyctl &> /dev/null; then
    echo "❌ Error: flyctl no está instalado"
    echo "Instala con: curl -L https://fly.io/install.sh | sh"
    exit 1
fi

# Verificar que estás autenticado
if ! flyctl auth whoami &> /dev/null; then
    echo "❌ Error: No estás autenticado en Fly.io"
    echo "Ejecuta: flyctl auth login"
    exit 1
fi

echo "📝 Configurando secrets..."

# Configurar todos los secrets
flyctl secrets set \
  NOSTR_RELAYS="wss://relay.mostro.network" \
  MOSTRO_PUBKEY="82fa8cb978b43c79b2156585bac2c011176a21d2aead6d9f7c575c005be88390" \
  SERVER_PRIVATE_KEY="2dfb72f7e130b4c6f971c5bac364b9f854f2409de51fb53d4dbd3e17bd69b98e" \
  FIREBASE_PROJECT_ID="mostro-mobile" \
  FIREBASE_SERVICE_ACCOUNT_PATH="/secrets/mostro-mobile-firebase-adminsdk-fbsvc-1ff8f6232c.json" \
  FCM_ENABLED="true" \
  UNIFIEDPUSH_ENABLED="false" \
  SERVER_HOST="0.0.0.0" \
  SERVER_PORT="8080" \
  TOKEN_TTL_HOURS="48" \
  CLEANUP_INTERVAL_HOURS="1" \
  RATE_LIMIT_PER_MINUTE="60" \
  BATCH_DELAY_MS="5000" \
  COOLDOWN_MS="60000" \
  RUST_LOG="info"

echo "✅ Secrets configurados"

echo "🏗️  Haciendo deploy..."
flyctl deploy

echo "✅ Deploy completado!"
echo ""
echo "📊 Comandos útiles:"
echo "  flyctl status          - Ver estado de la app"
echo "  flyctl logs            - Ver logs en tiempo real"
echo "  flyctl ssh console     - Conectar a la máquina"
echo "  flyctl secrets list    - Ver secrets configurados"
echo "  flyctl open            - Abrir la app en el navegador"
echo ""
echo "🌐 Tu app estará disponible en: https://mostro-push-server.fly.dev"
