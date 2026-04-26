# Verificación manual: ruta de chat de disputa

Este runbook describe cómo un operador verifica de extremo a extremo que
los DMs administrativos (enviados directamente usuario-a-usuario, NO
enrutados a través del daemon de Mostro) siguen alcanzando los
dispositivos registrados como push silenciosos a través de la ruta de
escucha de Nostr.

Este procedimiento se ejecuta después de cada despliegue del milestone
v1.1 (fases 1, 2 y 3). Es la única señal de extremo a extremo de que el
refactor de la fase 1 (`PushDispatcher`) y la adición de la fase 2
(`POST /api/notify`) no han introducido una regresión silenciosa en la
ruta del escucha.

## Por qué este runbook existe

En Mostro, los chats de disputa entre administradores y usuarios se
envían como mensajes Nostr directos `kind 1059` (Gift Wrap, NIP-59).
El remitente es el administrador (un usuario humano), NO el daemon de
Mostro. El daemon de Mostro publica eventos de actualización de trade,
pero NO los DMs administrativos.

Por esta razón, el escucha de Nostr en `src/nostr/listener.rs` NO
DEBE filtrar los eventos por `authors`. Filtrar por
`mostro_pubkey` haría que los DMs administrativos se descartaran en
silencio, rompiendo el chat de disputa para todos los usuarios.

Adicionalmente, Gift Wrap (NIP-59) usa una clave externa efímera por
evento. La clave del remitente nunca es visible en el evento externo,
por lo que filtrar por `authors` es estructuralmente imposible
incluso si se quisiera.

Esta restricción está documentada como anti-requisito **OOS-19 /
CRIT-1** en `.planning/PROJECT.md` y como bloque de comentario sobre
`Filter::new()` en `src/nostr/listener.rs` (introducido en la fase 1
decisión D-11).

## Prerrequisitos

- Acceso al staging de Fly.io (`mostro-push-server`).
- `flyctl` instalado y autenticado (`flyctl auth whoami` debe
  responder).
- Un cliente Nostr secundario capaz de publicar eventos `kind 1059`
  contra un relay configurado por el servidor (por ejemplo, Damus,
  Amethyst, o un script `nostr-tool`).
- Una `trade_pubkey` de prueba (64 caracteres hex) y un token FCM o
  UnifiedPush de prueba registrado para esa pubkey.
- Un dispositivo de prueba (real o emulador) capaz de recibir el push
  silencioso correspondiente al token registrado.
- Acceso de solo lectura al árbol de fuentes del repo
  (`mostro-push-server`) para ejecutar la verificación grep
  anti-CRIT-1 al final del procedimiento.

## Procedimiento

### Paso 1: Registrar la pubkey de prueba

Registra el `trade_pubkey` y el token de dispositivo a través del
endpoint existente `POST /api/register`:

```bash
curl -i -X POST https://mostro-push-server.fly.dev/api/register \
  -H 'content-type: application/json' \
  -d '{
    "trade_pubkey": "<64-hex-chars>",
    "token": "<token-fcm-o-unifiedpush>",
    "platform": "android"
  }'
```

Respuesta esperada: `200 OK` con cuerpo
`{"success":true,"message":"Token registered successfully","platform":"android"}`.

Anota el `trade_pubkey` exacto que registraste — lo necesitarás en el
paso siguiente.

### Paso 2: Publicar un evento kind 1059 desde un cliente Nostr secundario

Desde un cliente Nostr secundario (NO el daemon de Mostro — es
importante simular que el remitente es un usuario humano, no el
daemon), publica un Gift Wrap (NIP-59, `kind 1059`) dirigido al
`trade_pubkey` registrado, contra uno de los relays configurados
en el servidor (`NOSTR_RELAYS`).

El evento debe tener:

- `kind`: `1059`
- Etiqueta `p`: el `trade_pubkey` registrado en el paso 1.
- Clave externa: efímera (cualquier `Keys::generate()` u
  equivalente). Esta es la clave que firma el evento externo;
  NO es la clave del administrador.

El contenido interno del Gift Wrap puede ser cualquier mensaje de
prueba; el servidor de push no descifra ni inspecciona el contenido.

El daemon de Mostro NO envía DMs administrativos. Los administradores
contactan a los usuarios directamente (de usuario a usuario). Filtrar
por `mostro_pubkey` en el escucha rompería esta ruta silenciosamente,
razón por la cual la fase 1 D-11 introdujo el bloque de comentario
explícito en `src/nostr/listener.rs` y la fase 3 OPEN-6 mantiene el
campo `MOSTRO_PUBKEY` inerte sin aplicarlo como filtro.

### Paso 3: Verificar la entrega del push silencioso

Inmediatamente después de publicar el evento, observa los logs del
servidor en Fly.io:

```bash
flyctl logs -a mostro-push-server | grep -E "(Push sent successfully for event|Failed to send push)"
```

Debes ver una línea de la forma:

```
Push sent successfully for event <event-id>
```

dentro de los siguientes ~5-10 segundos tras publicar el evento.

Adicionalmente, el dispositivo de prueba debe recibir el push
silencioso. Verifícalo según el backend:

- **FCM (iOS o Android)**: el handler en background del cliente
  móvil debe ejecutarse (por ejemplo, `didReceiveRemoteNotification`
  en iOS, `FirebaseMessagingService.onMessageReceived` en Android).
- **UnifiedPush (Android)**: el receptor en background del cliente
  debe activarse según el distribuidor configurado.

Si NO ves la línea `Push sent successfully for event ...` en los
logs:

- Confirma que el evento llegó al relay configurado (algunas
  herramientas Nostr fallan en silencio si el relay rechaza el
  evento).
- Confirma que el `p` tag coincide exactamente con el
  `trade_pubkey` registrado (64 caracteres hex, sin
  mayúsculas/minúsculas mezcladas).
- Revisa los logs completos para errores en `connect_and_listen` o
  en `dispatcher.dispatch(...)`.

### Paso 4: Verificación anti-CRIT-1

Después de cada despliegue, ejecuta el siguiente comando en el árbol
de fuentes del repo para confirmar que no se ha re-introducido el
anti-fix prohibido (`.authors(mostro_pubkey)` en el filtro del
escucha):

```bash
grep -n '\.authors(' src/nostr/listener.rs
```

Salida esperada: exactamente UNA coincidencia, dentro del bloque de
comentario de la fase 1 D-11 (la línea que dice
`// DO NOT add .authors(...) here.` o equivalente).

Para una verificación con código de salida bash que falle si
aparece una llamada `.authors(...)` activa (no en comentario):

```bash
if grep -nE '^\s*[^/].*\.authors\(' src/nostr/listener.rs; then
    echo "FAIL: filtro .authors() presente en el escucha — anti-CRIT-1 violado"
    exit 1
else
    echo "PASS: no hay filtro .authors() activo"
fi
```

Si el comando de salida falla (`exit 1`), abre un issue de
seguridad de inmediato — alguien ha re-introducido el anti-fix
prohibido y los DMs administrativos están siendo descartados en
silencio.

## Limpieza

Después de verificar, elimina el token de prueba mediante el endpoint
`POST /api/unregister` para evitar contaminar las métricas de
producción:

```bash
curl -i -X POST https://mostro-push-server.fly.dev/api/unregister \
  -H 'content-type: application/json' \
  -d '{"trade_pubkey": "<64-hex-chars>"}'
```

Respuesta esperada: `200 OK` con cuerpo
`{"success":true,"message":"Token unregistered successfully"}`
o `{"success":true,"message":"Token not found (may have already been unregistered)"}`.

## Frecuencia recomendada

- Después de cada deploy del milestone v1.1 (fases 1, 2 y 3).
- Después de cualquier modificación de `src/nostr/listener.rs`,
  `src/push/dispatcher.rs`, o `src/push/mod.rs`.
- Como verificación periódica mensual en producción.

## Referencias

- `.planning/PROJECT.md` — anti-requisito **OOS-19 / CRIT-1**.
- `.planning/REQUIREMENTS.md` — requisito **VERIFY-03**.
- `.planning/phases/01-pushdispatcher-refactor-no-behaviour-change/01-CONTEXT.md` — decisión **D-11** (introducción del bloque de comentario anti-CRIT-1).
- `src/nostr/listener.rs` — bloque de comentario sobre `Filter::new()`.
- NIP-59 (Gift Wrap, `kind 1059`) — especificación del esquema de
  evento que envuelve los DMs.
