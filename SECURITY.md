# Security Policy

## Reporting a vulnerability

Report security issues privately to **security@mostro.network**.

Do not open a public GitHub issue, pull request, or discussion for a suspected
vulnerability, and do not disclose it on public channels before a fix is
available.

Include as much of the following as you can:

- A description of the issue and the security impact you believe it has.
- The affected component (HTTP endpoint, Nostr listener, push dispatcher,
  token store, deployment configuration).
- Version, commit hash, or deployed instance where you observed it.
- Reproduction steps, a proof of concept, or a minimal request sequence.
- Any logs, timings, or measurements that support the finding. Redact real
  `trade_pubkey` values and device tokens.

## Response process

- Acknowledgement of your report within 72 hours.
- An initial assessment, including severity and whether we accept the issue,
  within 7 days.
- Progress updates at least every 14 days until the issue is resolved or
  closed.
- Coordinated disclosure once a fix is released. We will credit reporters who
  wish to be named; tell us the name or handle you want used.

## Supported versions

Security fixes are applied to the `main` branch and released from there. Only
the latest release is supported. Operators running older builds should update
before reporting an issue that may already be fixed.

## Scope

In scope:

- The HTTP API: `/api/health`, `/api/info`, `/api/status`, `/api/register`,
  `/api/unregister`, `/api/notify`.
- The rate limiting middleware and client IP extraction.
- The Nostr listener and its subscription handling.
- The push dispatcher and the FCM and UnifiedPush backends, including
  credential handling.
- The in-memory token store and the UnifiedPush endpoint file.
- Privacy invariants, including log redaction and any behaviour that lets an
  observer or the server operator correlate a sender with a recipient,
  enumerate registered pubkeys, or link a `trade_pubkey` to a device.
- Dependency vulnerabilities that are reachable from this code.
- The shipped `Dockerfile`, `docker-compose.yml`, and `fly.toml` where they
  weaken the security posture of a default deployment.

Out of scope:

- Third-party services the server talks to: Firebase Cloud Messaging,
  UnifiedPush distributors, Nostr relays, and hosting providers. Report those
  to the respective vendor.
- The Mostro daemon, Mostro Mobile, and other MostroP2P repositories. Report
  those against the relevant project, at the same address.
- Findings that depend on a misconfigured operator deployment that contradicts
  the documented configuration, unless the default is itself unsafe.
- Volumetric denial of service, spam, or brute force against a public instance.
  Reports of an algorithmic or amplification issue in this code that allows
  disproportionate resource consumption are in scope.
- Reports produced solely by automated scanners without a demonstrated impact.

## Known design decisions

The following are deliberate and documented in
[docs/architecture.md](docs/architecture.md). They are not vulnerabilities on
their own. A report that shows one of them can be turned into a concrete
privacy or availability impact beyond what is described here is welcome.

- `/api/register`, `/api/unregister`, and `/api/notify` are unauthenticated.
  Sender identifiers, signatures, and `Authorization` headers are rejected by
  design, because they would let the operator correlate sender and recipient.
- `/api/notify` always returns `202` on parse-valid input. Registered and
  unregistered pubkeys are intended to be indistinguishable in status, body,
  headers, and timing. A measurable distinguisher is a valid finding.
- The Nostr listener does not filter by `authors`. Gift Wrap uses an ephemeral
  outer key per event and dispute admin messages are user-to-user, so an author
  filter would silently drop legitimate events.
- Device tokens are held in memory only and are never persisted to disk.
- The trusted Mostro instance whitelist on `/api/register` is honour-system
  only. The device proves nothing cryptographically about the instance it uses.
  This is a known limitation, tracked for a future hardening phase.

## Safe harbour

We will not pursue legal action against researchers who act in good faith,
stay within the scope above, avoid privacy violations and service degradation,
do not access, modify, or exfiltrate data that is not their own, and give us a
reasonable window to fix the issue before public disclosure.
