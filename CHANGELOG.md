# Changelog

All notable changes to `hkm-plugin-webhooks` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-11

### Changed

- **Requires kernel `^1.21.0`.** This plugin uses `EventBus::ALL`, which ships in kernel
  1.21.0 and exists in no earlier release. The previous floor let a resolver
  install it onto a kernel where that symbol is absent, which is a fatal at
  autoload rather than a missing feature — the plugin would not degrade, it
  would stop the application from booting.
- No behaviour changes. This release exists to make the declared floor match
  what the code actually needs.

## [Unreleased]

### Added

- **First release: signed, retried delivery of application events to registered
  HTTP endpoints.** Solves `webhook.delivery` and requires `http.client`.
  Subscribes to `EventBus::ALL`, matches each event against the registered
  patterns, and queues one delivery per matching endpoint. Needs kernel 1.20 for
  `EventBus::ALL` — on an older kernel `subscribe()` would register under the
  literal name `"*"`, nothing would ever match, and the plugin would install
  cleanly and deliver nothing.

- **The timestamp is part of the signed string, which is what stops a replay.**
  The signature is HMAC-SHA256 over `"{timestamp}.{body}"` and the header
  carries both (`t=…,v1=…`). Appwrite's equivalent signs `url + payload` with
  HMAC-SHA1 and nothing else: that authenticates the body and leaves a captured
  request replayable FOREVER, because the signature stays valid as long as the
  secret does. Rewriting `t=` to look fresh breaks the hash, which is the
  property that makes a receiver's age check worth anything.

  SHA-256 rather than SHA-1: HMAC-SHA1 is not practically broken, but SHA-1's
  collision resistance is, and a receiver's security reviewer should not have to
  litigate the difference.

- **The body is signed as BYTES and never re-serialised.** It is built once per
  event, stored, signed and sent verbatim; the per-endpoint parts — the delivery
  id, the attempt, the signature — travel in headers precisely so the bytes can
  be identical for every endpoint. The commonest way webhook verification fails
  in the wild is a receiver that re-encodes the JSON before checking, so
  `Signature::verify()` is published for receivers to use and tested against the
  documented string literally.

- **Per-SEGMENT pattern matching, not a character glob.** `user.*` matches
  `user.registered` and NOT `user.profile.updated`. If it did, adding a deeper
  resource's events to the application would silently widen every existing
  `user.*` subscription, and a third party would begin receiving events about a
  resource nobody agreed to send them. `**` matches one or more trailing
  segments, is legal only in final position, and never matches zero.

- **The URL came from a user, so every HTTP default is overridden.**
  `block_private => true`, because the client allows private ranges by default
  for first-party gateways and that default lets a tenant register
  `http://169.254.169.254/latest/meta-data/` and read IAM credentials out of the
  delivery log. A lowered `max_response_bytes`, because the reply is read only to
  log an excerpt and a hostile receiver could otherwise stream filler until
  megabytes were buffered per delivery. And `retry => 0`, because this plugin
  owns retrying — the client's own retry would turn ten delivery attempts into
  thirty POSTs, invisibly.

  Registration-time URL validation is ADVISORY and documented as such: DNS can
  change between saving a URL and fetching it, so no check at registration can
  be authoritative. The delivery-time guard is the control.

- **Redirects are not followed**, which matters more here than anywhere:
  following a 302 would let a receiver bounce us to an internal address after
  the SSRF guard had approved the public one it was given.

- **`410 Gone` disables the endpoint; other 4xx do not.** It is the one status
  with a standard meaning worth honouring — the only way a receiver can
  decommission an endpoint without reaching into our database. A 401 or 403, by
  contrast, is usually a receiver mid-deploy, and treating 4xx as permanent
  would discard real events over a thirty-second rollout.

- **`paused` and `disabled` are separate states**, because the way out differs:
  we pause automatically and `webhooks:retry` resumes it routinely, while
  `disabled` means a person decided or the receiver answered 410 and is never
  reversed automatically. Pausing HOLDS queued deliveries rather than discarding
  them, so resuming sends what was missed.

- **Concurrent deliverers claim rows rather than locking them**, with the same
  conditional UPDATE as `event.outbox` and a sharper reason: a duplicate here is
  a second POST into somebody else's system, which may charge them or page their
  on-call. The claim is a lease, released after `WEBHOOKS_CLAIM_TIMEOUT`, and
  that reclaim is the only signal anywhere that a deliverer died.

- **The failure streak is counted by the database**, not in PHP. Two deliverers
  failing against one endpoint at once must not lose an increment, because the
  streak is what decides whether the endpoint gets paused.

- **Secrets are encrypted at rest when an `EncryptionPort` is bound**, with the
  flag recorded PER ROW. A webhook secret has to be decryptable rather than
  hashed, and a global assumption would mean a deployment that adds the port
  later started treating its existing plaintext secrets as ciphertext — every
  receiver's signature check failing with nothing looking broken.

- **The backoff ceiling is computed in the config**, so it cannot be forgotten
  at a call site: without it, attempt 10 of a 60-second base lands 8 hours out
  and attempt 20 next year. The exponent is clamped before the shift, because
  `2 ** 60` overflows to a float and then to a negative int, which would
  schedule the retry in the PAST and spin the row through the queue as fast as
  the deliverer runs.

- **`webhooks:status` exits non-zero** when anything is parked or not receiving,
  so it works as a monitoring check without anything parsing its output.
  `webhooks:deliver` exits non-zero ONLY for what will not fix itself — a
  transient failure is not a failed run, and a supervisor restarting on non-zero
  would restart the deliverer because somebody else's server was briefly down.

- **Registering is not a CLI command**, on purpose: it mints a secret that must
  be shown once, and a CLI would put it in shell history.

### Fixed during development

- **`\r` was not being stripped from the stored response excerpt.** The
  character class was the usual "keep tab and newline" one,
  `\x00-\x08\x0B\x0C\x0E-\x1F`, which skips `0x0D` entirely — that class comes
  from XML and JSON text handling, where CRLF is ordinary and harmless, and it
  is wrong when the threat is a TERMINAL. A lone CR returns the cursor to the
  start of the line without advancing it, so a receiver replying
  `"ok\r  delivered 500/500, 0 failed"` could overwrite the line
  `webhooks:status` had just printed and forge the output of the command being
  used to investigate it. The comment above the code claimed CR was handled.

  Found by a revert check: removing the sanitising passed the whole suite,
  because this class had no tests at all.

- **`hash_equals` turned out to be unpinnable by a behaviour test.** Swapping in
  `===` also passed the suite, and always will: the two return the same boolean
  for every input and differ only in timing. There is now a guardrail test
  asserting the source still uses the constant-time comparison, which is the
  only check that can exist for it.

### Notes

- Delivery is **at-least-once**. `X-Webhook-Delivery` is stable across retries
  so a receiver can dedupe; `X-Webhook-Attempt` is not.
- There is **no ordering guarantee**: a delivery that fails is retried later
  while the ones behind it go out now.
- `response_excerpt` and `last_error` hold **untrusted text** from the receiver.
  They belong in a terminal or a log and must never be rendered as markup or
  echoed into one of our own responses.
- Pair with `event.outbox` for durability. The subscription fires after the
  commit, so without it an event is lost if the process dies in that window;
  with it, the listener's failure makes the outbox re-queue rather than consume.
  The listener therefore deliberately does not catch.
