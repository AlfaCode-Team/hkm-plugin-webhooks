# hkm-plugin-webhooks

> HKM Kernel plugin — provides **`webhook.delivery`**.
> Part of the [HKM Kernel](https://github.com/AlfaCode-Team/hkm-kernel) Gated Demand Architecture framework.

![PHP](https://img.shields.io/badge/PHP-8.4%2B-777bb4)

Delivers application events to HTTP endpoints somebody registered: signed,
retried, backed off, and paused when a receiver stops answering.

Requires **`http.client`** — outbound HTTP to a URL somebody typed is the whole
job, and that adapter's SSRF guard and connection pinning are what make it safe
to do at all.

## How events get here

It subscribes to **`EventBus::ALL`**. It cannot enumerate the names it wants:
they belong to other plugins, and a webhook consumer is installed precisely
because nobody knows in advance what the application emits.

Every dispatched event is matched against the registered patterns, and one
**queued** delivery is created per matching endpoint. Never sent inline — a POST
to somebody else's server would make your response time depend on their uptime,
and their timeout would become yours.

```php
// The application's own admin route, authorised however it authorises things.
$endpoint = $this->webhooks->register(
    url:           'https://customer.example.com/hooks/hkm',
    eventPatterns: ['user.*', 'invoice.**'],
);

// Show $endpoint->secret to the registrant ONCE. It is not recoverable.
```

## Pair it with `event.outbox`

The subscription fires at **dispatch** time, which is after the commit. So an
event dispatched straight to the `EventBus` is lost if the process dies in the
window between the commit and this listener — the data is consistent and nobody
is ever told.

Writing the event to the outbox instead closes that:

| | Without the outbox | With it |
| --- | --- | --- |
| Crash between commit and dispatch | the webhook is never queued, silently | the event row is already committed; the relay dispatches it |
| This listener throws | `EventBus` reports it and nothing retries | the outbox re-queues the event instead of consuming it |

The listener therefore deliberately **does not catch**. Swallowing a failure
would convert "the deliveries could not be queued" into "the event was
handled". The two plugins are independent, and together they are end-to-end
durable.

## The subscription dialect

Dot-separated, matched **per segment**:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `user.registered` | exactly that | anything else |
| `user.*` | `user.registered` | `user.profile.updated` — `*` is exactly ONE segment |
| `user.**` | `user.registered`, `user.a.b.c` | `user` — `**` is one or more, never zero |
| `**` | everything | — |

**Per segment, not a character glob.** If `user.*` matched
`user.profile.updated`, then adding a deeper resource's events to the
application would silently widen every existing `user.*` subscription — a third
party would start receiving events about a resource nobody agreed to send them.

`**` is only legal as the **last** segment: `a.**.b` has no single reading, and
a pattern nobody can predict is a subscription nobody can audit. Bad patterns
are refused at **registration**, where the person can still fix them.

## The signature

```
X-Webhook-Signature: t=1763000000,v1=<hex hmac-sha256>
X-Webhook-Delivery:  <uuid, stable across retries>
X-Webhook-Attempt:   3
```

The signed string is **`"{timestamp}.{body}"`**, HMAC-SHA256 with the endpoint's
secret.

**The timestamp is in the signed string, and that is the point.** Appwrite's
equivalent signs `url + payload` with HMAC-SHA1 and nothing else — which
authenticates the body and leaves a captured request replayable **forever**:
anyone who records one POST can resend it a year later and the receiver cannot
tell. Binding the timestamp in, and refusing an old one, is what closes that.
Rewriting `t=` to look fresh breaks the hash, which is the property that makes
the age check worth anything.

SHA-**256**, not SHA-1. HMAC-SHA1 is not practically broken, but SHA-1's
collision resistance is, every comparable product signs with SHA-256, and a
receiver's security reviewer should not have to litigate the difference.

### Verifying, as a receiver

```php
use Plugins\Webhooks\Domain\Signature;

if (!Signature::verify(
    $request->header('X-Webhook-Signature'),
    $rawBody,              // THE RAW BODY. Not a re-encoded version of it.
    $yourSecret,
    tolerance: 300,
)) {
    return Response::unauthorized();
}
```

**Verify against the raw bytes.** The commonest way webhook verification fails
in the wild is a receiver that parses the JSON, re-encodes it and verifies
against the result — which differs in key order, unicode escaping and float
formatting, so the signature never matches and the integration is declared
broken. Nothing on the sending side re-serialises the body either: it is built
once, signed, stored and sent verbatim.

`X-Webhook-Delivery` is **stable across retries**, so a receiver that processed
attempt 1 and failed to answer in time can recognise attempt 2 as the same
delivery and not act twice. `X-Webhook-Attempt` is not.

## Retrying, pausing and giving up

| Response | Outcome |
| --- | --- |
| `2xx` | delivered. The only success, and it clears the endpoint's failure streak |
| `410 Gone` | **permanent** — the endpoint is disabled. The one status with a standard meaning worth honouring: it is how a receiver decommissions an endpoint without reaching into your database |
| `3xx` | retryable, and **not followed** — see below |
| `4xx` | retryable. A 401 is usually a receiver mid-deploy with its auth not yet wired; treating 4xx as permanent would discard real events over a thirty-second deploy |
| `5xx`, timeout, TLS error | retryable |

Backoff doubles from `WEBHOOKS_BACKOFF_BASE` and is **capped** — without the
cap, attempt 10 of a 60-second base lands 8 hours out and attempt 20 next year.
After `WEBHOOKS_MAX_ATTEMPTS` the delivery is **parked** and stops retrying.
After `WEBHOOKS_PAUSE_AFTER_FAILURES` *consecutive* failures the **endpoint** is
paused — consecutive, so a receiver with one bad day two years ago is not paused
today.

**Redirects are not followed.** Following a 302 would let a receiver bounce you
to an internal address *after* the SSRF guard had approved the public one it was
given, and read the response back out of the delivery log. A receiver that has
genuinely moved should be re-registered.

**Paused is not disabled**, because the way out differs:

| | Who stopped it | Way back |
| --- | --- | --- |
| `paused` | us, automatically, after too many failures | `webhooks:retry` — routine |
| `disabled` | a person, or the receiver answering 410 | an explicit `--resume`, never automatic |

Pausing **holds** an endpoint's queued deliveries rather than discarding them,
so resuming sends what was missed.

## The URL came from a user, so every HTTP default is wrong

Three options are set on every delivery, and each closes something specific:

| Option | Why |
| --- | --- |
| `block_private => true` | The HTTP client allows private ranges by default, because a first-party gateway legitimately calls an internal service. Here that default means a tenant can register `http://169.254.169.254/latest/meta-data/` and read IAM credentials back out of the delivery log. The guard resolves the name and **pins** the connection to the addresses it checked |
| `max_response_bytes` | A receiver's reply is read only to log an excerpt, so a hostile one could otherwise hold the connection open streaming filler until megabytes were buffered, once per delivery, across a whole batch |
| `retry => 0` | **This** plugin owns retrying, with persistence and backoff. The client's own retry would multiply attempts invisibly — three transport retries inside ten delivery attempts is thirty POSTs — and spend three times the timeout inside one claim |

**Registration-time URL validation is advisory only**, and that is not a gap to
close: DNS can change between the moment a URL is saved and the moment it is
fetched, so no check at registration can be authoritative about where the
request ends up. It catches the honest mistake and the obvious attempt while the
person can still correct it; the delivery-time guard is the control.

Refused at registration: a non-`https` URL (the body is **signed, not
encrypted** — over http every event's contents cross the network in the clear),
credentials in the URL, a loopback/link-local/private literal, and anything
under `.internal` or `.localhost`.

## Concurrency

Safe to run several deliverers. Rows are **claimed** one at a time with
`UPDATE … WHERE id = :id AND status = 0`, which the database applies atomically,
so exactly one deliverer sees one affected row and the rest skip it. A duplicate
here is a second POST into somebody else's system, which may charge them, ship
something twice, or page their on-call.

The claim is a **lease**: a deliverer killed between claiming and settling would
hold the row forever, so each run first releases anything claimed longer than
`WEBHOOKS_CLAIM_TIMEOUT`. That reclaim is the only signal anywhere that a
deliverer died, which is why it is reported rather than silent.

## Commands

| Command | Does |
| --- | --- |
| `webhooks:deliver` | attempt what is due. Safe concurrently and every minute |
| `webhooks:status` | queue depth and endpoint health; **exits non-zero** when anything is parked or not receiving |
| `webhooks:endpoints` | list; `--pause` / `--resume` / `--disable` / `--delete=ID --yes` |
| `webhooks:retry` | requeue parked deliveries and resume auto-paused endpoints |
| `webhooks:prune` | delete settled deliveries. **Deletes nothing without `--yes`** |

`webhooks:deliver` exits non-zero **only** for things that will not fix
themselves — a parked delivery, a paused or disabled endpoint. A transient
failure is not a failed run, and a supervisor restarting on a non-zero exit
would restart the deliverer because somebody else's server was briefly down.

**Registering is deliberately not a command.** It mints a secret that must be
shown once, and a CLI would put it in shell history. It belongs in the
application's own admin surface, where there is a session to authorise it and
somewhere to display the secret.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `WEBHOOKS_TIMEOUT` | `15` | seconds per POST, matching what Appwrite allows |
| `WEBHOOKS_BATCH` | `50` | deliveries per run. Clamped 1–500 |
| `WEBHOOKS_MAX_ATTEMPTS` | `10` | before a delivery is parked |
| `WEBHOOKS_BACKOFF_BASE` | `60` | first retry delay; doubles |
| `WEBHOOKS_BACKOFF_MAX` | `3600` | the ceiling. Ten attempts then span about a day |
| `WEBHOOKS_PAUSE_AFTER_FAILURES` | `10` | consecutive failures before the endpoint is paused. `0` never pauses |
| `WEBHOOKS_CLAIM_TIMEOUT` | `300` | before a claim is treated as a dead deliverer's |
| `WEBHOOKS_PRUNE_AFTER_DAYS` | `7` | retention for settled deliveries |
| `WEBHOOKS_SIGNATURE_TOLERANCE` | `300` | the documented default for receivers |
| `WEBHOOKS_REQUIRE_HTTPS` | `true` | the body is signed, not encrypted |
| `WEBHOOKS_ALLOW_PRIVATE` | `false` | **inverts** the http-client's own default, on purpose |

## Secrets at rest

A webhook secret must be **decryptable**, not hashed — the HMAC cannot be
computed without the original bytes. When an `EncryptionPort` is bound the
column holds ciphertext, and `secret_encrypted` records that **per row**.

Per row, not globally: a deployment that adds the port later would otherwise
start treating its existing plaintext secrets as ciphertext, and every
receiver's signature check would begin failing with nothing in the application
looking broken.

`describe()` says which, out loud, so an operator does not have to assume.

## `response_excerpt` and `last_error` are untrusted text

They hold whatever a receiver returned. Both are truncated and stripped of
control characters, because this text is printed into an operator's terminal by
`webhooks:status` — a lone `\r` returns the cursor to the start of the line
without advancing it, so a receiver replying `"ok\r  delivered 500/500, 0
failed"` could overwrite the line just printed and forge the output of the
command being used to investigate it. Never render either as markup or echo it
into one of your own responses.

## No routes

Endpoint management is authenticated, authorised and usually tenant-scoped, and
every application models that differently — so the application exposes its own
admin routes and calls `WebhookContract`, rather than inheriting opinions about
who may register a webhook.

## Multi-tenancy

The CLI operates on the **core** `DatabasePort`. In a database-per-tenant
deployment the endpoints live in each tenant's own database, and **nothing here
iterates tenants** — that is the tenancy plugin's business. Such a deployment
runs the deliverer once per tenant with the port rebound, like any other
per-tenant command.

## Testing

```bash
HKM_KERNEL_PATH=/path/to/hkm-kernel vendor/bin/phpunit
```

The integration suite needs the kernel's own `vendor/` — it runs this plugin's
real migration through LetMigrate and points a real `DatabasePort` at the result.

## Verified / not verified

**Verified**: 177 tests, 336 assertions. `ground check --strict` clean.

The integration suite runs the real SQL against the schema this plugin's own
migration produces, on SQLite. Three properties are established there that no
in-memory double can show:

- **The claim.** Two repositories over one database claim the same row; exactly
  one wins and the loser does not POST.
- **The join in `due()`.** It is the only thing that makes pausing an endpoint
  actually stop the POSTs; a double that filters in PHP proves nothing about the
  query that runs in production.
- **The failure streak.** `consecutive_failures + 1` is computed by the
  database, so two deliverers failing against one endpoint at once cannot lose
  an increment — and the streak is what decides the pause.

**Fifteen behaviours confirmed load-bearing by reverting them**, including
per-segment wildcard matching (4 failures), the timestamp in the signed string
(3), the replay window (2), the claim predicate (9 errors), the endpoint-status
join (5), the backoff predicate (5), 410-is-permanent (1), the backoff ceiling
(1), a success clearing the streak (1), refusing an empty secret (1), the https
requirement (1), refusing internal hosts (8), and `**` not matching zero
segments (1).

**Two reverts initially passed, and both were real:**

- **`\r` was not being stripped from the response excerpt.** The character class
  was the usual "keep tab and newline" one, `\x00-\x08\x0B\x0C\x0E-\x1F`, which
  skips `0x0D` entirely — that class comes from XML and JSON text handling where
  CRLF is ordinary, and it is wrong when the threat is a terminal. The comment
  above it claimed CR was handled. Found by writing the test this class did not
  have; fixed, and now pinned.
- **`hash_equals` cannot be pinned by a behaviour test.** It and `===` return
  the same boolean for every input; the difference is timing. There is a
  guardrail test asserting the source still uses it, which is the only check
  that can exist.

**Not verified:**

- **No HTTP request has ever been sent.** The transport is covered by reading
  only. Every delivery test uses a fake, so what is established is the retry,
  pause and signing POLICY — not that the three options actually reach cURL.
  This is the largest gap, and the `block_private` option itself is tested in
  `hkm-plugin-http-client`, not from here.
- **No receiver has ever verified a signature.** `Signature::verify()` is tested
  against `Signature::sign()`, which proves they agree with each other. A
  receiver in another language reimplementing it from the documented string is
  untested, which is why there is a test spelling that string out literally.
- **Only SQLite.** No MySQL, no PostgreSQL. The statements avoid dialect-specific
  grammar deliberately, but "portable by construction" is an argument, not a
  measurement. The thing most worth checking on MySQL is that `execute()` reports
  **1** for a winning claim.
- **No real concurrency.** The claim race and the streak increment are proven
  with two sequential statements against one database — which is what makes
  them atomic — not with two processes running at once.
- **No command has been run**, and no scheduler has run the declared tasks. The
  entries parse and compute correct due times against the kernel's own
  `CronExpression`, and that is all.
- **`EncryptionPort` is exercised only through Ground's `FakeEncrypter`**, which
  is not a real cipher. Key rotation is untested.
- **The `prune()` status filters mask each other**, as in the outbox: the suite
  passes with either one removed. Both are kept and the comment explains what
  each is for.

## License

MIT — see [LICENSE](LICENSE).
