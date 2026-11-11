<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Gateways;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use Plugins\Webhooks\Domain\Contracts\WebhookTransport;
use Plugins\Webhooks\Domain\DeliveryResult;

/**
 * Posts a signed body through `HttpClientPort`. Vendor SDK only — no database,
 * no services.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE THREE OPTIONS ARE THE WHOLE POINT OF THIS CLASS
 * ──────────────────────────────────────────────────────────────────────────
 * The URL came from a USER, which makes every default wrong:
 *
 *   `block_private`      The HTTP client allows private and reserved ranges by
 *                        default, because a first-party gateway legitimately
 *                        calls an internal service. Here that default means a
 *                        tenant can register `http://169.254.169.254/latest/
 *                        meta-data/` and have the platform POST to it and log
 *                        the reply — IAM credentials, read out through a
 *                        webhook delivery log. So the destination is declared
 *                        untrusted per request, and the guard resolves the name
 *                        and PINS the connection to the addresses it checked,
 *                        which is what closes the rebind window between the
 *                        two.
 *
 *   `max_response_bytes` The app-wide ceiling is generous for pulling a
 *                        document. A receiver's reply is read only to log an
 *                        excerpt, so a hostile one could otherwise hold the
 *                        connection open streaming filler until megabytes were
 *                        buffered, once per delivery, across a whole batch.
 *
 *   `retry` => 0         THIS plugin owns retrying, with persistence and
 *                        exponential backoff. The client's own retry would
 *                        multiply attempts invisibly — three transport retries
 *                        inside ten delivery attempts is thirty POSTs — and
 *                        would spend three times the timeout inside one claim.
 *
 * REDIRECTS ARE NOT FOLLOWED, by the adapter, and that matters here more than
 * anywhere: following a 302 would let a receiver bounce us to an internal
 * address AFTER the guard had approved the public one it was given.
 */
final readonly class HttpWebhookTransport implements WebhookTransport
{
    /** Enough for a receiver's error message, and nothing like a document. */
    public const MAX_RESPONSE_BYTES = 64 * 1024;

    public function __construct(
        private HttpClientPort $http,
        private bool $allowPrivate = false,
    ) {}

    public function send(string $url, string $body, array $headers, int $timeoutSeconds): DeliveryResult
    {
        $started = microtime(true);

        try {
            $response = $this->http->request('POST', $url, [
                'body'               => $body,
                'headers'            => $headers,
                'timeout'            => $timeoutSeconds,
                'connect_timeout'    => min($timeoutSeconds, 10),
                'retry'              => 0,
                'block_private'      => !$this->allowPrivate,
                'max_response_bytes' => self::MAX_RESPONSE_BYTES,
            ]);

            return DeliveryResult::fromResponse(
                $response->status(),
                $response->body(),
                self::elapsed($started),
            );
        } catch (\Throwable $e) {
            // A receiver that is down, slow, or has a broken certificate is the
            // NORMAL case for this class, not an exception — so nothing escapes
            // it. The adapter reports a refused URL on the same channel as a
            // timeout, so both arrive here; both are recorded as retryable, and
            // a URL that is permanently refused exhausts its attempts and parks
            // rather than being distinguished by matching on message text that
            // belongs to another plugin.
            return DeliveryResult::transportFailure($e->getMessage(), self::elapsed($started));
        }
    }

    public function describe(): string
    {
        return 'http' . ($this->allowPrivate ? ' (private addresses ALLOWED)' : '');
    }

    private static function elapsed(float $started): float
    {
        return (microtime(true) - $started) * 1000;
    }
}
