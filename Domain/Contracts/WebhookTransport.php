<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain\Contracts;

use Plugins\Webhooks\Domain\DeliveryResult;

/**
 * Posting a signed body to somebody else's URL.
 *
 * A seam rather than a direct `HttpClientPort` call in the service, because the
 * service's job is the retry and pause POLICY and every test of that policy
 * would otherwise need a live socket.
 *
 * An implementation MUST NOT throw. A receiver that is down, slow, or returning
 * nonsense is the normal case here, not an exception — so every outcome comes
 * back as a {@see DeliveryResult}, including a refused URL and a timeout.
 */
interface WebhookTransport
{
    /**
     * @param array<string, string> $headers
     */
    public function send(string $url, string $body, array $headers, int $timeoutSeconds): DeliveryResult;

    /** One line for status output. Never a secret. */
    public function describe(): string;
}
