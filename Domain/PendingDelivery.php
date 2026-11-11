<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * One queued delivery: this event, to this endpoint.
 *
 * The payload is carried as raw JSON for two separate reasons, and the second
 * one is the load-bearing one:
 *
 *   A corrupt row parks itself instead of taking the batch down with it, as in
 *   the outbox.
 *
 *   THE SIGNATURE IS OVER THESE EXACT BYTES. Decoding and re-encoding would
 *   change key order, unicode escaping and float formatting, so the body that
 *   was signed and the body that is sent would differ and every signature would
 *   be rejected — the single most common way webhook verification fails in the
 *   wild. Nothing between the database and the socket is allowed to
 *   re-serialise it.
 *
 * `id` is the DELIVERY id and is stable across retries, so it is what a
 * receiver dedupes on. `attempt` changes; the id does not.
 */
final readonly class PendingDelivery
{
    public function __construct(
        public int $rowId,
        public string $id,
        public string $endpointId,
        public string $eventName,
        public string $eventId,
        public string $bodyJson,
        public int $attempts,
    ) {}
}
