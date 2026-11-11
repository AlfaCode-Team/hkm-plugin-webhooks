<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Application\Ports;

use Plugins\Webhooks\Domain\EndpointStatus;
use Plugins\Webhooks\Domain\PendingDelivery;
use Plugins\Webhooks\Domain\WebhookEndpoint;

/**
 * Persistence for endpoints and queued deliveries.
 *
 * The same claim/lease shape as the outbox, for the same reason — two
 * deliverers must not both POST the same row — and with more at stake, because
 * a duplicated webhook is visible to somebody else's system and may charge
 * them for it.
 */
interface WebhookStore
{
    // ── endpoints ─────────────────────────────────────────────────────────────

    public function saveEndpoint(WebhookEndpoint $endpoint): void;

    public function findEndpoint(string $id): ?WebhookEndpoint;

    /**
     * Every endpoint, whatever its status.
     *
     * @return list<WebhookEndpoint>
     */
    public function allEndpoints(): array;

    /**
     * Endpoints that are currently receiving.
     *
     * Separate from {@see allEndpoints()} because this one is on the dispatch
     * path, where it runs for every event.
     *
     * @return list<WebhookEndpoint>
     */
    public function receivingEndpoints(): array;

    public function setEndpointStatus(string $id, EndpointStatus $status): void;

    /** Record a failed attempt against the endpoint and return the new streak. */
    public function recordEndpointFailure(string $id): int;

    /** A delivery succeeded: clear the streak. */
    public function clearEndpointFailures(string $id): void;

    public function deleteEndpoint(string $id): bool;

    // ── deliveries ────────────────────────────────────────────────────────────

    /**
     * Queue one delivery.
     *
     * @return bool false when this (delivery id) was already queued, which is a
     *         successful idempotent no-op rather than a failure.
     */
    public function enqueue(
        string $deliveryId,
        string $endpointId,
        string $eventName,
        string $eventId,
        string $bodyJson,
        \DateTimeImmutable $at,
    ): bool;

    /**
     * Deliveries that are due now, oldest first.
     *
     * Must exclude rows whose backoff has not elapsed, and rows belonging to an
     * endpoint that is no longer receiving — otherwise pausing an endpoint
     * would not actually stop the POSTs.
     *
     * @return list<PendingDelivery>
     */
    public function due(\DateTimeImmutable $now, int $limit): array;

    /** @return bool true when THIS caller won the row. */
    public function claim(int $rowId, string $owner, \DateTimeImmutable $at): bool;

    public function markDelivered(
        int $rowId,
        int $status,
        string $responseExcerpt,
        float $durationMs,
        \DateTimeImmutable $at,
    ): void;

    /**
     * Put a row back for another attempt at $nextAttemptAt, or park it when
     * $park is true.
     */
    public function recordFailure(
        int $rowId,
        int $attempts,
        ?int $status,
        string $reason,
        string $responseExcerpt,
        float $durationMs,
        ?\DateTimeImmutable $nextAttemptAt,
        bool $park,
    ): void;

    /** Release rows a dead deliverer is still holding. */
    public function reclaimStale(\DateTimeImmutable $cutoff): int;

    /** @return array<string, int> delivery counts by status label, zeros present */
    public function counts(): array;

    /** Move parked deliveries back into the queue. */
    public function retryParked(int $limit, \DateTimeImmutable $at): int;

    /** Delete settled deliveries older than $before. */
    public function prune(\DateTimeImmutable $before): int;

    /** For status output — never a secret, never a DSN. */
    public function describe(): string;
}
