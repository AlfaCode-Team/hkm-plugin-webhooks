<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Support;

use Plugins\Webhooks\Application\Ports\WebhookStore;
use Plugins\Webhooks\Domain\EndpointStatus;
use Plugins\Webhooks\Domain\PendingDelivery;
use Plugins\Webhooks\Domain\WebhookEndpoint;

/**
 * A WebhookStore over arrays, for driving the fan-out and retry/pause POLICY.
 *
 * Deliberately not forgiving: {@see claim()} refuses a row that is not pending
 * and {@see due()} excludes rows whose endpoint is not receiving, exactly as the
 * real `WHERE` clauses and the real join do. A permissive double would let the
 * service pass tests the repository's own predicates would fail — which is the
 * whole reason the integration suite exists as well.
 */
final class InMemoryWebhookStore implements WebhookStore
{
    /** @var array<string, WebhookEndpoint> */
    public array $endpoints = [];

    /** @var array<int, array<string, mixed>> */
    public array $deliveries = [];

    /** @var array<string, int> */
    public array $failureStreaks = [];

    /** Row ids whose next claim loses the race, as if another deliverer won. */
    /** @var list<int> */
    public array $claimsLostFor = [];

    /** @var list<string> */
    public array $log = [];

    /**
     * Endpoint ids to delete immediately AFTER due() has built its list.
     *
     * Simulates the one race the `findEndpoint() === null` branch in the
     * service exists for. It cannot be reached any other way: `due()` joins the
     * endpoints table, so a deleted endpoint's rows are already excluded — the
     * branch only fires when an endpoint is removed between the read and the
     * per-row lookup, which a single-threaded test cannot otherwise produce.
     *
     * @var list<string>
     */
    public array $deleteAfterDue = [];

    private int $nextRow = 1;

    private const PENDING   = 0;
    private const DELIVERED = 1;
    private const FAILED    = 2;
    private const CLAIMED   = 3;

    // ── endpoints ─────────────────────────────────────────────────────────────

    public function saveEndpoint(WebhookEndpoint $endpoint): void
    {
        $this->endpoints[$endpoint->id] = $endpoint;
        $this->log[] = 'saveEndpoint';
    }

    public function findEndpoint(string $id): ?WebhookEndpoint
    {
        $endpoint = $this->endpoints[$id] ?? null;

        if ($endpoint === null) {
            return null;
        }

        // Rebuilt so the streak the store has recorded is what the caller sees,
        // mirroring a real read.
        return WebhookEndpoint::of(
            id:                  $endpoint->id,
            url:                 $endpoint->url,
            patterns:            $endpoint->patterns,
            secret:              $endpoint->secret,
            status:              $endpoint->status,
            consecutiveFailures: $this->failureStreaks[$id] ?? 0,
            description:         $endpoint->description,
        );
    }

    /** @return list<WebhookEndpoint> */
    public function allEndpoints(): array
    {
        return array_values(array_map(
            fn (WebhookEndpoint $e): WebhookEndpoint => $this->findEndpoint($e->id) ?? $e,
            $this->endpoints,
        ));
    }

    /** @return list<WebhookEndpoint> */
    public function receivingEndpoints(): array
    {
        return array_values(array_filter(
            $this->allEndpoints(),
            static fn (WebhookEndpoint $e): bool => $e->isReceiving(),
        ));
    }

    public function setEndpointStatus(string $id, EndpointStatus $status): void
    {
        $current = $this->endpoints[$id] ?? null;

        if ($current === null) {
            return;
        }

        $this->endpoints[$id] = WebhookEndpoint::of(
            id:                  $current->id,
            url:                 $current->url,
            patterns:            $current->patterns,
            secret:              $current->secret,
            status:              $status,
            consecutiveFailures: $this->failureStreaks[$id] ?? 0,
            description:         $current->description,
        );

        $this->log[] = "status:{$id}:{$status->value}";
    }

    public function recordEndpointFailure(string $id): int
    {
        $this->failureStreaks[$id] = ($this->failureStreaks[$id] ?? 0) + 1;

        return $this->failureStreaks[$id];
    }

    public function clearEndpointFailures(string $id): void
    {
        $this->failureStreaks[$id] = 0;
        $this->log[] = "clearStreak:{$id}";
    }

    public function deleteEndpoint(string $id): bool
    {
        if (!isset($this->endpoints[$id])) {
            return false;
        }

        unset($this->endpoints[$id]);

        return true;
    }

    // ── deliveries ────────────────────────────────────────────────────────────

    public function enqueue(
        string $deliveryId,
        string $endpointId,
        string $eventName,
        string $eventId,
        string $bodyJson,
        \DateTimeImmutable $at,
    ): bool {
        foreach ($this->deliveries as $row) {
            if ($row['delivery_id'] === $deliveryId) {
                return false;
            }
        }

        $rowId = $this->nextRow++;

        $this->deliveries[$rowId] = [
            'id'              => $rowId,
            'delivery_id'     => $deliveryId,
            'endpoint_id'     => $endpointId,
            'event_name'      => $eventName,
            'event_id'        => $eventId,
            'body'            => $bodyJson,
            'status'          => self::PENDING,
            'attempts'        => 0,
            'next_attempt_at' => $at,
            'last_error'      => null,
            'response_status' => null,
            'claimed_at'      => null,
        ];

        $this->log[] = "enqueue:{$endpointId}";

        return true;
    }

    /** @return list<PendingDelivery> */
    public function due(\DateTimeImmutable $now, int $limit): array
    {
        $due = [];

        foreach ($this->deliveries as $row) {
            if ($row['status'] !== self::PENDING) {
                continue;
            }

            if ($row['next_attempt_at'] instanceof \DateTimeImmutable && $row['next_attempt_at'] > $now) {
                continue;
            }

            // The real query JOINs the endpoints table on an active status.
            // Without this, pausing an endpoint would not stop the POSTs.
            $endpoint = $this->endpoints[$row['endpoint_id']] ?? null;

            if ($endpoint === null || !$endpoint->isReceiving()) {
                continue;
            }

            $due[] = $row;
        }

        usort($due, static fn (array $a, array $b): int => $a['id'] <=> $b['id']);

        // The race window: the rows have been read, and now the endpoint goes.
        foreach ($this->deleteAfterDue as $id) {
            unset($this->endpoints[$id]);
        }
        $this->deleteAfterDue = [];

        return array_map(
            static fn (array $row): PendingDelivery => new PendingDelivery(
                rowId:      (int) $row['id'],
                id:         (string) $row['delivery_id'],
                endpointId: (string) $row['endpoint_id'],
                eventName:  (string) $row['event_name'],
                eventId:    (string) $row['event_id'],
                bodyJson:   (string) $row['body'],
                attempts:   (int) $row['attempts'],
            ),
            array_slice($due, 0, max(1, $limit)),
        );
    }

    public function claim(int $rowId, string $owner, \DateTimeImmutable $at): bool
    {
        if (\in_array($rowId, $this->claimsLostFor, true)) {
            return false;
        }

        if (($this->deliveries[$rowId]['status'] ?? null) !== self::PENDING) {
            return false;
        }

        $this->deliveries[$rowId]['status']     = self::CLAIMED;
        $this->deliveries[$rowId]['claimed_at'] = $at;
        $this->log[] = "claim:{$rowId}";

        return true;
    }

    public function markDelivered(
        int $rowId,
        int $status,
        string $responseExcerpt,
        float $durationMs,
        \DateTimeImmutable $at,
    ): void {
        if (($this->deliveries[$rowId]['status'] ?? null) !== self::CLAIMED) {
            return;
        }

        $this->deliveries[$rowId]['status']          = self::DELIVERED;
        $this->deliveries[$rowId]['response_status'] = $status;
        $this->deliveries[$rowId]['attempts']++;
        $this->deliveries[$rowId]['next_attempt_at'] = null;
        $this->log[] = "delivered:{$rowId}";
    }

    public function recordFailure(
        int $rowId,
        int $attempts,
        ?int $status,
        string $reason,
        string $responseExcerpt,
        float $durationMs,
        ?\DateTimeImmutable $nextAttemptAt,
        bool $park,
    ): void {
        $this->deliveries[$rowId]['status']          = $park ? self::FAILED : self::PENDING;
        $this->deliveries[$rowId]['attempts']        = $attempts;
        $this->deliveries[$rowId]['response_status'] = $status;
        $this->deliveries[$rowId]['last_error']      = $reason;
        $this->deliveries[$rowId]['next_attempt_at'] = $nextAttemptAt;
        $this->deliveries[$rowId]['claimed_at']      = null;
        $this->log[] = ($park ? 'parked:' : 'retry:') . $rowId;
    }

    public function reclaimStale(\DateTimeImmutable $cutoff): int
    {
        $reclaimed = 0;

        foreach ($this->deliveries as $id => $row) {
            if ($row['status'] !== self::CLAIMED) {
                continue;
            }

            if (!$row['claimed_at'] instanceof \DateTimeImmutable || $row['claimed_at'] >= $cutoff) {
                continue;
            }

            $this->deliveries[$id]['status']          = self::PENDING;
            $this->deliveries[$id]['attempts']++;
            $this->deliveries[$id]['claimed_at']      = null;
            $this->deliveries[$id]['next_attempt_at'] = $cutoff;
            $reclaimed++;
        }

        return $reclaimed;
    }

    /** @return array<string, int> */
    public function counts(): array
    {
        $counts = ['pending' => 0, 'delivered' => 0, 'failed' => 0, 'claimed' => 0];
        $labels  = [
            self::PENDING   => 'pending',
            self::DELIVERED => 'delivered',
            self::FAILED    => 'failed',
            self::CLAIMED   => 'claimed',
        ];

        foreach ($this->deliveries as $row) {
            $label = $labels[$row['status']] ?? null;

            if ($label !== null) {
                $counts[$label]++;
            }
        }

        return $counts;
    }

    public function retryParked(int $limit, \DateTimeImmutable $at): int
    {
        $released = 0;

        foreach ($this->deliveries as $id => $row) {
            if ($released >= $limit) {
                break;
            }

            if ($row['status'] !== self::FAILED) {
                continue;
            }

            $this->deliveries[$id]['status']          = self::PENDING;
            $this->deliveries[$id]['attempts']        = 0;
            $this->deliveries[$id]['last_error']      = null;
            $this->deliveries[$id]['next_attempt_at'] = $at;
            $released++;
        }

        return $released;
    }

    public function prune(\DateTimeImmutable $before): int
    {
        $deleted = 0;

        foreach ($this->deliveries as $id => $row) {
            if (\in_array($row['status'], [self::DELIVERED, self::FAILED], true)) {
                unset($this->deliveries[$id]);
                $deleted++;
            }
        }

        return $deleted;
    }

    public function describe(): string
    {
        return 'in-memory webhooks';
    }

    // ── test helpers ──────────────────────────────────────────────────────────

    public function seedEndpoint(
        string $id,
        array $patterns,
        string $url = 'https://example.com/hook',
        EndpointStatus $status = EndpointStatus::Active,
        string $secret = 'a-secret-long-enough-to-be-accepted-xx',
    ): WebhookEndpoint {
        $endpoint = WebhookEndpoint::of($id, $url, $patterns, $secret, $status);
        $this->endpoints[$id] = $endpoint;

        return $endpoint;
    }

    /** @return array<string, mixed> */
    public function row(int $rowId): array
    {
        return $this->deliveries[$rowId] ?? [];
    }

    public function statusOf(string $endpointId): ?EndpointStatus
    {
        return ($this->endpoints[$endpointId] ?? null)?->status;
    }

    /** @return list<array<string, mixed>> */
    public function allRows(): array
    {
        return array_values($this->deliveries);
    }
}
