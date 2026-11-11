<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Persistence;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DriverAware;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\EncryptionPort;
use Plugins\Webhooks\Application\Ports\WebhookStore;
use Plugins\Webhooks\Domain\EndpointStatus;
use Plugins\Webhooks\Domain\PendingDelivery;
use Plugins\Webhooks\Domain\WebhookEndpoint;
use Plugins\Webhooks\Infrastructure\Exceptions\WebhookException;

/**
 * The only thing here that writes SQL. DatabasePort only.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE SECRET AT REST
 * ──────────────────────────────────────────────────────────────────────────
 * A webhook secret has to be DECRYPTABLE, not hashed: the HMAC cannot be
 * computed without the original bytes. So when the application binds an
 * `EncryptionPort` the column holds ciphertext, and `secret_encrypted` records
 * that per row.
 *
 * The flag is per row and not a global assumption, because a deployment that
 * adds the port later would otherwise start treating its existing plaintext
 * secrets as ciphertext — `decrypt()` would throw, or worse succeed on
 * something, and every receiver's signature check would begin failing with
 * nothing in the application looking broken.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * CLAIMING
 * ──────────────────────────────────────────────────────────────────────────
 * The same conditional-UPDATE claim as the outbox, for a sharper reason: a
 * duplicate here is a second POST into somebody else's system, which may charge
 * them, ship something twice, or page their on-call. `UPDATE … WHERE id = :id
 * AND status = 0` is applied atomically, so one deliverer sees one affected row
 * and the rest see none.
 */
final class WebhookRepository implements WebhookStore
{
    public const ENDPOINTS  = 'webhook_endpoints';
    public const DELIVERIES = 'webhook_deliveries';

    private const PENDING   = 0;
    private const DELIVERED = 1;
    private const FAILED    = 2;
    private const CLAIMED   = 3;

    private const ERROR_MAX_CHARS = 1000;
    private const OWNER_MAX_CHARS = 64;

    private const PRUNE_BATCH    = 1000;
    private const PRUNE_MAX_RUNS = 100;

    public function __construct(
        private readonly DatabasePort $db,
        private readonly ?EncryptionPort $encryption = null,
    ) {}

    // ── endpoints ─────────────────────────────────────────────────────────────

    public function saveEndpoint(WebhookEndpoint $endpoint): void
    {
        [$secret, $encrypted] = $this->protect($endpoint->secret);

        try {
            $this->db->upsert(
                self::ENDPOINTS,
                [
                    'id'                   => $endpoint->id,
                    'url'                  => $endpoint->url,
                    'event_patterns'       => json_encode($endpoint->patternStrings(), JSON_THROW_ON_ERROR),
                    'secret'               => $secret,
                    'secret_encrypted'     => $encrypted ? 1 : 0,
                    'status'               => $endpoint->status->value,
                    'consecutive_failures' => $endpoint->consecutiveFailures,
                    'description'          => $endpoint->description,
                    'created_at'           => self::stamp(new \DateTimeImmutable()),
                ],
                conflictColumns: ['id'],
                // Everything but created_at, so re-saving an endpoint updates it
                // rather than failing, and does not rewrite when it was first
                // registered.
                updateColumns: [
                    'url', 'event_patterns', 'secret', 'secret_encrypted',
                    'status', 'consecutive_failures', 'description',
                ],
            );
        } catch (\Throwable $e) {
            throw WebhookException::saveFailed($endpoint->id, $e);
        }
    }

    public function findEndpoint(string $id): ?WebhookEndpoint
    {
        $row = $this->db->queryOne(
            'SELECT * FROM ' . self::ENDPOINTS . ' WHERE id = :id',
            ['id' => $id],
        );

        return $row === null ? null : $this->hydrateEndpoint($row);
    }

    /** @return list<WebhookEndpoint> */
    public function allEndpoints(): array
    {
        return array_values(array_filter(array_map(
            fn (array $row): ?WebhookEndpoint => $this->hydrateEndpoint($row),
            $this->db->query('SELECT * FROM ' . self::ENDPOINTS . ' ORDER BY created_at ASC, id ASC'),
        )));
    }

    /** @return list<WebhookEndpoint> */
    public function receivingEndpoints(): array
    {
        return array_values(array_filter(array_map(
            fn (array $row): ?WebhookEndpoint => $this->hydrateEndpoint($row),
            $this->db->query(
                'SELECT * FROM ' . self::ENDPOINTS . ' WHERE status = :status ORDER BY id ASC',
                ['status' => EndpointStatus::Active->value],
            ),
        )));
    }

    public function setEndpointStatus(string $id, EndpointStatus $status): void
    {
        $this->db->execute(
            'UPDATE ' . self::ENDPOINTS . ' SET status = :status, updated_at = :now WHERE id = :id',
            ['status' => $status->value, 'now' => self::stamp(new \DateTimeImmutable()), 'id' => $id],
        );
    }

    public function recordEndpointFailure(string $id): int
    {
        $this->db->execute(
            'UPDATE ' . self::ENDPOINTS . '
                SET consecutive_failures = consecutive_failures + 1, updated_at = :now
              WHERE id = :id',
            ['now' => self::stamp(new \DateTimeImmutable()), 'id' => $id],
        );

        // Read back rather than counting in PHP. Two deliverers can both fail
        // against one endpoint at once, and `+ 1` in the database is the only
        // version of this that does not lose one of the increments — which is
        // what decides whether the endpoint reaches its pause threshold.
        $row = $this->db->queryOne(
            'SELECT consecutive_failures FROM ' . self::ENDPOINTS . ' WHERE id = :id',
            ['id' => $id],
        );

        return (int) ($row['consecutive_failures'] ?? 0);
    }

    public function clearEndpointFailures(string $id): void
    {
        $this->db->execute(
            'UPDATE ' . self::ENDPOINTS . '
                SET consecutive_failures = 0, updated_at = :now
              WHERE id = :id',
            ['now' => self::stamp(new \DateTimeImmutable()), 'id' => $id],
        );
    }

    public function deleteEndpoint(string $id): bool
    {
        // Queued deliveries are left behind deliberately. They are the record
        // of what was owed, `due()` already skips rows whose endpoint is not
        // receiving, and the deliverer parks one whose endpoint has gone — so
        // nothing is attempted, and the history of what happened survives the
        // endpoint being removed.
        return $this->db->execute(
            'DELETE FROM ' . self::ENDPOINTS . ' WHERE id = :id',
            ['id' => $id],
        ) > 0;
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
        return $this->db->upsert(
            self::DELIVERIES,
            [
                'delivery_id'     => $deliveryId,
                'endpoint_id'     => $endpointId,
                'event_name'      => $eventName,
                'event_id'        => $eventId,
                'body'            => $bodyJson,
                'status'          => self::PENDING,
                'attempts'        => 0,
                // Due immediately. Never NULL: `next_attempt_at <= now` is the
                // whole due predicate, and a NULL would make the row invisible
                // to it forever.
                'next_attempt_at' => self::stamp($at),
                'created_at'      => self::stamp($at),
            ],
            conflictColumns: ['delivery_id'],
            updateColumns: [],
        ) > 0;
    }

    /** @return list<PendingDelivery> */
    public function due(\DateTimeImmutable $now, int $limit): array
    {
        $limit = max(1, min(500, $limit));

        // The join is what makes pausing an endpoint actually stop the POSTs.
        // Without it, pausing would leave its queued rows due, the deliverer
        // would pick them up, and the only thing that stopped delivery would be
        // the endpoint lookup inside the loop — by which point the row has been
        // claimed and burns an attempt every run.
        $rows = $this->db->query(
            'SELECT d.id, d.delivery_id, d.endpoint_id, d.event_name, d.event_id, d.body, d.attempts
               FROM ' . self::DELIVERIES . ' d
               JOIN ' . self::ENDPOINTS . ' e ON e.id = d.endpoint_id
              WHERE d.status = ' . self::PENDING . '
                AND d.next_attempt_at <= :now
                AND e.status = :active
              ORDER BY d.next_attempt_at ASC, d.id ASC
              LIMIT ' . $limit,
            ['now' => self::stamp($now), 'active' => EndpointStatus::Active->value],
        );

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
            $rows,
        );
    }

    public function claim(int $rowId, string $owner, \DateTimeImmutable $at): bool
    {
        return $this->db->execute(
            'UPDATE ' . self::DELIVERIES . '
                SET status = :claimed, claimed_by = :owner, claimed_at = :at
              WHERE id = :id AND status = :pending',
            [
                'claimed' => self::CLAIMED,
                'owner'   => mb_substr($owner, 0, self::OWNER_MAX_CHARS),
                'at'      => self::stamp($at),
                'id'      => $rowId,
                'pending' => self::PENDING,
            ],
        ) === 1;
    }

    public function markDelivered(
        int $rowId,
        int $status,
        string $responseExcerpt,
        float $durationMs,
        \DateTimeImmutable $at,
    ): void {
        $this->db->execute(
            'UPDATE ' . self::DELIVERIES . '
                SET status = :delivered, response_status = :response, response_excerpt = :excerpt,
                    duration_ms = :duration, attempts = attempts + 1, delivered_at = :at,
                    claimed_by = NULL, claimed_at = NULL, last_error = NULL, next_attempt_at = NULL
              WHERE id = :id AND status = :claimed',
            [
                'delivered' => self::DELIVERED,
                'response'  => $status,
                'excerpt'   => $responseExcerpt,
                'duration'  => (int) round($durationMs),
                'at'        => self::stamp($at),
                'id'        => $rowId,
                'claimed'   => self::CLAIMED,
            ],
        );
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
        $this->db->execute(
            'UPDATE ' . self::DELIVERIES . '
                SET status = :status, attempts = :attempts, response_status = :response,
                    response_excerpt = :excerpt, last_error = :error, duration_ms = :duration,
                    next_attempt_at = :next, claimed_by = NULL, claimed_at = NULL
              WHERE id = :id',
            [
                'status'   => $park ? self::FAILED : self::PENDING,
                'attempts' => $attempts,
                'response' => $status,
                'excerpt'  => $responseExcerpt,
                'error'    => mb_substr($reason, 0, self::ERROR_MAX_CHARS),
                'duration' => (int) round($durationMs),
                'next'     => $nextAttemptAt === null ? null : self::stamp($nextAttemptAt),
                'id'       => $rowId,
            ],
        );
    }

    public function reclaimStale(\DateTimeImmutable $cutoff): int
    {
        return $this->db->execute(
            'UPDATE ' . self::DELIVERIES . '
                SET status = :pending, attempts = attempts + 1,
                    claimed_by = NULL, claimed_at = NULL,
                    next_attempt_at = :now,
                    last_error = :note
              WHERE status = :claimed AND claimed_at < :cutoff',
            [
                'pending' => self::PENDING,
                // Due immediately on release. The attempt it is charged is the
                // backoff; adding another delay on top would hold an event that
                // has already waited out a dead deliverer's whole lease.
                'now'     => self::stamp($cutoff),
                'note'    => 'reclaimed: the deliverer that claimed this row never settled it',
                'claimed' => self::CLAIMED,
                'cutoff'  => self::stamp($cutoff),
            ],
        );
    }

    /** @return array<string, int> */
    public function counts(): array
    {
        $counts = ['pending' => 0, 'delivered' => 0, 'failed' => 0, 'claimed' => 0];

        $labels = [
            self::PENDING   => 'pending',
            self::DELIVERED => 'delivered',
            self::FAILED    => 'failed',
            self::CLAIMED   => 'claimed',
        ];

        foreach ($this->db->query('SELECT status, COUNT(*) AS total FROM ' . self::DELIVERIES . ' GROUP BY status') as $row) {
            $label = $labels[(int) $row['status']] ?? null;

            if ($label !== null) {
                $counts[$label] = (int) $row['total'];
            }
        }

        return $counts;
    }

    public function retryParked(int $limit, \DateTimeImmutable $at): int
    {
        $ids = $this->idsWithStatus(self::FAILED, max(1, min(500, $limit)));

        if ($ids === []) {
            return 0;
        }

        return $this->db->execute(
            'UPDATE ' . self::DELIVERIES . '
                SET status = :pending, attempts = 0, last_error = NULL,
                    next_attempt_at = :now, claimed_by = NULL, claimed_at = NULL
              WHERE id IN (' . implode(',', $ids) . ')',
            ['pending' => self::PENDING, 'now' => self::stamp($at)],
        );
    }

    public function prune(\DateTimeImmutable $before): int
    {
        $deleted = 0;

        for ($run = 0; $run < self::PRUNE_MAX_RUNS; $run++) {
            // Only settled rows. A pending or claimed delivery is still owed to
            // its receiver however old it is. Both halves of the restriction are
            // kept for the same reasons as the outbox: the id query makes the
            // batching correct, and the predicate here closes the window where
            // `retryParked()` could have rescued a row between the two.
            $batch = $this->db->execute(
                'DELETE FROM ' . self::DELIVERIES . '
                  WHERE status IN (:delivered, :failed)
                    AND created_at < :before
                    AND id IN (' . implode(',', $this->settledIdsBefore($before)) . ')',
                [
                    'delivered' => self::DELIVERED,
                    'failed'    => self::FAILED,
                    'before'    => self::stamp($before),
                ],
            );

            $deleted += $batch;

            if ($batch < self::PRUNE_BATCH) {
                break;
            }
        }

        return $deleted;
    }

    public function describe(): string
    {
        $driver = $this->db instanceof DriverAware ? $this->db->driver() : 'unknown driver';

        return self::DELIVERIES . ' on ' . $driver
            . ($this->encryption === null ? ' (secrets in PLAINTEXT)' : ' (secrets encrypted)');
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * @param array<string, mixed> $row
     */
    private function hydrateEndpoint(array $row): ?WebhookEndpoint
    {
        $patterns = json_decode((string) $row['event_patterns'], true);

        if (!\is_array($patterns) || $patterns === []) {
            // A row whose patterns cannot be read subscribes to nothing
            // knowable. Returning null drops it from the dispatch set rather
            // than throwing, because one corrupt endpoint row must not stop
            // every OTHER endpoint receiving — and it would, since this is on
            // the path of every event in the application.
            return null;
        }

        try {
            return WebhookEndpoint::of(
                id:                  (string) $row['id'],
                url:                 (string) $row['url'],
                patterns:            array_map('strval', $patterns),
                secret:              $this->reveal((string) $row['secret'], (bool) $row['secret_encrypted']),
                // An unrecognised status becomes Disabled, never Active. The
                // only two readings are "stop sending" and "send to this URL
                // anyway", and the second is the one that cannot be taken back.
                status:              EndpointStatus::tryFrom((string) $row['status']) ?? EndpointStatus::Disabled,
                consecutiveFailures: (int) $row['consecutive_failures'],
                description:         (string) $row['description'],
            );
        } catch (\Throwable) {
            // A pattern that no longer parses, or a secret that will not
            // decrypt after a key was lost. Same reasoning as above: drop this
            // one, keep the others. An endpoint that silently stops receiving
            // is visible in `webhooks:endpoints`, which lists from the table.
            return null;
        }
    }

    /**
     * The secret as it should be stored.
     *
     * @return array{string, bool} the value to store, and whether it is ciphertext
     */
    private function protect(string $secret): array
    {
        if ($this->encryption === null) {
            return [$secret, false];
        }

        return [$this->encryption->encryptString($secret), true];
    }

    private function reveal(string $stored, bool $encrypted): string
    {
        if (!$encrypted) {
            // Stored before an EncryptionPort was bound. Read as-is: treating
            // it as ciphertext would throw, and every receiver's signature
            // check would start failing with nothing looking broken.
            return $stored;
        }

        if ($this->encryption === null) {
            // Ciphertext, and the port that could read it is gone. There is no
            // honest fallback — signing with the ciphertext would produce a
            // valid-looking HMAC that no receiver can verify — so this endpoint
            // is dropped by the caller.
            throw new \RuntimeException(
                'A webhook secret is encrypted but no EncryptionPort is bound.',
            );
        }

        return $this->encryption->decryptString($stored);
    }

    /** @return list<int> */
    private function idsWithStatus(int $status, int $limit): array
    {
        return array_map(
            static fn (array $row): int => (int) $row['id'],
            $this->db->query(
                'SELECT id FROM ' . self::DELIVERIES . '
                  WHERE status = ' . $status . '
                  ORDER BY id ASC
                  LIMIT ' . $limit,
            ),
        );
    }

    /**
     * Returns `[0]` when nothing qualifies: an empty `IN ()` is a syntax error
     * on every driver, and `id` is a positive auto-increment so `IN (0)`
     * matches nothing and the DELETE honestly reports zero.
     *
     * @return non-empty-list<int>
     */
    private function settledIdsBefore(\DateTimeImmutable $before): array
    {
        $ids = array_map(
            static fn (array $row): int => (int) $row['id'],
            $this->db->query(
                'SELECT id FROM ' . self::DELIVERIES . '
                  WHERE status IN (' . self::DELIVERED . ', ' . self::FAILED . ')
                    AND created_at < :before
                  ORDER BY id ASC
                  LIMIT ' . self::PRUNE_BATCH,
                ['before' => self::stamp($before)],
            ),
        );

        return $ids === [] ? [0] : $ids;
    }

    private static function stamp(\DateTimeImmutable $moment): string
    {
        return $moment->format('Y-m-d H:i:s');
    }
}
