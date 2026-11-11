<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Integration;

use AlfacodeTeam\Ground\Fakes\FakeEncrypter;
use AlfacodeTeam\Ground\Fakes\MigratedSqlite;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Webhooks\Domain\EndpointStatus;
use Plugins\Webhooks\Domain\WebhookEndpoint;
use Plugins\Webhooks\Infrastructure\Persistence\WebhookRepository;

/**
 * The real SQL, against the schema this plugin's own migration produces.
 *
 * Three things are established here that no in-memory double can show:
 *
 *   The CLAIM. Two repositories over one database claim the same row and
 *   exactly one wins — which is what stops a second POST into somebody else's
 *   system.
 *
 *   The JOIN in `due()`. It is the only thing that makes pausing an endpoint
 *   actually stop the POSTs, and a double that filters in PHP proves nothing
 *   about the query that runs in production.
 *
 *   The failure STREAK. `consecutive_failures = consecutive_failures + 1` is
 *   computed by the database on purpose: two deliverers failing against one
 *   endpoint at once must not lose an increment, because the streak is what
 *   decides whether the endpoint is paused.
 */
#[CoversClass(WebhookRepository::class)]
final class WebhookRepositoryTest extends TestCase
{
    private ?MigratedSqlite $db = null;
    private WebhookRepository $store;

    protected function setUp(): void
    {
        $this->db    = MigratedSqlite::migrated(\dirname(__DIR__, 2) . '/database/migrations', 'webhooks');
        $this->store = new WebhookRepository($this->db);
    }

    protected function tearDown(): void
    {
        // Guarded: tearDown still runs after a failure in setUp, and an
        // unguarded access would replace the real error with "must not be
        // accessed before initialization".
        $this->db?->discard();
        $this->db = null;
    }

    private function at(string $moment): \DateTimeImmutable
    {
        return new \DateTimeImmutable($moment);
    }

    private function endpoint(
        string $id,
        array $patterns = ['user.*'],
        EndpointStatus $status = EndpointStatus::Active,
        string $secret = 'a-secret-long-enough-to-be-accepted-xx',
    ): WebhookEndpoint {
        $endpoint = WebhookEndpoint::of($id, 'https://example.com/' . $id, $patterns, $secret, $status);
        $this->store->saveEndpoint($endpoint);

        return $endpoint;
    }

    private function queue(string $deliveryId, string $endpointId, string $due = '2026-11-11 12:00:00'): int
    {
        $this->store->enqueue(
            deliveryId: $deliveryId,
            endpointId: $endpointId,
            eventName:  'user.registered',
            eventId:    'evt-' . $deliveryId,
            bodyJson:   '{"ok":true}',
            at:         $this->at($due),
        );

        $row = $this->db?->queryOne(
            'SELECT id FROM webhook_deliveries WHERE delivery_id = :id',
            ['id' => $deliveryId],
        );

        return (int) ($row['id'] ?? 0);
    }

    // ── The schema ────────────────────────────────────────────────────────────

    public function test_the_migration_creates_both_tables_with_the_columns_the_sql_names(): void
    {
        foreach ([
            'webhook_endpoints' => [
                'id', 'url', 'event_patterns', 'secret', 'secret_encrypted',
                'status', 'consecutive_failures', 'description', 'created_at', 'updated_at',
            ],
            'webhook_deliveries' => [
                'id', 'delivery_id', 'endpoint_id', 'event_name', 'event_id', 'body',
                'status', 'attempts', 'next_attempt_at', 'response_status',
                'response_excerpt', 'last_error', 'duration_ms', 'claimed_by',
                'claimed_at', 'delivered_at', 'created_at',
            ],
        ] as $table => $expected) {
            $columns = array_map(
                static fn (array $c): string => (string) $c['name'],
                $this->db?->query("PRAGMA table_info({$table})") ?? [],
            );

            foreach ($expected as $column) {
                self::assertContains($column, $columns, "{$table}.{$column} must exist");
            }
        }
    }

    // ── Endpoints ─────────────────────────────────────────────────────────────

    public function test_an_endpoint_round_trips(): void
    {
        $this->endpoint('ep-1', ['user.*', 'invoice.**']);

        $loaded = $this->store->findEndpoint('ep-1');

        self::assertNotNull($loaded);
        self::assertSame('ep-1', $loaded->id);
        self::assertSame(['user.*', 'invoice.**'], $loaded->patternStrings());
        self::assertSame('a-secret-long-enough-to-be-accepted-xx', $loaded->secret);
        self::assertSame(EndpointStatus::Active, $loaded->status);
    }

    public function test_saving_the_same_id_updates_rather_than_failing(): void
    {
        // The id is the primary key, so a plain INSERT would raise a constraint
        // violation on a change to an existing endpoint.
        $this->endpoint('ep-1', ['user.*']);
        $this->store->saveEndpoint(WebhookEndpoint::of(
            'ep-1',
            'https://moved.example.com/hook',
            ['invoice.*'],
            'another-secret-long-enough-to-pass-xx',
        ));

        $loaded = $this->store->findEndpoint('ep-1');

        self::assertSame('https://moved.example.com/hook', $loaded?->url);
        self::assertSame(['invoice.*'], $loaded?->patternStrings());
    }

    public function test_receiving_endpoints_exclude_paused_and_disabled(): void
    {
        $this->endpoint('ep-active');
        $this->endpoint('ep-paused', status: EndpointStatus::Paused);
        $this->endpoint('ep-disabled', status: EndpointStatus::Disabled);

        $ids = array_map(static fn (WebhookEndpoint $e): string => $e->id, $this->store->receivingEndpoints());

        self::assertSame(['ep-active'], $ids);
        self::assertCount(3, $this->store->allEndpoints(), 'but all three are still listed');
    }

    public function test_a_secret_is_encrypted_at_rest_when_a_port_is_bound(): void
    {
        $store = new WebhookRepository($this->db, new FakeEncrypter());

        $store->saveEndpoint(WebhookEndpoint::of(
            'ep-1',
            'https://example.com/hook',
            ['user.*'],
            'the-real-signing-secret-long-enough-x',
        ));

        $raw = $this->db?->queryOne('SELECT secret, secret_encrypted FROM webhook_endpoints WHERE id = :id', ['id' => 'ep-1']);

        self::assertStringNotContainsString('the-real-signing-secret', (string) $raw['secret'], 'a DB dump must not yield it');
        self::assertSame(1, (int) $raw['secret_encrypted']);

        // And it comes back usable, because the HMAC needs the original bytes.
        self::assertSame('the-real-signing-secret-long-enough-x', $store->findEndpoint('ep-1')?->secret);
    }

    public function test_a_plaintext_row_still_reads_after_an_encryption_port_is_added(): void
    {
        // The flag is per ROW, not a global assumption. A deployment that adds
        // the port later would otherwise treat its existing plaintext secrets
        // as ciphertext, and every receiver's signature check would start
        // failing with nothing in the application looking broken.
        $this->endpoint('ep-plain', secret: 'stored-before-encryption-was-on-xxxx');

        $withPort = new WebhookRepository($this->db, new FakeEncrypter());

        self::assertSame('stored-before-encryption-was-on-xxxx', $withPort->findEndpoint('ep-plain')?->secret);
    }

    public function test_an_encrypted_row_with_no_port_is_dropped_rather_than_signed_with_ciphertext(): void
    {
        // Signing with the ciphertext would produce a valid-looking HMAC that no
        // receiver on earth can verify. Dropping the endpoint is visible in
        // `webhooks:endpoints`; a silently wrong signature is not.
        $encrypting = new WebhookRepository($this->db, new FakeEncrypter());
        $encrypting->saveEndpoint(WebhookEndpoint::of(
            'ep-1',
            'https://example.com/hook',
            ['user.*'],
            'the-real-signing-secret-long-enough-x',
        ));

        self::assertNull($this->store->findEndpoint('ep-1'));
    }

    public function test_a_corrupt_endpoint_row_is_dropped_and_the_others_still_load(): void
    {
        // This is on the path of EVERY event in the application, so one bad row
        // must not stop every other endpoint receiving.
        $this->endpoint('ep-good');
        $this->endpoint('ep-bad');
        $this->db?->execute(
            "UPDATE webhook_endpoints SET event_patterns = '{not json' WHERE id = 'ep-bad'",
        );

        $ids = array_map(static fn (WebhookEndpoint $e): string => $e->id, $this->store->receivingEndpoints());

        self::assertSame(['ep-good'], $ids);
    }

    public function test_an_unknown_status_reads_as_disabled_never_active(): void
    {
        // The only two readings are "stop sending" and "post to this URL
        // anyway", and the second cannot be taken back.
        $this->endpoint('ep-1');
        $this->db?->execute("UPDATE webhook_endpoints SET status = 'gibberish' WHERE id = 'ep-1'");

        self::assertSame(EndpointStatus::Disabled, $this->store->findEndpoint('ep-1')?->status);
        self::assertSame([], $this->store->receivingEndpoints());
    }

    // ── The failure streak ────────────────────────────────────────────────────

    public function test_the_failure_streak_is_counted_by_the_database(): void
    {
        $this->endpoint('ep-1');

        self::assertSame(1, $this->store->recordEndpointFailure('ep-1'));
        self::assertSame(2, $this->store->recordEndpointFailure('ep-1'));

        // Two deliverers, two independent repositories, one endpoint. The
        // increment must not be lost — it is what decides the pause.
        $rival = new WebhookRepository($this->db);
        self::assertSame(3, $rival->recordEndpointFailure('ep-1'));
        self::assertSame(4, $this->store->recordEndpointFailure('ep-1'));

        $this->store->clearEndpointFailures('ep-1');
        self::assertSame(0, $this->store->findEndpoint('ep-1')?->consecutiveFailures);
    }

    // ── due(): the join is the whole point ────────────────────────────────────

    public function test_due_excludes_rows_whose_endpoint_is_not_receiving(): void
    {
        // Without the join, pausing an endpoint would leave its rows due, the
        // deliverer would claim them, and the only thing stopping delivery
        // would be a check inside the loop — by which point the row has burned
        // an attempt every run.
        $this->endpoint('ep-active');
        $this->endpoint('ep-paused', status: EndpointStatus::Paused);
        $this->queue('d-active', 'ep-active');
        $this->queue('d-paused', 'ep-paused');

        $due = $this->store->due($this->at('2026-11-11 12:00:00'), 100);

        self::assertCount(1, $due);
        self::assertSame('d-active', $due[0]->id);
    }

    public function test_due_excludes_a_row_whose_backoff_has_not_elapsed(): void
    {
        $this->endpoint('ep-1');
        $this->queue('d-later', 'ep-1', '2026-11-11 12:05:00');

        self::assertSame([], $this->store->due($this->at('2026-11-11 12:00:00'), 100));
        self::assertCount(1, $this->store->due($this->at('2026-11-11 12:05:00'), 100));
    }

    public function test_due_returns_oldest_first_and_honours_the_limit(): void
    {
        $this->endpoint('ep-1');
        $this->queue('d-3', 'ep-1', '2026-11-11 11:03:00');
        $this->queue('d-1', 'ep-1', '2026-11-11 11:01:00');
        $this->queue('d-2', 'ep-1', '2026-11-11 11:02:00');

        $ids = array_map(
            static fn ($d): string => $d->id,
            $this->store->due($this->at('2026-11-11 12:00:00'), 2),
        );

        self::assertSame(['d-1', 'd-2'], $ids);
    }

    public function test_queuing_the_same_delivery_id_twice_does_not_duplicate_or_throw(): void
    {
        $this->endpoint('ep-1');

        self::assertSame(1, $this->queue('d-1', 'ep-1'));

        $again = $this->store->enqueue(
            'd-1',
            'ep-1',
            'user.registered',
            'evt-x',
            '{}',
            $this->at('2026-11-11 12:00:00'),
        );

        self::assertFalse($again, 'an idempotent no-op, not a constraint violation');
        self::assertSame(1, (int) $this->db?->queryOne('SELECT COUNT(*) AS n FROM webhook_deliveries')['n']);
    }

    // ── Claiming ──────────────────────────────────────────────────────────────

    public function test_only_one_of_two_deliverers_can_claim_the_same_row(): void
    {
        // THE headline property. A duplicate here is a second POST into
        // somebody else's system, which may charge them or ship something twice.
        $this->endpoint('ep-1');
        $rowId = $this->queue('d-1', 'ep-1');
        $rival = new WebhookRepository($this->db);

        $mine   = $this->store->claim($rowId, 'deliverer-a', $this->at('2026-11-11 12:00:01'));
        $theirs = $rival->claim($rowId, 'deliverer-b', $this->at('2026-11-11 12:00:01'));

        self::assertTrue($mine);
        self::assertFalse($theirs, 'the loser must NOT be allowed to POST');

        $row = $this->db?->queryOne('SELECT claimed_by FROM webhook_deliveries WHERE id = :id', ['id' => $rowId]);
        self::assertSame('deliverer-a', $row['claimed_by']);
    }

    public function test_a_claimed_row_is_no_longer_due(): void
    {
        $this->endpoint('ep-1');
        $rowId = $this->queue('d-1', 'ep-1');

        $this->store->claim($rowId, 'deliverer-a', $this->at('2026-11-11 12:00:01'));

        self::assertSame([], $this->store->due($this->at('2026-11-11 12:00:02'), 100));
    }

    public function test_mark_delivered_refuses_a_row_this_deliverer_does_not_hold(): void
    {
        $this->endpoint('ep-1');
        $rowId = $this->queue('d-1', 'ep-1');

        $this->store->markDelivered($rowId, 200, 'ok', 1.0, $this->at('2026-11-11 12:00:02'));

        $row = $this->db?->queryOne('SELECT status FROM webhook_deliveries WHERE id = :id', ['id' => $rowId]);
        self::assertSame(0, (int) $row['status'], 'a pending row must not be settleable without a claim');
    }

    public function test_mark_delivered_records_the_outcome(): void
    {
        $this->endpoint('ep-1');
        $rowId = $this->queue('d-1', 'ep-1');
        $this->store->claim($rowId, 'deliverer-a', $this->at('2026-11-11 12:00:01'));

        $this->store->markDelivered($rowId, 201, 'created', 42.7, $this->at('2026-11-11 12:00:02'));

        $row = $this->db?->queryOne('SELECT * FROM webhook_deliveries WHERE id = :id', ['id' => $rowId]);
        self::assertSame(1, (int) $row['status']);
        self::assertSame(201, (int) $row['response_status']);
        self::assertSame('created', $row['response_excerpt']);
        self::assertSame(43, (int) $row['duration_ms']);
        self::assertSame(1, (int) $row['attempts']);
        self::assertNull($row['claimed_by']);
    }

    public function test_record_failure_schedules_or_parks(): void
    {
        $this->endpoint('ep-1');
        $retry = $this->queue('d-retry', 'ep-1');
        $park  = $this->queue('d-park', 'ep-1');

        $this->store->claim($retry, 'a', $this->at('2026-11-11 12:00:01'));
        $this->store->claim($park, 'a', $this->at('2026-11-11 12:00:01'));

        $this->store->recordFailure($retry, 1, 503, 'HTTP 503', 'later', 5.0, $this->at('2026-11-11 12:01:00'), false);
        $this->store->recordFailure($park, 10, null, 'timed out', '', 15000.0, null, true);

        $retryRow = $this->db?->queryOne('SELECT * FROM webhook_deliveries WHERE id = :id', ['id' => $retry]);
        self::assertSame(0, (int) $retryRow['status']);
        self::assertSame('2026-11-11 12:01:00', $retryRow['next_attempt_at']);
        self::assertSame(503, (int) $retryRow['response_status']);

        $parkRow = $this->db?->queryOne('SELECT * FROM webhook_deliveries WHERE id = :id', ['id' => $park]);
        self::assertSame(2, (int) $parkRow['status']);
        self::assertNull($parkRow['next_attempt_at']);
        self::assertNull($parkRow['response_status'], 'a transport failure records no status, not 0');
    }

    public function test_a_long_error_is_truncated_rather_than_failing_the_write(): void
    {
        $this->endpoint('ep-1');
        $rowId = $this->queue('d-1', 'ep-1');
        $this->store->claim($rowId, 'a', $this->at('2026-11-11 12:00:01'));

        $this->store->recordFailure($rowId, 1, 500, str_repeat('x', 5000), '', 1.0, null, true);

        $row = $this->db?->queryOne('SELECT last_error FROM webhook_deliveries WHERE id = :id', ['id' => $rowId]);
        self::assertSame(1000, mb_strlen((string) $row['last_error']));
    }

    // ── The lease ─────────────────────────────────────────────────────────────

    public function test_a_stale_claim_is_reclaimed_and_a_fresh_one_is_not(): void
    {
        $this->endpoint('ep-1');
        $stale = $this->queue('d-stale', 'ep-1');
        $fresh = $this->queue('d-fresh', 'ep-1');

        $this->store->claim($stale, 'dead', $this->at('2026-11-11 11:00:00'));
        $this->store->claim($fresh, 'live', $this->at('2026-11-11 12:00:00'));

        self::assertSame(1, $this->store->reclaimStale($this->at('2026-11-11 11:30:00')));

        $staleRow = $this->db?->queryOne('SELECT * FROM webhook_deliveries WHERE id = :id', ['id' => $stale]);
        self::assertSame(0, (int) $staleRow['status']);
        self::assertSame(1, (int) $staleRow['attempts'], 'a reclaim costs an attempt');
        self::assertNull($staleRow['claimed_at']);

        $freshRow = $this->db?->queryOne('SELECT status FROM webhook_deliveries WHERE id = :id', ['id' => $fresh]);
        self::assertSame(3, (int) $freshRow['status'], 'a deliverer working right now keeps its claim');
    }

    // ── Operator surface ──────────────────────────────────────────────────────

    public function test_counts_report_each_status_with_zeros_present(): void
    {
        $this->endpoint('ep-1');
        $delivered = $this->queue('d-1', 'ep-1');
        $this->queue('d-2', 'ep-1');
        $this->store->claim($delivered, 'a', $this->at('2026-11-11 12:00:01'));
        $this->store->markDelivered($delivered, 200, 'ok', 1.0, $this->at('2026-11-11 12:00:02'));

        self::assertSame(
            ['pending' => 1, 'delivered' => 1, 'failed' => 0, 'claimed' => 0],
            $this->store->counts(),
        );
    }

    public function test_retry_parked_releases_rows_and_resets_their_attempts(): void
    {
        $this->endpoint('ep-1');

        foreach (['a', 'b', 'c'] as $n) {
            $rowId = $this->queue('d-' . $n, 'ep-1');
            $this->store->claim($rowId, 'x', $this->at('2026-11-11 12:00:01'));
            $this->store->recordFailure($rowId, 10, 500, 'gave up', '', 1.0, null, true);
        }

        self::assertSame(2, $this->store->retryParked(2, $this->at('2026-11-11 12:10:00')));
        self::assertSame(
            ['pending' => 2, 'delivered' => 0, 'failed' => 1, 'claimed' => 0],
            $this->store->counts(),
        );

        $row = $this->db?->queryOne('SELECT attempts, next_attempt_at FROM webhook_deliveries WHERE status = 0 LIMIT 1');
        self::assertSame(0, (int) $row['attempts']);
        self::assertSame('2026-11-11 12:10:00', $row['next_attempt_at']);
    }

    public function test_prune_deletes_settled_rows_and_never_an_owed_one(): void
    {
        // The one row prune must never touch is a delivery still owed —
        // deleting one is losing a notification somebody is entitled to.
        $this->endpoint('ep-1');

        $old = $this->queue('d-old', 'ep-1', '2026-01-01 00:00:00');
        $this->store->claim($old, 'a', $this->at('2026-01-01 00:00:01'));
        $this->store->markDelivered($old, 200, 'ok', 1.0, $this->at('2026-01-01 00:00:02'));

        $this->queue('d-pending', 'ep-1', '2026-01-01 00:00:00');
        $claimed = $this->queue('d-claimed', 'ep-1', '2026-01-01 00:00:00');
        $this->store->claim($claimed, 'a', $this->at('2026-01-01 00:00:01'));

        self::assertSame(1, $this->store->prune($this->at('2026-06-01 00:00:00')));
        self::assertSame(
            ['pending' => 1, 'delivered' => 0, 'failed' => 0, 'claimed' => 1],
            $this->store->counts(),
        );
    }

    public function test_prune_on_an_empty_table_is_zero_not_a_syntax_error(): void
    {
        // An empty `IN ()` is a syntax error on every driver, which is why the
        // id batch falls back to `IN (0)`.
        self::assertSame(0, $this->store->prune($this->at('2026-06-01 00:00:00')));
    }

    public function test_deleting_an_endpoint_keeps_its_delivery_history(): void
    {
        $this->endpoint('ep-1');
        $this->queue('d-1', 'ep-1');

        self::assertTrue($this->store->deleteEndpoint('ep-1'));
        self::assertFalse($this->store->deleteEndpoint('ep-1'), 'a second delete reports nothing removed');

        self::assertSame(1, (int) $this->db?->queryOne('SELECT COUNT(*) AS n FROM webhook_deliveries')['n']);
        self::assertSame([], $this->store->due($this->at('2026-11-11 12:00:00'), 100), 'but nothing is attempted');
    }

    public function test_describe_names_the_dialect_and_the_secret_posture(): void
    {
        self::assertStringContainsString('sqlite', $this->store->describe());
        self::assertStringContainsString('PLAINTEXT', $this->store->describe());

        $encrypting = new WebhookRepository($this->db, new FakeEncrypter());
        self::assertStringContainsString('secrets encrypted', $encrypting->describe());
    }
}
