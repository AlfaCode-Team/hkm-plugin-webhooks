<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Unit;

use AlfacodeTeam\Ground\Fakes\FrozenClock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Webhooks\Application\Services\WebhookService;
use Plugins\Webhooks\Domain\DeliveryResult;
use Plugins\Webhooks\Domain\EndpointStatus;
use Plugins\Webhooks\Domain\Signature;
use Plugins\Webhooks\Infrastructure\Config\WebhookConfig;
use Plugins\Webhooks\Infrastructure\Exceptions\WebhookException;
use Tests\Plugins\Webhooks\Support\FakeTransport;
use Tests\Plugins\Webhooks\Support\InMemoryWebhookStore;
use Tests\Plugins\Webhooks\Support\TestEvent;

/**
 * Registration, fan-out, and the retry/pause policy.
 */
#[CoversClass(WebhookService::class)]
#[CoversClass(WebhookConfig::class)]
#[CoversClass(DeliveryResult::class)]
final class WebhookServiceTest extends TestCase
{
    private InMemoryWebhookStore $store;
    private FakeTransport $transport;
    private FrozenClock $clock;

    protected function setUp(): void
    {
        $this->store     = new InMemoryWebhookStore();
        $this->transport = new FakeTransport();
        $this->clock     = new FrozenClock('2026-11-11 12:00:00');
    }

    private function service(?WebhookConfig $config = null): WebhookService
    {
        return new WebhookService(
            store:     $this->store,
            transport: $this->transport,
            config:    $config ?? WebhookConfig::of(),
            clock:     $this->clock,
        );
    }

    // ── Registration ──────────────────────────────────────────────────────────

    public function test_registering_generates_a_strong_secret(): void
    {
        // Generated rather than asked for: a secret somebody chooses is one
        // somebody can choose badly, and entropy is its only job.
        $endpoint = $this->service()->register('https://example.com/hook', ['user.*']);

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $endpoint->secret);
        self::assertSame(EndpointStatus::Active, $endpoint->status);
        self::assertSame(['user.*'], $endpoint->patternStrings());
    }

    public function test_http_is_refused_by_default(): void
    {
        // The body is SIGNED, not encrypted. Over http every event's contents
        // cross the network in the clear, and the signature proves authorship
        // rather than confidentiality.
        try {
            $this->service()->register('http://example.com/hook', ['user.*']);
            self::fail('expected a refusal');
        } catch (WebhookException $e) {
            self::assertStringContainsString('not https', $e->getMessage());
            self::assertStringContainsString('in the clear', $e->getMessage());
        }
    }

    public function test_http_is_allowed_when_the_operator_turns_https_off(): void
    {
        $endpoint = $this->service(WebhookConfig::of(requireHttps: false))
            ->register('http://example.com/hook', ['user.*']);

        self::assertSame('http://example.com/hook', $endpoint->url);
    }

    /** @return list<array{string}> */
    public static function internalHosts(): array
    {
        return [
            ['https://localhost/hook'],
            ['https://127.0.0.1/hook'],
            ['https://[::1]/hook'],
            ['https://10.0.0.5/hook'],
            ['https://192.168.1.1/hook'],
            ['https://169.254.169.254/latest/meta-data/'],
            ['https://redis.internal/hook'],
            ['https://app.localhost/hook'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('internalHosts')]
    public function test_an_obviously_internal_host_is_refused(string $url): void
    {
        // The URL came from a USER, so the metadata service and a local Redis
        // are the attack rather than the use case. This check is ADVISORY — DNS
        // can change after registration — and the delivery-time guard is the
        // control; this catches it where the person can still fix it.
        $this->expectException(WebhookException::class);

        $this->service()->register($url, ['user.*']);
    }

    public function test_private_hosts_are_allowed_when_the_operator_asks(): void
    {
        $endpoint = $this->service(WebhookConfig::of(requireHttps: false, allowPrivate: true))
            ->register('http://10.0.0.5/hook', ['user.*']);

        self::assertSame('http://10.0.0.5/hook', $endpoint->url);
    }

    public function test_credentials_in_the_url_are_refused(): void
    {
        // cURL would send them as Basic auth to whatever the host resolves to,
        // and the URL is printed by the status command and stored in a column.
        try {
            $this->service()->register('https://user:pass@example.com/hook', ['user.*']);
            self::fail('expected a refusal');
        } catch (WebhookException $e) {
            self::assertStringContainsString('credentials in the URL', $e->getMessage());
        }
    }

    public function test_a_non_http_scheme_is_refused(): void
    {
        $this->expectException(WebhookException::class);

        $this->service()->register('ftp://example.com/hook', ['user.*']);
    }

    public function test_a_bad_pattern_is_refused_with_the_reason(): void
    {
        // EventPattern throws a plain InvalidArgumentException because the
        // Domain layer imports nothing; the service translates it so the caller
        // gets a 422 with the explanation rather than a 500.
        try {
            $this->service()->register('https://example.com/hook', ['a.**.b']);
            self::fail('expected a refusal');
        } catch (WebhookException $e) {
            self::assertStringContainsString('a.**.b', $e->getMessage());
            self::assertStringContainsString('last segment', $e->getMessage());
        }
    }

    public function test_an_empty_pattern_list_is_refused(): void
    {
        // An endpoint with no patterns would sit in the table looking
        // registered and receive nothing at all.
        $this->expectException(WebhookException::class);

        $this->service()->register('https://example.com/hook', []);
    }

    public function test_a_weak_supplied_secret_is_refused(): void
    {
        try {
            $this->service()->register('https://example.com/hook', ['user.*'], 'short');
            self::fail('expected a refusal');
        } catch (WebhookException $e) {
            self::assertStringContainsString('at least 32 characters', $e->getMessage());
        }
    }

    // ── Fan-out ───────────────────────────────────────────────────────────────

    public function test_an_event_is_queued_for_each_subscribed_endpoint(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $this->store->seedEndpoint('ep-2', ['user.registered']);
        $this->store->seedEndpoint('ep-3', ['invoice.*']);

        $queued = $this->service()->enqueueFor(new TestEvent('user.registered'));

        self::assertSame(2, $queued);
        self::assertCount(2, $this->store->allRows());
    }

    public function test_every_endpoint_receives_byte_identical_bytes(): void
    {
        // The signature is over these exact bytes, and two endpoints subscribed
        // to one event must not somehow receive different payloads.
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $this->store->seedEndpoint('ep-2', ['user.*']);

        $this->service()->enqueueFor(new TestEvent('user.registered', ['userId' => 'u-1']));

        $bodies = array_map(static fn (array $r): string => (string) $r['body'], $this->store->allRows());

        self::assertCount(2, $bodies);
        self::assertSame($bodies[0], $bodies[1]);
    }

    public function test_a_paused_endpoint_is_not_queued_for(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*'], status: EndpointStatus::Paused);

        self::assertSame(0, $this->service()->enqueueFor(new TestEvent('user.registered')));
    }

    public function test_an_unmatched_event_costs_nothing(): void
    {
        // A wildcard subscriber runs on EVERY event in the application, so the
        // common case has to return before any payload is built.
        $this->store->seedEndpoint('ep-1', ['invoice.*']);

        self::assertSame(0, $this->service()->enqueueFor(new TestEvent('user.registered')));
        self::assertSame([], $this->store->allRows());
    }

    public function test_the_body_has_the_documented_envelope(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*']);

        $this->service()->enqueueFor(new TestEvent('user.registered', ['userId' => 'u-1'], '2.0'));

        $body = json_decode((string) $this->store->allRows()[0]['body'], true);

        self::assertSame('user.registered', $body['event']);
        self::assertSame('2.0', $body['version']);
        self::assertSame(['userId' => 'u-1'], $body['data']);
        self::assertSame('2026-11-11T12:00:00+00:00', $body['occurredAt']);
        self::assertArrayHasKey('id', $body);
    }

    public function test_an_outbox_relayed_event_keeps_the_outbox_event_id(): void
    {
        // So the two plugins agree on what "the same event" means, and a
        // redelivery from either side is recognisable as one event. Matched by
        // VALUE, never by importing the outbox's class.
        $this->store->seedEndpoint('ep-1', ['user.*']);

        $this->service()->enqueueFor(new TestEvent('user.registered', [
            '_outbox_event_id' => 'outbox-abc',
            'userId'           => 'u-1',
        ]));

        $row  = $this->store->allRows()[0];
        $body = json_decode((string) $row['body'], true);

        self::assertSame('outbox-abc', $body['id']);
        self::assertSame('outbox-abc', $row['event_id']);
        self::assertSame(
            ['userId' => 'u-1'],
            $body['data'],
            'the envelope key is a transport detail and must not be republished in data',
        );
    }

    public function test_an_unencodable_payload_throws_rather_than_being_swallowed(): void
    {
        // Thrown on purpose: EventBus reports it, and when the event came from
        // the outbox that report is what makes the row re-queue instead of
        // being marked delivered.
        $this->store->seedEndpoint('ep-1', ['bad.*']);

        $this->expectException(\RuntimeException::class);

        $this->service()->enqueueFor(new TestEvent('bad.event', ['h' => fopen('php://memory', 'rb')]));
    }

    // ── Delivery ──────────────────────────────────────────────────────────────

    private function queueOne(string $event = 'user.registered'): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $this->service()->enqueueFor(new TestEvent($event));
    }

    public function test_a_2xx_is_delivered_and_clears_the_failure_streak(): void
    {
        $this->queueOne();
        $this->store->failureStreaks['ep-1'] = 3;

        $report = $this->service()->deliver();

        self::assertSame(1, $report->delivered);
        self::assertSame(1, $this->transport->count());
        self::assertSame(0, $this->store->failureStreaks['ep-1'], 'a flaky receiver must not accumulate to a pause');
    }

    public function test_the_signature_header_verifies_against_the_body_that_was_sent(): void
    {
        // The end-to-end property a receiver depends on, checked with the same
        // published verify() a receiver would call.
        $this->store->seedEndpoint('ep-1', ['user.*'], secret: str_repeat('k', 40));
        $this->service()->enqueueFor(new TestEvent('user.registered'));

        $this->service()->deliver();

        $sent = $this->transport->last();

        self::assertTrue(Signature::verify(
            $sent['headers'][Signature::HEADER],
            $sent['body'],
            str_repeat('k', 40),
            300,
            $this->clock->now(),
        ));
    }

    public function test_the_delivery_id_is_stable_across_retries_and_the_attempt_is_not(): void
    {
        // A receiver that processed attempt 1 and failed to answer in time must
        // be able to recognise attempt 2 as the same delivery and not act twice.
        $this->queueOne();
        $this->transport->alwaysReturn(DeliveryResult::fromResponse(500, 'boom', 1.0));

        $service = $this->service();
        $service->deliver();

        // Past the backoff.
        $this->clock->travel('+10 minutes');
        $service->deliver();

        self::assertSame(2, $this->transport->count());
        self::assertSame(
            $this->transport->header('X-Webhook-Delivery', 0),
            $this->transport->header('X-Webhook-Delivery', 1),
            'the delivery id must not change between attempts',
        );
        self::assertSame('1', $this->transport->header('X-Webhook-Attempt', 0));
        self::assertSame('2', $this->transport->header('X-Webhook-Attempt', 1));
    }

    public function test_a_5xx_schedules_a_retry_rather_than_parking(): void
    {
        $this->queueOne();
        $this->transport->alwaysReturn(DeliveryResult::fromResponse(503, 'later', 1.0));

        $report = $this->service()->deliver();

        self::assertSame(1, $report->failed);
        self::assertSame(0, $report->exhausted);

        $row = $this->store->allRows()[0];
        self::assertSame(0, $row['status'], 'pending, not parked');
        self::assertInstanceOf(\DateTimeImmutable::class, $row['next_attempt_at']);
        self::assertSame('2026-11-11 12:01:00', $row['next_attempt_at']->format('Y-m-d H:i:s'));
    }

    public function test_the_retry_is_not_attempted_before_its_backoff_elapses(): void
    {
        $this->queueOne();
        $this->transport->alwaysReturn(DeliveryResult::fromResponse(503, 'later', 1.0));

        $service = $this->service();
        $service->deliver();

        // 30 seconds into a 60-second backoff.
        $this->clock->travel('+30 seconds');
        self::assertTrue($service->deliver()->isIdle());
        self::assertSame(1, $this->transport->count());

        $this->clock->travel('+31 seconds');
        $service->deliver();
        self::assertSame(2, $this->transport->count());
    }

    public function test_the_backoff_doubles_and_is_capped(): void
    {
        // Computed in the config so the ceiling cannot be forgotten at a call
        // site: without it, attempt 10 of a 60-second base is 8 hours out and
        // attempt 20 is next year.
        $config = WebhookConfig::of(backoffBase: 60, backoffMax: 600);

        self::assertSame(60,  $config->backoffSeconds(1));
        self::assertSame(120, $config->backoffSeconds(2));
        self::assertSame(240, $config->backoffSeconds(3));
        self::assertSame(480, $config->backoffSeconds(4));
        self::assertSame(600, $config->backoffSeconds(5), 'capped');
        self::assertSame(600, $config->backoffSeconds(50), 'still capped, not overflowed');
        self::assertSame(
            600,
            $config->backoffSeconds(1000),
            'a huge attempt count must not overflow to a negative and schedule in the PAST',
        );
    }

    public function test_attempts_run_out_and_the_delivery_is_parked(): void
    {
        $this->queueOne();
        $this->transport->alwaysReturn(DeliveryResult::fromResponse(503, 'later', 1.0));
        $service = $this->service(WebhookConfig::of(maxAttempts: 2, pauseAfterFailures: 0));

        $service->deliver();
        $this->clock->travel('+10 minutes');
        $report = $service->deliver();

        self::assertSame(1, $report->exhausted);
        self::assertSame(2, $this->store->allRows()[0]['status'], 'parked');
    }

    public function test_a_410_disables_the_endpoint_and_does_not_retry(): void
    {
        // The one status with a standard meaning worth honouring: it is how a
        // receiver decommissions an endpoint without reaching into our database.
        $this->queueOne();
        $this->transport->alwaysReturn(DeliveryResult::fromResponse(410, 'gone', 1.0));

        $report = $this->service()->deliver();

        self::assertSame(1, $report->permanent);
        self::assertSame(0, $report->failed);
        self::assertSame(1, $report->disabled);
        self::assertSame(EndpointStatus::Disabled, $this->store->statusOf('ep-1'));
        self::assertSame(2, $this->store->allRows()[0]['status'], 'parked, not scheduled');
    }

    public function test_consecutive_failures_pause_the_endpoint(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $this->transport->alwaysReturn(DeliveryResult::fromResponse(500, 'boom', 1.0));
        $service = $this->service(WebhookConfig::of(pauseAfterFailures: 2));

        // Two separate events, so two separate deliveries fail in turn.
        $service->enqueueFor(new TestEvent('user.a'));
        $service->enqueueFor(new TestEvent('user.b'));

        $report = $service->deliver();

        self::assertSame(1, $report->paused);
        self::assertSame(EndpointStatus::Paused, $this->store->statusOf('ep-1'));
    }

    public function test_a_paused_endpoints_queued_deliveries_are_held_not_dropped(): void
    {
        // Pausing must stop the POSTs without discarding what was owed, so that
        // resuming sends what was missed.
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $service = $this->service();
        $service->enqueueFor(new TestEvent('user.registered'));

        $service->pause('ep-1');
        $report = $service->deliver();

        self::assertTrue($report->isIdle(), 'nothing is attempted');
        self::assertSame(0, $this->transport->count());
        self::assertCount(1, $this->store->allRows(), 'but the row is still there');
        self::assertSame(0, $this->store->allRows()[0]['status'], 'still pending');

        $service->resume('ep-1');
        $service->deliver();

        self::assertSame(1, $this->transport->count(), 'and goes out on resume');
    }

    public function test_a_transport_failure_is_retryable_and_records_no_status(): void
    {
        // `status` stays NULL rather than 0: "the request did not happen" is
        // genuinely different from "the receiver answered 0", and 0 reads as a
        // status in every table that shows it.
        $this->queueOne();
        $this->transport->alwaysReturn(DeliveryResult::transportFailure('connection timed out', 15000.0));

        $report = $this->service()->deliver();

        self::assertSame(1, $report->failed);
        self::assertNull($this->store->allRows()[0]['response_status']);
        self::assertStringContainsString('timed out', (string) $this->store->allRows()[0]['last_error']);
    }

    // ── Concurrency ───────────────────────────────────────────────────────────

    public function test_a_row_another_deliverer_claimed_is_not_sent(): void
    {
        // A duplicate here is a second POST into somebody else's system, which
        // may charge them or page their on-call.
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $service = $this->service();
        $service->enqueueFor(new TestEvent('user.a'));
        $service->enqueueFor(new TestEvent('user.b'));

        $this->store->claimsLostFor = [1];

        $report = $service->deliver();

        self::assertSame(1, $report->lost);
        self::assertSame(1, $report->delivered);
        self::assertSame(1, $this->transport->count());
    }

    public function test_a_dead_deliverers_row_is_reclaimed_and_sent(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $service = $this->service(WebhookConfig::of(claimTimeout: 300));
        $service->enqueueFor(new TestEvent('user.registered'));

        // Claimed an hour ago by something that never came back.
        $this->store->deliveries[1]['status']     = 3;
        $this->store->deliveries[1]['claimed_at'] = new \DateTimeImmutable('2026-11-11 11:00:00');

        $report = $service->deliver();

        self::assertSame(1, $report->reclaimed);
        self::assertSame(1, $report->delivered);
    }

    public function test_an_endpoint_deleted_mid_run_parks_its_row_without_sending(): void
    {
        // The narrow race the null-endpoint branch exists for. `due()` joins
        // the endpoints table, so a deleted endpoint's rows are normally
        // excluded before the loop ever sees them — this branch only fires when
        // the endpoint goes between that read and the per-row lookup. There is
        // nobody to deliver to and no secret to sign with, so the row is
        // parked rather than retried against nothing.
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $service = $this->service();
        $service->enqueueFor(new TestEvent('user.registered'));

        $this->store->deleteAfterDue = ['ep-1'];

        $report = $service->deliver();

        self::assertSame(0, $this->transport->count(), 'nothing may be sent');
        self::assertSame(1, $report->permanent);
        self::assertSame(2, $this->store->allRows()[0]['status'], 'parked, not left to retry forever');
        self::assertStringContainsString('deleted', (string) $this->store->allRows()[0]['last_error']);
    }

    public function test_a_deleted_endpoints_rows_are_not_even_read(): void
    {
        // The ordinary case, which is the join doing its job: a deleted
        // endpoint's queued rows are excluded from `due()` entirely.
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $service = $this->service();
        $service->enqueueFor(new TestEvent('user.registered'));

        $service->delete('ep-1');

        self::assertTrue($service->deliver()->isIdle());
        self::assertSame(0, $this->transport->count());
        self::assertCount(1, $this->store->allRows(), 'the history of what was owed survives the endpoint');
    }

    // ── Operator surface ──────────────────────────────────────────────────────

    public function test_retry_resumes_auto_paused_endpoints_but_never_disabled_ones(): void
    {
        // `disabled` means somebody decided, or the receiver answered 410.
        // Undoing that because a queue was retried would start posting again to
        // a receiver that asked to be finished with.
        $this->store->seedEndpoint('ep-paused', ['user.*'], status: EndpointStatus::Paused);
        $this->store->seedEndpoint('ep-disabled', ['user.*'], status: EndpointStatus::Disabled);

        $this->service()->retryParked();

        self::assertSame(EndpointStatus::Active, $this->store->statusOf('ep-paused'));
        self::assertSame(EndpointStatus::Disabled, $this->store->statusOf('ep-disabled'));
    }

    public function test_resuming_clears_the_failure_streak(): void
    {
        // Otherwise it resumes already most of the way to being paused again,
        // and a single further failure pauses it.
        $this->store->seedEndpoint('ep-1', ['user.*'], status: EndpointStatus::Paused);
        $this->store->failureStreaks['ep-1'] = 9;

        $this->service()->resume('ep-1');

        self::assertSame(0, $this->store->failureStreaks['ep-1']);
    }

    public function test_managing_an_unknown_endpoint_is_refused(): void
    {
        $this->expectException(WebhookException::class);

        $this->service()->pause('nope');
    }

    public function test_counts_report_every_status_even_at_zero(): void
    {
        self::assertSame(
            ['pending' => 0, 'delivered' => 0, 'failed' => 0, 'claimed' => 0],
            $this->service()->counts(),
        );
    }

    public function test_describe_names_the_posture_and_no_secret(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*'], secret: 'super-secret-value-which-is-long-enough');

        $described = $this->service()->describe();

        self::assertStringContainsString('private addresses refused', $described);
        self::assertStringNotContainsString('super-secret-value', $described);
    }

    public function test_describe_says_so_loudly_when_private_addresses_are_allowed(): void
    {
        // An operator reading status output should not have to infer that the
        // SSRF guard has been turned off.
        self::assertStringContainsString(
            'PRIVATE ADDRESSES ALLOWED',
            $this->service(WebhookConfig::of(allowPrivate: true))->describe(),
        );
    }

    public function test_an_endpoints_description_never_carries_the_secret_or_the_query_string(): void
    {
        // A receiver that authenticates by ?token=… has put a credential in the
        // URL, and describe() is what gets printed and copied into tickets.
        $endpoint = $this->store->seedEndpoint(
            'ep-1',
            ['user.*'],
            url: 'https://example.com/hook?token=abc123',
            secret: 'super-secret-value-which-is-long-enough',
        );

        $described = $endpoint->describe();
        $encoded   = (string) json_encode($described);

        self::assertStringNotContainsString('super-secret-value', $encoded);
        self::assertStringNotContainsString('abc123', $encoded);
        self::assertSame('https://example.com/hook?…', $described['url']);
    }

    public function test_an_idle_run_reports_idle(): void
    {
        self::assertTrue($this->service()->deliver()->isIdle());
    }

    public function test_the_batch_limit_is_honoured(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $service = $this->service();

        for ($i = 0; $i < 5; $i++) {
            $service->enqueueFor(new TestEvent('user.e' . $i));
        }

        self::assertSame(2, $service->deliver(limit: 2)->delivered);
        self::assertSame(2, $this->transport->count());
    }

    public function test_the_transport_is_given_the_configured_timeout(): void
    {
        $this->store->seedEndpoint('ep-1', ['user.*']);
        $service = $this->service(WebhookConfig::of(timeout: 7));
        $service->enqueueFor(new TestEvent('user.registered'));

        $service->deliver();

        self::assertSame(7, $this->transport->last()['timeout']);
    }

    public function test_an_endpoint_with_no_secret_is_refused_rather_than_signed_with_nothing(): void
    {
        // An empty secret produces an HMAC anybody can compute, which is worse
        // than sending none because the receiver believes it verified something.
        $this->store->seedEndpoint('ep-1', ['user.*'], secret: '');
        $service = $this->service();
        $service->enqueueFor(new TestEvent('user.registered'));

        $report = $service->deliver();

        self::assertSame(0, $this->transport->count(), 'nothing may be sent');
        self::assertSame(1, $report->permanent);
        self::assertSame(EndpointStatus::Disabled, $this->store->statusOf('ep-1'));
    }
}
