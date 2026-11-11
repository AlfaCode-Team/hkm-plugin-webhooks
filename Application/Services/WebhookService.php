<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Events\Contracts\IntegrationEventContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort;
use Plugins\Webhooks\API\Contracts\WebhookContract;
use Plugins\Webhooks\Application\Ports\WebhookStore;
use Plugins\Webhooks\Domain\Contracts\WebhookTransport;
use Plugins\Webhooks\Domain\DeliveryReport;
use Plugins\Webhooks\Domain\DeliveryResult;
use Plugins\Webhooks\Domain\EndpointStatus;
use Plugins\Webhooks\Domain\EventPattern;
use Plugins\Webhooks\Domain\Signature;
use Plugins\Webhooks\Domain\WebhookEndpoint;
use Plugins\Webhooks\Infrastructure\Config\WebhookConfig;
use Plugins\Webhooks\Infrastructure\Exceptions\WebhookException;

/**
 * Registration, fan-out and the retry/pause policy.
 */
final class WebhookService implements WebhookContract
{
    /** Below this, a captured delivery makes the secret brute-forceable offline. */
    public const MIN_SECRET_LENGTH = 32;

    /**
     * The payload key `event.outbox` uses to carry its event id.
     *
     * Matched BY VALUE and not by importing that plugin's class — which is the
     * rule for integration events anyway (primitives only), and which keeps
     * this plugin working whether or not the outbox is installed. When the key
     * is there, the event id a consumer dedupes on is the same one the outbox
     * recorded, so a redelivery from either side is recognisable as the same
     * event.
     */
    private const OUTBOX_ID_KEY = '_outbox_event_id';

    public function __construct(
        private readonly WebhookStore $store,
        private readonly WebhookTransport $transport,
        private readonly WebhookConfig $config,
        private readonly ?ClockPort $clock = null,
    ) {}

    // ── registration ──────────────────────────────────────────────────────────

    public function register(
        string $url,
        array $eventPatterns,
        ?string $secret = null,
        string $description = '',
    ): WebhookEndpoint {
        $url = trim($url);

        $this->assertUrlIsUsable($url);

        if ($eventPatterns === []) {
            throw WebhookException::invalidPattern('', 'an endpoint must subscribe to at least one event');
        }

        $patterns = [];
        foreach ($eventPatterns as $pattern) {
            try {
                $patterns[] = EventPattern::of((string) $pattern);
            } catch (\InvalidArgumentException $e) {
                // Translated at the boundary: EventPattern throws a plain
                // InvalidArgumentException because the Domain layer imports
                // nothing, and a registration failure needs to reach the caller
                // as a 422 with the reason.
                throw WebhookException::invalidPattern((string) $pattern, $e->getMessage());
            }
        }

        if ($secret === null) {
            $secret = self::generateSecret();
        } elseif (\strlen($secret) < self::MIN_SECRET_LENGTH) {
            throw WebhookException::weakSecret(\strlen($secret), self::MIN_SECRET_LENGTH);
        }

        $endpoint = WebhookEndpoint::of(
            id:          self::uuid(),
            url:         $url,
            patterns:    $patterns,
            secret:      $secret,
            status:      EndpointStatus::Active,
            description: $description,
        );

        $this->store->saveEndpoint($endpoint);

        return $endpoint;
    }

    /**
     * Queue a delivery for every endpoint subscribed to this event.
     *
     * Called from the `EventBus::ALL` listener. It MUST be allowed to throw: a
     * failure here is reported by `EventBus::dispatch()`, and when the event
     * came through the outbox that is what makes it re-queue rather than
     * consume — which is the only reason a crash in this method does not lose
     * the event.
     *
     * @return int how many deliveries were queued.
     */
    public function enqueueFor(IntegrationEventContract $event): int
    {
        $endpoints = $this->store->receivingEndpoints();

        if ($endpoints === []) {
            return 0;
        }

        $matching = array_values(array_filter(
            $endpoints,
            static fn (WebhookEndpoint $e): bool => $e->subscribesTo($event->name()),
        ));

        if ($matching === []) {
            return 0;
        }

        // THE BODY IS BUILT ONCE, for every endpoint. Identical bytes mean the
        // signature is over what is actually sent, and mean two endpoints
        // subscribed to one event cannot somehow receive different payloads.
        // The per-endpoint parts — the delivery id, the attempt number, the
        // signature — all travel in HEADERS for exactly that reason.
        $now     = $this->now();
        $eventId = $this->eventIdOf($event);
        $body    = $this->encodeBody($event, $eventId, $now);

        $queued = 0;

        foreach ($matching as $endpoint) {
            $written = $this->store->enqueue(
                deliveryId: self::uuid(),
                endpointId: $endpoint->id,
                eventName:  $event->name(),
                eventId:    $eventId,
                bodyJson:   $body,
                at:         $now,
            );

            if ($written) {
                $queued++;
            }
        }

        return $queued;
    }

    // ── delivery ──────────────────────────────────────────────────────────────

    public function deliver(?int $limit = null): DeliveryReport
    {
        // Release anything a dead deliverer is still holding, before reading
        // the queue — otherwise those rows are invisible to every run forever.
        $reclaimed = $this->store->reclaimStale(
            $this->now()->sub(new \DateInterval('PT' . $this->config->claimTimeout . 'S')),
        );

        $owner     = self::owner();
        $delivered = 0;
        $failed    = 0;
        $permanent = 0;
        $lost      = 0;
        $exhausted = 0;
        $paused    = 0;
        $disabled  = 0;

        foreach ($this->store->due($this->now(), $limit ?? $this->config->batch) as $pending) {
            if (!$this->store->claim($pending->rowId, $owner, $this->now())) {
                // Another deliverer won it. Sending anyway would be a second
                // POST to someone else's system, and possibly a second charge
                // on it.
                $lost++;

                continue;
            }

            $endpoint = $this->store->findEndpoint($pending->endpointId);

            if ($endpoint === null) {
                // The endpoint was deleted after the row was queued. Park it:
                // there is nobody to deliver to, and no secret to sign with.
                $this->store->recordFailure(
                    rowId: $pending->rowId,
                    attempts: $pending->attempts + 1,
                    status: null,
                    reason: 'the endpoint was deleted',
                    responseExcerpt: '',
                    durationMs: 0.0,
                    nextAttemptAt: null,
                    park: true,
                );
                $permanent++;

                continue;
            }

            $result = $this->attempt($endpoint, $pending->id, $pending->bodyJson, $pending->attempts + 1);

            if ($result->isDelivered()) {
                $this->store->markDelivered(
                    $pending->rowId,
                    (int) $result->status,
                    $result->responseExcerpt,
                    $result->durationMs,
                    $this->now(),
                );
                // A success clears the streak, so a receiver that is merely
                // flaky never accumulates its way to a pause.
                $this->store->clearEndpointFailures($endpoint->id);
                $delivered++;

                continue;
            }

            $attempts = $pending->attempts + 1;
            $park     = !$result->outcome->willRetry() || $attempts >= $this->config->maxAttempts;

            $this->store->recordFailure(
                rowId: $pending->rowId,
                attempts: $attempts,
                status: $result->status,
                reason: $result->failureReason,
                responseExcerpt: $result->responseExcerpt,
                durationMs: $result->durationMs,
                nextAttemptAt: $park
                    ? null
                    : $this->now()->add(new \DateInterval('PT' . $this->config->backoffSeconds($attempts) . 'S')),
                park: $park,
            );

            if ($result->outcome->willRetry()) {
                $failed++;

                if ($park) {
                    $exhausted++;
                }
            } else {
                $permanent++;
            }

            // A permanent failure is the receiver telling us to stop (410) or
            // our own guard refusing the URL. Either way retrying is pointless,
            // so the ENDPOINT goes down rather than just this row.
            if (!$result->outcome->willRetry()) {
                $this->store->setEndpointStatus($endpoint->id, EndpointStatus::Disabled);
                $disabled++;

                continue;
            }

            $streak = $this->store->recordEndpointFailure($endpoint->id);

            if ($this->config->pauseAfterFailures > 0 && $streak >= $this->config->pauseAfterFailures) {
                $this->store->setEndpointStatus($endpoint->id, EndpointStatus::Paused);
                $this->store->clearEndpointFailures($endpoint->id);
                $paused++;
            }
        }

        return new DeliveryReport(
            delivered: $delivered,
            failed:    $failed,
            permanent: $permanent,
            lost:      $lost,
            reclaimed: $reclaimed,
            exhausted: $exhausted,
            paused:    $paused,
            disabled:  $disabled,
        );
    }

    /** One POST, signed for this endpoint. */
    private function attempt(
        WebhookEndpoint $endpoint,
        string $deliveryId,
        string $body,
        int $attempt,
    ): DeliveryResult {
        if ($endpoint->secret === '') {
            // Signing with an empty secret produces an HMAC anyone can compute,
            // which is worse than sending none because the receiver believes it
            // verified something.
            return DeliveryResult::refused('the endpoint has no signing secret');
        }

        $signature = Signature::sign($body, $endpoint->secret, $this->now());

        return $this->transport->send(
            $endpoint->url,
            $body,
            [
                'Content-Type'       => 'application/json',
                'User-Agent'         => 'hkm-webhooks/1',
                Signature::HEADER    => $signature->header(),
                // Stable across retries, so a receiver that processed attempt 1
                // and failed to answer in time can recognise attempt 2 as the
                // same delivery and not act twice.
                'X-Webhook-Delivery' => $deliveryId,
                'X-Webhook-Attempt'  => (string) $attempt,
            ],
            $this->config->timeout,
        );
    }

    // ── management ────────────────────────────────────────────────────────────

    /** @return list<WebhookEndpoint> */
    public function endpoints(): array
    {
        return $this->store->allEndpoints();
    }

    public function endpoint(string $id): ?WebhookEndpoint
    {
        return $this->store->findEndpoint($id);
    }

    public function pause(string $id): void
    {
        $this->requireEndpoint($id);
        $this->store->setEndpointStatus($id, EndpointStatus::Paused);
    }

    public function resume(string $id): void
    {
        $this->requireEndpoint($id);
        $this->store->setEndpointStatus($id, EndpointStatus::Active);
        // Without this the endpoint resumes already most of the way to being
        // paused again, and a single further failure would pause it.
        $this->store->clearEndpointFailures($id);
    }

    public function disable(string $id): void
    {
        $this->requireEndpoint($id);
        $this->store->setEndpointStatus($id, EndpointStatus::Disabled);
    }

    public function delete(string $id): bool
    {
        return $this->store->deleteEndpoint($id);
    }

    public function retryParked(?int $limit = null): int
    {
        $released = $this->store->retryParked($limit ?? $this->config->batch, $this->now());

        // Resume endpoints WE paused. A `disabled` one is left alone: somebody
        // decided that, or the receiver answered 410, and undoing it because a
        // queue was retried would re-enable a receiver that asked to be
        // finished with.
        foreach ($this->store->allEndpoints() as $endpoint) {
            if ($endpoint->status->isAutomaticallyResumable()) {
                $this->store->setEndpointStatus($endpoint->id, EndpointStatus::Active);
                $this->store->clearEndpointFailures($endpoint->id);
            }
        }

        return $released;
    }

    /** @return array<string, int> */
    public function counts(): array
    {
        return $this->store->counts();
    }

    public function prune(?int $olderThanDays = null): int
    {
        $days = max(1, $olderThanDays ?? $this->config->pruneAfterDays);

        return $this->store->prune($this->now()->sub(new \DateInterval('P' . $days . 'D')));
    }

    public function describe(): string
    {
        return sprintf(
            '%s via %s — batch %d, %d attempts, %ds timeout, pause after %s, %s',
            $this->store->describe(),
            $this->transport->describe(),
            $this->config->batch,
            $this->config->maxAttempts,
            $this->config->timeout,
            $this->config->pauseAfterFailures === 0 ? 'never' : $this->config->pauseAfterFailures . ' failures',
            $this->config->allowPrivate ? 'PRIVATE ADDRESSES ALLOWED' : 'private addresses refused',
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Structural checks on a URL somebody typed.
     *
     * ADVISORY ONLY, and that is not a weakness to be fixed here — it is why
     * the delivery-time guard exists. DNS can change between the moment a URL
     * is saved and the moment it is fetched, so no check at registration can
     * be authoritative about where the request will end up. What this catches
     * is the honest mistake and the obvious attempt, at the point where the
     * person can still correct it; `HttpWebhookTransport` resolves and pins at
     * delivery, which is the control.
     */
    private function assertUrlIsUsable(string $url): void
    {
        if ($url === '') {
            throw WebhookException::invalidUrl($url, 'it is empty.');
        }

        $parts = parse_url($url);

        if ($parts === false || !isset($parts['host'], $parts['scheme'])) {
            throw WebhookException::invalidUrl($url, 'it is not a URL with a scheme and a host.');
        }

        $scheme = strtolower($parts['scheme']);

        if (!\in_array($scheme, ['http', 'https'], true)) {
            throw WebhookException::invalidUrl($url, "the scheme [{$scheme}] is not http or https.");
        }

        if ($this->config->requireHttps && $scheme !== 'https') {
            throw WebhookException::invalidUrl(
                $url,
                'it is not https. The body is signed, not encrypted, so over http every event\'s '
                . 'contents cross the network in the clear. Set WEBHOOKS_REQUIRE_HTTPS=false only '
                . 'for an endpoint inside a trusted network.',
            );
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            // `https://user:pass@host/` would put a credential in the URL
            // column, every log line and every status table — and cURL would
            // send it as Basic auth to whatever the host resolves to.
            throw WebhookException::invalidUrl(
                $url,
                'it carries credentials in the URL. Use the signing secret, or a header the '
                . 'receiver checks.',
            );
        }

        if (!$this->config->allowPrivate && self::isObviouslyInternal($parts['host'])) {
            throw WebhookException::invalidUrl(
                $url,
                "the host [{$parts['host']}] is a loopback, link-local or private address. Set "
                . 'WEBHOOKS_ALLOW_PRIVATE=true only if this application is meant to post to '
                . 'internal services.',
            );
        }
    }

    /**
     * The cheap half of the check: a host that needs no resolution to reject.
     *
     * Deliberately NOT a reimplementation of the full range check — that lives
     * in the HTTP client's SSRF guard, where it runs against the ADDRESSES the
     * name actually resolves to and pins the connection to them. Duplicating it
     * here would mean two copies of security-critical code that could disagree,
     * and the copy that matters is the one at the socket.
     */
    private static function isObviouslyInternal(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));

        if (\in_array($host, ['localhost', 'localhost.localdomain', '127.0.0.1', '::1', '0.0.0.0'], true)) {
            return true;
        }

        if (str_ends_with($host, '.localhost') || str_ends_with($host, '.internal')) {
            return true;
        }

        // An IP literal can be judged right here, with no DNS at all.
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return filter_var(
                $host,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            ) === false;
        }

        return false;
    }

    /**
     * The event id a consumer dedupes on.
     *
     * Prefers the outbox's id when the event was relayed from there, so the two
     * plugins agree on what "the same event" means.
     */
    private function eventIdOf(IntegrationEventContract $event): string
    {
        $carried = $event->payload()[self::OUTBOX_ID_KEY] ?? null;

        return \is_string($carried) && $carried !== '' ? $carried : self::uuid();
    }

    /**
     * The exact bytes that are signed and sent.
     *
     * The envelope key is dropped from `data`: it is the outbox's transport
     * detail, it is already reported as `id`, and leaving it in would publish
     * an internal field name in every payload.
     */
    private function encodeBody(
        IntegrationEventContract $event,
        string $eventId,
        \DateTimeImmutable $now,
    ): string {
        $data = $event->payload();
        unset($data[self::OUTBOX_ID_KEY]);

        try {
            return json_encode([
                'id'         => $eventId,
                'event'      => $event->name(),
                'version'    => $event->version(),
                'occurredAt' => $now->format(\DateTimeInterface::RFC3339),
                'data'       => $data,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $e) {
            // Thrown, not swallowed: when the event came through the outbox,
            // this is what makes the row re-queue instead of being marked
            // delivered. An integration event is required to carry primitives
            // only, and this is where that is enforced in practice.
            throw new \RuntimeException(sprintf(
                'Webhook payload for [%s] cannot be encoded as JSON: %s',
                $event->name(),
                $e->getMessage(),
            ), 0, $e);
        }
    }

    private function requireEndpoint(string $id): void
    {
        if ($this->store->findEndpoint($id) === null) {
            throw WebhookException::unknownEndpoint($id);
        }
    }

    private function now(): \DateTimeImmutable
    {
        return $this->clock?->now() ?? new \DateTimeImmutable();
    }

    /**
     * 64 hex characters from the CSPRNG.
     *
     * Generated rather than asked for, because a secret somebody chooses is a
     * secret somebody can choose badly, and this one's only job is entropy.
     */
    private static function generateSecret(): string
    {
        return bin2hex(random_bytes(32));
    }

    private static function owner(): string
    {
        return substr(
            (gethostname() ?: 'unknown') . ':' . getmypid() . ':' . bin2hex(random_bytes(3)),
            0,
            64,
        );
    }

    private static function uuid(): string
    {
        $b = random_bytes(16);

        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }
}
