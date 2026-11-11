<?php

declare(strict_types=1);

namespace Plugins\Webhooks\API\Contracts;

use Plugins\Webhooks\Domain\DeliveryReport;
use Plugins\Webhooks\Domain\WebhookEndpoint;

/**
 * Registering receivers for application events, and delivering to them.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * HOW EVENTS GET HERE
 * ──────────────────────────────────────────────────────────────────────────
 * This plugin subscribes to `EventBus::ALL`. It cannot enumerate the event
 * names it wants, because they belong to other plugins and a webhook consumer
 * is installed precisely because nobody knows in advance what the application
 * emits. Every dispatched event is matched against the registered patterns and
 * a delivery is queued for each endpoint that subscribed.
 *
 * Queued, never sent inline. A POST to somebody else's server belongs nowhere
 * near a request: it would make the response time depend on their uptime, and
 * their timeout would become ours.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * PAIR IT WITH `event.outbox` FOR DURABILITY
 * ──────────────────────────────────────────────────────────────────────────
 * The subscription fires at DISPATCH time, which is after the commit. So an
 * event dispatched directly to the EventBus is lost if the process dies in the
 * window between the commit and this listener — the data is consistent and
 * nobody is ever told.
 *
 * Writing the event to the outbox instead closes that: the event row commits
 * with the state change, the outbox relay dispatches it, and if this listener
 * throws, `EventBus::dispatch()` reports the failure and the outbox re-queues
 * the event rather than consuming it. The two plugins are independent, and
 * together they are end-to-end durable.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * NO ROUTES
 * ──────────────────────────────────────────────────────────────────────────
 * This module declares none. Endpoint management is an authenticated,
 * authorised, usually tenant-scoped operation, and every application models
 * that differently — so the application exposes its own admin routes and calls
 * this contract, rather than inheriting opinions about who may register a
 * webhook.
 */
interface WebhookContract
{
    /**
     * Register a receiver.
     *
     * @param list<string> $eventPatterns dot-separated, where `*` matches one
     *        segment and a trailing `**` matches one or more. See EventPattern.
     * @param string|null  $secret        omit to have a strong one generated —
     *        which is the recommended path. The returned endpoint carries it in
     *        plaintext so it can be shown to the registrant ONCE; it is stored
     *        encrypted when an EncryptionPort is bound.
     *
     * @throws \Plugins\Webhooks\Infrastructure\Exceptions\WebhookException
     *         when the URL or a pattern is unusable, or the secret is too weak.
     */
    public function register(
        string $url,
        array $eventPatterns,
        ?string $secret = null,
        string $description = '',
    ): WebhookEndpoint;

    /**
     * Attempt the deliveries that are due.
     *
     * Safe to run concurrently: rows are claimed one at a time and a deliverer
     * that loses the race skips the row rather than sending a second POST.
     */
    public function deliver(?int $limit = null): DeliveryReport;

    /** @return list<WebhookEndpoint> every endpoint, whatever its status */
    public function endpoints(): array;

    public function endpoint(string $id): ?WebhookEndpoint;

    /**
     * Stop delivering to an endpoint, keeping its queued deliveries.
     *
     * Queued rows are held rather than discarded, so resuming sends what was
     * missed instead of silently dropping it.
     */
    public function pause(string $id): void;

    public function resume(string $id): void;

    /**
     * Stop for good. Requires {@see resume()} by a person to undo, and is never
     * reversed automatically.
     */
    public function disable(string $id): void;

    public function delete(string $id): bool;

    /**
     * Put parked deliveries back in the queue, and resume endpoints that were
     * paused automatically.
     *
     * Does NOT re-enable a `disabled` endpoint: that state means somebody
     * decided, or the receiver answered 410 Gone, and undoing it is a decision
     * rather than a retry.
     *
     * @return int how many deliveries were released.
     */
    public function retryParked(?int $limit = null): int;

    /** @return array<string, int> delivery counts by status, zeros present */
    public function counts(): array;

    /** Delete settled deliveries past the retention window. */
    public function prune(?int $olderThanDays = null): int;

    /** One line for status output. Never a secret or a DSN. */
    public function describe(): string;
}
