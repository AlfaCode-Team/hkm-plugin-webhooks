<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Listeners;

use AlfacodeTeam\PhpServicePlatform\Kernel\Events\Contracts\EventListenerContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\Contracts\IntegrationEventContract;
use Plugins\Webhooks\Application\Services\WebhookService;

/**
 * Subscribed to `EventBus::ALL`. Turns every dispatched event into queued
 * deliveries for the endpoints that asked for it.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * IT RUNS ON EVERY DISPATCH, SO IT HAS TO DECIDE FAST
 * ──────────────────────────────────────────────────────────────────────────
 * A wildcard subscriber is called for every event in the application, so the
 * common case — no endpoint subscribes to this one — must cost almost nothing.
 * `WebhookService::enqueueFor()` reads the receiving endpoints and returns
 * immediately when there are none or none match, before building any payload.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * IT DELIBERATELY DOES NOT CATCH
 * ──────────────────────────────────────────────────────────────────────────
 * Swallowing a failure here is the one thing that would make this silently
 * lossy. `EventBus::dispatch()` isolates and REPORTS a listener failure, and
 * when the event arrived through `event.outbox` that report is what makes the
 * outbox re-queue the event instead of marking it delivered. Catching would
 * convert "the deliveries could not be queued" into "the event was handled",
 * and the webhook would never be sent by anything.
 *
 * So a database failure propagates, the bus records it, and the event is
 * retried from wherever it came. For an application dispatching straight to the
 * bus with no outbox, the event is lost on a crash in this window — which is
 * the reason the two plugins are documented as a pair.
 */
final readonly class EnqueueWebhookListener implements EventListenerContract
{
    public function __construct(
        private WebhookService $webhooks,
    ) {}

    public function handle(IntegrationEventContract $event): void
    {
        $this->webhooks->enqueueFor($event);
    }
}
