<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Webhooks\API\Contracts\WebhookContract;

/**
 * webhooks:retry — put parked deliveries back, and resume endpoints we paused.
 *
 * The deliberate second step after a receiver has been fixed. It does NOT
 * re-enable a `disabled` endpoint: that state means somebody decided, or the
 * receiver answered 410 Gone, and undoing it because a queue was retried would
 * start posting again to a receiver that asked to be finished with.
 */
final class WebhookRetryCommand extends AbstractCommand
{
    public function __construct(
        private readonly WebhookContract $webhooks,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->name        = 'webhooks:retry';
        $this->description = 'Requeue parked deliveries and resume auto-paused endpoints';

        $this->addOption('limit', 'l', 'Max deliveries to release', acceptsValue: true);
    }

    protected function handle(): int
    {
        $parked = $this->webhooks->counts()['failed'] ?? 0;
        $paused = \count(array_filter(
            $this->webhooks->endpoints(),
            static fn ($e): bool => $e->status->isAutomaticallyResumable(),
        ));

        if ($parked === 0 && $paused === 0) {
            $this->success('Nothing parked and nothing paused.');

            return self::SUCCESS;
        }

        $limit    = $this->option('limit');
        $released = $this->webhooks->retryParked($limit === null ? null : (int) $limit);

        if ($paused > 0) {
            $this->success("Resumed {$paused} auto-paused endpoint(s), failure streaks cleared.");
        }

        if ($released > 0) {
            $this->success("Released {$released} parked delivery(ies); attempts reset.");
        }

        if ($released < $parked) {
            // Said plainly rather than left as two numbers to compare: a batch
            // limit silently leaving rows parked is how a retry gets believed
            // to be complete when it is not.
            $this->warning(($parked - $released) . ' still parked — the batch limit stopped short. Run it again.');
        }

        $this->muted('They go out on the next `webhooks:deliver`.');

        return self::SUCCESS;
    }
}
