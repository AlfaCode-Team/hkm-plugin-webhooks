<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Webhooks\API\Contracts\WebhookContract;

/**
 * webhooks:deliver — attempt the deliveries that are due.
 *
 * Safe to run concurrently and safe on a short interval.
 */
final class WebhookDeliverCommand extends AbstractCommand
{
    public function __construct(
        private readonly WebhookContract $webhooks,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->name        = 'webhooks:deliver';
        $this->description = 'Deliver due webhook events to their endpoints';

        $this->addOption('limit', 'l', 'Max deliveries to attempt this run', acceptsValue: true);
        $this->addOption('quiet-when-idle', '', 'Print nothing when there was no work');
    }

    protected function handle(): int
    {
        $limit  = $this->option('limit');
        $report = $this->webhooks->deliver($limit === null ? null : (int) $limit);

        if ($report->isIdle()) {
            if (!$this->hasOption('quiet-when-idle')) {
                $this->muted('Nothing due.');
            }

            return self::SUCCESS;
        }

        if ($report->delivered > 0) {
            $this->success("Delivered {$report->delivered}.");
        }

        if ($report->reclaimed > 0) {
            // The only place a dead deliverer is ever reported.
            $this->warning(
                "Reclaimed {$report->reclaimed} from a deliverer that never finished — "
                . 'a previous run was killed mid-delivery.',
            );
        }

        if ($report->failed > 0) {
            $this->error("{$report->failed} failed and will be retried with backoff.");
        }

        if ($report->exhausted > 0) {
            $this->error(
                "{$report->exhausted} ran out of attempts and are parked. They will NOT be "
                . 'retried — see `webhooks:status`, then `webhooks:retry`.',
            );
        }

        if ($report->paused > 0) {
            // This changes what a receiver gets from now on, not just this run.
            $this->error(
                "{$report->paused} endpoint(s) were PAUSED after too many consecutive failures. "
                . 'Queued deliveries are held, not dropped; `webhooks:retry` resumes them.',
            );
        }

        if ($report->disabled > 0) {
            $this->error(
                "{$report->disabled} endpoint(s) were DISABLED — the receiver answered 410 Gone, "
                . 'or the URL was refused. Re-enabling is a decision: `webhooks:endpoints --resume=ID`.',
            );
        }

        if ($report->lost > 0) {
            $this->muted("{$report->lost} were claimed by another deliverer first.");
        }

        // Non-zero only for the things that will not fix themselves. A
        // transient failure is not a failed run, and a supervisor restarting on
        // a non-zero exit would restart the deliverer because somebody else's
        // server was briefly down.
        return $report->needsAttention() ? self::FAILURE : self::SUCCESS;
    }
}
