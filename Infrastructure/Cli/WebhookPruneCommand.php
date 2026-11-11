<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Webhooks\API\Contracts\WebhookContract;

/**
 * webhooks:prune — delete settled deliveries past the retention window.
 *
 * DELETES NOTHING WITHOUT `--yes`. This is the only command here that destroys
 * data, and the rows it would wrongly remove are the evidence of what was sent
 * to whom — which is exactly what gets asked for when a customer disputes
 * whether they were notified. A prompt would be worse: this belongs in cron,
 * where a prompt either blocks forever or is answered by whatever is on stdin.
 *
 * Only `delivered` and `failed` rows are eligible. A pending or claimed
 * delivery is still owed to its receiver however old it is.
 */
final class WebhookPruneCommand extends AbstractCommand
{
    public function __construct(
        private readonly WebhookContract $webhooks,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->name        = 'webhooks:prune';
        $this->description = 'Delete settled webhook deliveries older than the retention window';

        $this->addOption('days', 'd', 'Override the retention window, in days', acceptsValue: true);
        $this->addOption('yes', 'y', 'Actually delete. Without this, nothing is deleted');
    }

    protected function handle(): int
    {
        $days   = $this->option('days');
        $days   = $days === null ? null : max(1, (int) $days);
        $window = $days === null ? 'the configured retention window' : "{$days} day(s)";

        $counts  = $this->webhooks->counts();
        $settled = ($counts['delivered'] ?? 0) + ($counts['failed'] ?? 0);
        $owed    = ($counts['pending'] ?? 0) + ($counts['claimed'] ?? 0);

        if (!$this->hasOption('yes')) {
            $this->info("Would delete delivered and failed rows older than {$window}.");
            $this->muted("Settled rows in the table: {$settled} (not all are necessarily older than the window).");
            $this->muted("Still owed, and never pruned: {$owed}.");
            $this->newLine();
            $this->warning('Nothing was deleted. Re-run with --yes to delete.');

            return self::SUCCESS;
        }

        $deleted = $this->webhooks->prune($days);

        if ($deleted === 0) {
            $this->success('Nothing was old enough to prune.');

            return self::SUCCESS;
        }

        $this->success("Deleted {$deleted} settled delivery(ies) older than {$window}.");

        // Deletion runs in bounded batches so one invocation cannot hold a long
        // lock on the deliverer's own hot table. Hitting the ceiling is normal
        // on a table nobody has pruned yet, and the operator needs to know to
        // run it again rather than assume it finished.
        if ($deleted >= 100_000) {
            $this->warning('The per-run ceiling was reached — run it again to continue.');
        }

        return self::SUCCESS;
    }
}
