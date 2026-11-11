<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Webhooks\API\Contracts\WebhookContract;
use Plugins\Webhooks\Domain\EndpointStatus;

/**
 * webhooks:status — queue depth and endpoint health.
 *
 * Exits non-zero when deliveries are parked or an endpoint is not receiving, so
 * it works as a monitoring check without anything parsing its output.
 */
final class WebhookStatusCommand extends AbstractCommand
{
    public function __construct(
        private readonly WebhookContract $webhooks,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->name        = 'webhooks:status';
        $this->description = 'Show webhook queue depth and endpoint health';
    }

    protected function handle(): int
    {
        $counts    = $this->webhooks->counts();
        $endpoints = $this->webhooks->endpoints();

        $this->section('Webhooks');
        // describe() carries the table, the dialect, the tuning and whether
        // secrets are encrypted — never a secret, a host or a DSN.
        $this->muted($this->webhooks->describe());
        $this->newLine();

        $this->info('Deliveries');
        foreach ($counts as $label => $total) {
            $this->info(sprintf('  %-11s %d', $label, $total));
        }

        $notReceiving = array_values(array_filter(
            $endpoints,
            static fn ($e): bool => !$e->isReceiving(),
        ));

        $this->newLine();
        $this->info('Endpoints: ' . \count($endpoints) . ' registered, '
            . (\count($endpoints) - \count($notReceiving)) . ' receiving');

        foreach ($notReceiving as $endpoint) {
            // describe() drops the secret and the URL's query string, which is
            // where a receiver that authenticates by ?token=… put a credential.
            $described = $endpoint->describe();

            $this->warning(sprintf(
                '  %s  %s  %s',
                $described['status'],
                $described['id'],
                $described['url'],
            ));

            if ($endpoint->status === EndpointStatus::Paused) {
                $this->muted('    paused automatically — `webhooks:retry` resumes it');
            } else {
                $this->muted('    disabled by a decision or a 410 — `webhooks:endpoints --resume=…`');
            }
        }

        $parked  = $counts['failed'] ?? 0;
        $claimed = $counts['claimed'] ?? 0;

        $this->newLine();

        if ($claimed > 0) {
            $this->muted(
                "{$claimed} claimed. That is a deliverer working if it clears on the next run, "
                . 'and one that died if it does not — `webhooks:deliver` reclaims those.',
            );
        }

        if ($parked > 0) {
            $this->error("{$parked} delivery(ies) parked after exhausting their attempts.");
        }

        if ($parked === 0 && $notReceiving === []) {
            $this->success('All endpoints receiving, nothing parked.');

            return self::SUCCESS;
        }

        return self::FAILURE;
    }
}
