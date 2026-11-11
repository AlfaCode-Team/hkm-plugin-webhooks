<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\Webhooks\API\Contracts\WebhookContract;

/**
 * webhooks:endpoints — list registered receivers, and intervene in one.
 *
 * REGISTERING is deliberately not here. It needs a URL, a pattern list and a
 * secret that must be shown to the registrant exactly once, and it is almost
 * always tenant-scoped — so it belongs in the application's own admin surface
 * calling `WebhookContract::register()`, where there is a session to authorise
 * it and somewhere to display the secret. A CLI that minted secrets would put
 * them in shell history.
 */
final class WebhookEndpointsCommand extends AbstractCommand
{
    public function __construct(
        private readonly WebhookContract $webhooks,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->name        = 'webhooks:endpoints';
        $this->description = 'List webhook endpoints, or pause/resume/disable one';

        $this->addOption('pause', '', 'Stop delivering to this endpoint id', acceptsValue: true);
        $this->addOption('resume', '', 'Start delivering to this endpoint id again', acceptsValue: true);
        $this->addOption('disable', '', 'Stop for good; needs an explicit resume', acceptsValue: true);
        $this->addOption('delete', '', 'Remove this endpoint id entirely', acceptsValue: true);
        $this->addOption('yes', 'y', 'Confirm a --delete');
    }

    protected function handle(): int
    {
        foreach (['pause', 'resume', 'disable'] as $action) {
            $id = $this->option($action);

            if ($id !== null) {
                return $this->apply($action, (string) $id);
            }
        }

        $id = $this->option('delete');

        if ($id !== null) {
            return $this->delete((string) $id);
        }

        return $this->list();
    }

    private function apply(string $action, string $id): int
    {
        if ($this->webhooks->endpoint($id) === null) {
            $this->error("No endpoint [{$id}].");

            return self::FAILURE;
        }

        match ($action) {
            'pause'   => $this->webhooks->pause($id),
            'resume'  => $this->webhooks->resume($id),
            'disable' => $this->webhooks->disable($id),
        };

        $this->success("Endpoint [{$id}] is now " . match ($action) {
            'pause'   => 'paused. Queued deliveries are HELD, not dropped.',
            'resume'  => 'active, with its failure streak cleared.',
            'disable' => 'disabled. Nothing will resume it automatically.',
        });

        return self::SUCCESS;
    }

    private function delete(string $id): int
    {
        $endpoint = $this->webhooks->endpoint($id);

        if ($endpoint === null) {
            $this->error("No endpoint [{$id}].");

            return self::FAILURE;
        }

        if (!$this->hasOption('yes')) {
            // Shown rather than prompted: this may run in a script, where a
            // prompt either blocks or is auto-answered by whatever is on stdin.
            $described = $endpoint->describe();
            $this->warning("Would delete endpoint [{$id}] — {$described['url']}");
            $this->muted('Its delivery history is kept. Re-run with --yes to delete.');

            return self::SUCCESS;
        }

        $this->webhooks->delete($id);
        $this->success("Deleted endpoint [{$id}]. Its delivery history is kept.");

        return self::SUCCESS;
    }

    private function list(): int
    {
        $endpoints = $this->webhooks->endpoints();

        if ($endpoints === []) {
            $this->muted('No endpoints registered.');

            return self::SUCCESS;
        }

        foreach ($endpoints as $endpoint) {
            // describe() never includes the secret, and drops the URL's query
            // string — a receiver authenticating by ?token=… would otherwise
            // have its credential printed here and copied into a ticket.
            $d = $endpoint->describe();

            $this->info(sprintf('%-10s %s', $d['status'], $d['id']));
            $this->muted('  ' . $d['url']);
            $this->muted('  events: ' . implode(', ', $d['events']));

            if ($d['consecutiveFailures'] > 0) {
                $this->muted('  consecutive failures: ' . $d['consecutiveFailures']);
            }

            if ($d['description'] !== '') {
                $this->muted('  ' . $d['description']);
            }
        }

        return self::SUCCESS;
    }
}
