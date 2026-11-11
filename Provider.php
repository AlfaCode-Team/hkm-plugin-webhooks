<?php

declare(strict_types=1);

namespace Plugins\Webhooks;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\CoreContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Contracts\ModuleContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Cli\CliPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\HttpPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Worker\WorkerPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\EncryptionPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use Plugins\Webhooks\API\Contracts\WebhookContract;
use Plugins\Webhooks\Application\Services\WebhookService;
use Plugins\Webhooks\Infrastructure\Cli\WebhookDeliverCommand;
use Plugins\Webhooks\Infrastructure\Cli\WebhookEndpointsCommand;
use Plugins\Webhooks\Infrastructure\Cli\WebhookPruneCommand;
use Plugins\Webhooks\Infrastructure\Cli\WebhookRetryCommand;
use Plugins\Webhooks\Infrastructure\Cli\WebhookStatusCommand;
use Plugins\Webhooks\Infrastructure\Config\WebhookConfig;
use Plugins\Webhooks\Infrastructure\Listeners\EnqueueWebhookListener;
use Plugins\Webhooks\Infrastructure\WebhookFactory;

/**
 * Webhooks — wires the 'webhook.delivery' domain.
 *
 * Requires `http.client`, because outbound HTTP to a URL somebody typed is the
 * entire job and the SSRF guard plus connection pinning in that adapter is what
 * makes it safe to do at all.
 */
final class Provider implements ModuleContract
{
    public function solves(): string
    {
        return 'webhook.delivery';
    }

    /** @return list<string> */
    public function requires(): array
    {
        return ['http.client'];
    }

    /** @return list<class-string> */
    public function exposes(): array
    {
        return [WebhookContract::class];
    }

    public function register(ModuleContainer $container): void
    {
        $container->bindInternal(WebhookConfig::class, static fn (): WebhookConfig => WebhookConfig::fromEnv());

        $container->bind(
            WebhookContract::class,
            static fn (ModuleContainer $c): WebhookService => WebhookFactory::make(
                db:     $c->make(DatabasePort::class),
                http:   $c->make(HttpClientPort::class),
                config: $c->make(WebhookConfig::class),
                // Optional. Without it, secrets are stored in plaintext and
                // describe() says so out loud rather than letting an operator
                // assume otherwise.
                encryption: $c->has(EncryptionPort::class) ? $c->make(EncryptionPort::class) : null,
                clock:      $c->has(ClockPort::class) ? $c->make(ClockPort::class) : null,
            ),
        );

        // The listener's dependency. INTERNAL on purpose: enqueueFor() is the
        // event-ingestion path and is deliberately absent from WebhookContract,
        // because publishing it would let any module inject arbitrary events
        // into the delivery queue.
        $container->bindInternal(
            WebhookService::class,
            static fn (ModuleContainer $c): WebhookService => $c->make(WebhookContract::class),
        );

        // The LISTENER is the published seam, and binding it is load-bearing.
        // EventBus::resolveListener() does container->get(ListenerClass) from
        // the KERNEL scope. With no binding here it autowired the listener by
        // reflection, which reached for the INTERNAL WebhookService above from
        // that kernel scope and threw ScopeViolationException on every single
        // dispatch — so no webhook was ever delivered, and the bus logged it as
        // a failing listener rather than a missing binding.
        //
        // Binding it publicly fixes that without widening the contract:
        // ModuleContainer threads a binding's OWNING scope while it resolves, so
        // the nested make(WebhookService::class) inside this closure runs as
        // scope [webhook.delivery] and reaches the internal binding legally.
        $container->bind(
            EnqueueWebhookListener::class,
            static fn (ModuleContainer $c): EnqueueWebhookListener => new EnqueueWebhookListener(
                $c->make(WebhookService::class),
            ),
        );
    }

    public function boot(HttpPipeline $http, CliPipeline $cli, WorkerPipeline $worker, EventBus $events): void
    {
        // THE wildcard subscription, and the reason EventBus::ALL exists. A
        // webhook consumer cannot enumerate the event names it wants: they
        // belong to other plugins, and this is installed precisely because
        // nobody knows in advance what the application emits. Matching against
        // the registered patterns happens in the service.
        $events->subscribe(EventBus::ALL, EnqueueWebhookListener::class);

        // Instances, not class-strings. A class-string is built from the
        // CoreContainer and a command whose dependencies do not resolve there is
        // SILENTLY NOT REGISTERED — it does not appear in `list` at all. Every
        // command here takes WebhookContract, an interface bound per request,
        // which cannot be autowired by reflection.
        //
        // Deferred, so the DatabasePort and HTTP client behind them are built
        // only on the CLI path: every module's boot() also runs during an HTTP
        // build, and these have no business opening a connection there.
        $cli->defer(static function (CliPipeline $cli): void {
            $webhooks = self::forCli($cli->container());

            $cli->command(new WebhookDeliverCommand($webhooks));
            $cli->command(new WebhookStatusCommand($webhooks));
            $cli->command(new WebhookEndpointsCommand($webhooks));
            $cli->command(new WebhookRetryCommand($webhooks));
            $cli->command(new WebhookPruneCommand($webhooks));
        });
    }

    /**
     * The webhooks service the CLI operates on.
     *
     * Built from the CoreContainer, which for a single-database application is
     * the only connection there is. In a database-per-tenant deployment the
     * endpoints live in each tenant's own database and nothing here iterates
     * tenants — that is the tenancy plugin's business. Such a deployment runs
     * the deliverer once per tenant, with the port rebound, like any other
     * per-tenant command.
     */
    private static function forCli(CoreContainer $core): WebhookService
    {
        return WebhookFactory::make(
            db:         $core->make(DatabasePort::class),
            http:       $core->make(HttpClientPort::class),
            config:     WebhookConfig::fromEnv(),
            encryption: $core->has(EncryptionPort::class) ? $core->make(EncryptionPort::class) : null,
            clock:      $core->has(ClockPort::class) ? $core->make(ClockPort::class) : null,
        );
    }
}
