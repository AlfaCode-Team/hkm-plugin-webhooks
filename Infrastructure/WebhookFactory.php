<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\ClockPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\EncryptionPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HttpClientPort;
use Plugins\Webhooks\Application\Services\WebhookService;
use Plugins\Webhooks\Infrastructure\Config\WebhookConfig;
use Plugins\Webhooks\Infrastructure\Gateways\HttpWebhookTransport;
use Plugins\Webhooks\Infrastructure\Persistence\WebhookRepository;

/**
 * Assembly in one place.
 *
 * The service is built from two different containers — the request-scoped
 * `ModuleContainer` in `Provider::register()` and the app-lifetime
 * `CoreContainer` on the CLI path — and the one thing that must not differ
 * between them is `allowPrivate`, which is wired into BOTH the transport and
 * the config. Assembling it twice by hand is how one of those two ends up
 * reading a stale default and the delivery path quietly stops refusing private
 * addresses.
 */
final class WebhookFactory
{
    public static function make(
        DatabasePort $db,
        HttpClientPort $http,
        ?WebhookConfig $config = null,
        ?EncryptionPort $encryption = null,
        ?ClockPort $clock = null,
    ): WebhookService {
        $config ??= WebhookConfig::fromEnv();

        return new WebhookService(
            store:     new WebhookRepository($db, $encryption),
            transport: new HttpWebhookTransport($http, allowPrivate: $config->allowPrivate),
            config:    $config,
            clock:     $clock,
        );
    }
}
