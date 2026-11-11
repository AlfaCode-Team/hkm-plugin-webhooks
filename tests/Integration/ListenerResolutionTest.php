<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Integration;

use AlfacodeTeam\Ground\PluginGround;
use PHPUnit\Framework\TestCase;
use Plugins\Webhooks\Infrastructure\Listeners\EnqueueWebhookListener;
use Plugins\Webhooks\Provider;

/**
 * The listener must be resolvable FROM THE KERNEL SCOPE.
 *
 * This is not a stylistic preference about bindings — it is the difference
 * between a plugin that delivers webhooks and one that delivers none.
 *
 * `EventBus::resolveListener()` does `container->get(EnqueueWebhookListener::class)`
 * and the EventBus is not inside any module's scope. The listener's constructor
 * takes the CONCRETE `WebhookService`, which `register()` binds with
 * `bindInternal()` because `enqueueFor()` is deliberately absent from the
 * published contract. So with no binding for the listener itself, the container
 * autowired it by reflection, reached for that internal binding from scope
 * [kernel], and threw `ScopeViolationException` on EVERY dispatch.
 *
 * Nothing in the unit suite could see that: every unit test constructs the
 * listener directly, which is precisely the one thing production never does.
 * The bug was found by booting the real kernel.
 *
 * Binding the listener publicly fixes it without widening the contract, because
 * ModuleContainer threads a binding's OWNING scope while it resolves — so the
 * nested `make(WebhookService::class)` runs as scope [webhook.delivery].
 */
final class ListenerResolutionTest extends TestCase
{
    private ?\AlfacodeTeam\Ground\BootedGround $ground = null;

    protected function tearDown(): void
    {
        $this->ground?->destroy();
        $this->ground = null;
    }

    public function test_the_event_listener_resolves_from_the_kernel_scope(): void
    {
        // Booting resolves this plugin's requires[], so the sibling modules must
        // be present. They are not a dependency of the rest of the suite.
        $siblings = [
            'Plugins\\HttpClient\\Provider',
            'Plugins\\Database\\Provider',
            'Plugins\\Outbox\\Provider',
            'Plugins\\Mail\\Provider',
        ];

        foreach ($siblings as $sibling) {
            if (!class_exists($sibling)) {
                self::markTestSkipped("Sibling checkout for [{$sibling}] is absent.");
            }
        }

        $this->ground = PluginGround::for(Provider::class, ...$siblings)->boot();

        // 'kernel' is the caller scope EventBus resolves under. Before the
        // listener was bound, this line threw ScopeViolationException.
        $listener = $this->ground->makeFromScope(EnqueueWebhookListener::class, 'kernel');

        self::assertInstanceOf(
            EnqueueWebhookListener::class,
            $listener,
            'EventBus resolves the listener from the kernel scope; if that throws, no webhook is ever delivered.',
        );
    }
}
