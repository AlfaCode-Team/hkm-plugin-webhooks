<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * Whether an endpoint is receiving.
 *
 * `Paused` and `Disabled` are separate because the way out of them differs, and
 * collapsing them would lose the only thing an operator needs to know: whether
 * anyone decided this.
 *
 *   Paused   — WE stopped it, automatically, after too many consecutive
 *              failures. Resuming is safe and routine: the cause was almost
 *              certainly on the receiver's side and may well be fixed.
 *   Disabled — SOMEBODY stopped it: an operator, or the receiver itself by
 *              answering 410 Gone. Re-enabling is a decision, not a retry, and
 *              must not happen because a queue drained.
 */
enum EndpointStatus: string
{
    case Active   = 'active';
    case Paused   = 'paused';
    case Disabled = 'disabled';

    public function isReceiving(): bool
    {
        return $this === self::Active;
    }

    /** Can `webhooks:retry` put this back by itself? */
    public function isAutomaticallyResumable(): bool
    {
        return $this === self::Paused;
    }
}
