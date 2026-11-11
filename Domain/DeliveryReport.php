<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * What one `webhooks:deliver` run did.
 *
 * `paused` and `disabled` are counted separately from `failed` because they are
 * the only two that change what a receiver gets from now on, rather than just
 * from this run — so they are the two worth telling somebody about.
 */
final readonly class DeliveryReport
{
    public function __construct(
        public int $delivered = 0,
        public int $failed = 0,
        public int $permanent = 0,
        public int $lost = 0,
        public int $reclaimed = 0,
        public int $exhausted = 0,
        public int $paused = 0,
        public int $disabled = 0,
    ) {}

    public function attempted(): int
    {
        return $this->delivered + $this->failed + $this->permanent;
    }

    public function isIdle(): bool
    {
        return $this->attempted() === 0 && $this->lost === 0 && $this->reclaimed === 0;
    }

    /** Did anything happen that a person should look at? */
    public function needsAttention(): bool
    {
        return $this->paused > 0 || $this->disabled > 0 || $this->exhausted > 0;
    }

    /** @return array<string, int> */
    public function toArray(): array
    {
        return [
            'delivered' => $this->delivered,
            'failed'    => $this->failed,
            'permanent' => $this->permanent,
            'lost'      => $this->lost,
            'reclaimed' => $this->reclaimed,
            'exhausted' => $this->exhausted,
            'paused'    => $this->paused,
            'disabled'  => $this->disabled,
        ];
    }
}
