<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * Which event names an endpoint has subscribed to.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE DIALECT, AND WHY IT IS THIS SMALL
 * ──────────────────────────────────────────────────────────────────────────
 * Event names are dot-separated (`user.registered`, `invoice.line.added`), so
 * the pattern is too, and matching is per SEGMENT rather than per character.
 *
 *   `user.registered`   exact
 *   `user.*`            exactly ONE more segment — `user.registered`, and NOT
 *                       `user.profile.updated`
 *   `user.**`           one or more remaining segments — both of the above
 *   `**`                everything
 *
 * A character-wise glob would make `user.*` match `user.profile.updated`, and
 * an endpoint that asked for "user events" would start receiving a deeper
 * resource's events the day somebody added one. Per-segment means adding
 * `user.profile.updated` to the application cannot silently widen an existing
 * subscription.
 *
 * `**` MATCHES ONE OR MORE, NEVER ZERO. `user.**` does not match the bare
 * `user`, because the subscription that wants `user` is `user`, and a `**` that
 * matched nothing would make `user.**` and `user` indistinguishable while
 * reading as if they differed.
 *
 * `**` IS ONLY LEGAL AS THE LAST SEGMENT. `a.**.b` has no useful reading —
 * whether it should match `a.x.b` or `a.x.y.b` or both is a guess — and a
 * pattern nobody can predict is a subscription nobody can audit. It is refused
 * at construction, which is also registration time, so the person typing it
 * finds out rather than wondering later why nothing arrives.
 */
final readonly class EventPattern
{
    public const ONE  = '*';
    public const MANY = '**';

    /** @param list<string> $segments */
    private function __construct(
        public string $pattern,
        private array $segments,
    ) {}

    public static function of(string $pattern): self
    {
        $pattern = trim($pattern);

        if ($pattern === '') {
            throw new \InvalidArgumentException('An event pattern cannot be empty.');
        }

        $segments = explode('.', $pattern);

        foreach ($segments as $index => $segment) {
            if ($segment === '') {
                throw new \InvalidArgumentException(sprintf(
                    'Event pattern [%s] has an empty segment. A leading, trailing or doubled '
                    . '"." matches nothing at all.',
                    $pattern,
                ));
            }

            if ($segment === self::MANY && $index !== \count($segments) - 1) {
                throw new \InvalidArgumentException(sprintf(
                    'Event pattern [%s] uses "**" before the end. It is only meaningful as the '
                    . 'last segment: in the middle there is no single reading of how many '
                    . 'segments it should swallow, and a pattern nobody can predict is a '
                    . 'subscription nobody can audit.',
                    $pattern,
                ));
            }

            // A segment that MIXES a wildcard with literal text ("user.*ed") is
            // refused rather than quietly treated as a literal. Matching is
            // per-segment, so there is nothing sensible for the `*` to do there,
            // and silently reading it as the literal string `*ed` would make the
            // subscription match nothing while looking like it should.
            if ($segment !== self::ONE && $segment !== self::MANY && str_contains($segment, '*')) {
                throw new \InvalidArgumentException(sprintf(
                    'Event pattern [%s] has a segment [%s] that mixes "*" with literal text. '
                    . 'Matching is per segment: a wildcard segment is exactly "*" or "**".',
                    $pattern,
                    $segment,
                ));
            }
        }

        return new self($pattern, $segments);
    }

    /** Is this a valid pattern? For validating input without catching. */
    public static function isValid(string $pattern): bool
    {
        try {
            self::of($pattern);

            return true;
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    public function matches(string $eventName): bool
    {
        $name = explode('.', $eventName);

        foreach ($this->segments as $index => $segment) {
            // `**` is last by construction, so reaching it means every segment
            // before it matched. It needs at least one name segment left.
            if ($segment === self::MANY) {
                return \count($name) > $index;
            }

            if (!isset($name[$index])) {
                return false;
            }

            if ($segment === self::ONE) {
                continue;
            }

            // Literal segments are compared exactly and case-sensitively. Event
            // names are identifiers chosen by the code that emits them, not
            // user input, so folding case would only let two different events
            // collide.
            if ($segment !== $name[$index]) {
                return false;
            }
        }

        // Every pattern segment matched; the name must not have more left over,
        // or `user` would match `user.registered`.
        return \count($name) === \count($this->segments);
    }

    /** Does this pattern subscribe to everything? */
    public function isCatchAll(): bool
    {
        return $this->segments === [self::MANY];
    }

    public function __toString(): string
    {
        return $this->pattern;
    }
}
