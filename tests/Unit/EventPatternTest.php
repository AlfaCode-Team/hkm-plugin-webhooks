<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Webhooks\Domain\EventPattern;

/**
 * The subscription matcher.
 *
 * This decides what a third party receives, so getting it wrong is either an
 * event somebody paid for and never got, or an event about a resource they
 * should not have been told about. The boundary cases are the whole point.
 */
#[CoversClass(EventPattern::class)]
final class EventPatternTest extends TestCase
{
    /** @return list<array{string, string, bool, string}> */
    public static function matchCases(): array
    {
        return [
            // Exact.
            ['user.registered', 'user.registered', true,  'exact'],
            ['user.registered', 'user.updated',    false, 'a different verb'],
            ['user',            'user',            true,  'a single segment'],

            // `*` is EXACTLY ONE segment. This is the case that matters most:
            // a character-wise glob would make the next line true, and an
            // endpoint that asked for "user events" would silently start
            // receiving a deeper resource's events the day one was added.
            ['user.*', 'user.registered',     true,  'one more segment'],
            ['user.*', 'user.profile.updated', false, '`*` must NOT cross a dot'],
            ['user.*', 'user',                false, '`*` needs a segment to match'],
            ['*.created', 'user.created',     true,  'a wildcard in front'],
            ['*.created', 'invoice.created',  true,  'any resource, that verb'],
            ['*.created', 'user.profile.created', false, 'still exactly one segment'],
            ['user.*.updated', 'user.profile.updated', true, 'a wildcard in the middle'],
            ['user.*.updated', 'user.updated', false, 'the middle segment is required'],

            // `**` is one or more trailing segments.
            ['user.**', 'user.registered',      true,  'one trailing segment'],
            ['user.**', 'user.profile.updated', true,  'two trailing segments'],
            ['user.**', 'user.a.b.c.d',         true,  'any depth'],
            ['user.**', 'user',                 false, '`**` matches one or more, never zero'],
            ['user.**', 'users.registered',     false, 'the literal prefix must still match'],

            // The catch-all.
            ['**', 'user.registered', true,  'everything'],
            ['**', 'anything',        true,  'including a single segment'],

            // No partial-segment matching at all.
            ['user', 'user.registered', false, 'a prefix is not a match'],
            ['user.registered', 'user', false, 'nor is a truncation'],
            ['User.Registered', 'user.registered', false, 'case-sensitive: names are identifiers'],
        ];
    }

    #[DataProvider('matchCases')]
    public function test_matching(string $pattern, string $event, bool $expected, string $why): void
    {
        self::assertSame($expected, EventPattern::of($pattern)->matches($event), $why);
    }

    /** @return list<array{string, string}> */
    public static function rejected(): array
    {
        return [
            ['',             'empty'],
            ['   ',          'whitespace only'],
            ['user.',        'a trailing dot matches nothing at all'],
            ['.user',        'a leading dot likewise'],
            ['user..name',   'a doubled dot leaves an empty segment'],
            ['a.**.b',       '`**` before the end has no single reading'],
            ['**.user',      'same, at the front'],
            ['user.*ed',     'a wildcard mixed with literal text'],
            ['user.re*',     'likewise'],
            ['**x',          'and here'],
        ];
    }

    #[DataProvider('rejected')]
    public function test_an_unusable_pattern_is_refused_at_construction(string $pattern, string $why): void
    {
        // Refused where it is TYPED — at registration — rather than silently
        // matching nothing and leaving somebody wondering later why no events
        // arrive.
        $this->expectException(\InvalidArgumentException::class);

        EventPattern::of($pattern);
    }

    #[DataProvider('rejected')]
    public function test_is_valid_agrees_with_the_constructor(string $pattern, string $why): void
    {
        self::assertFalse(EventPattern::isValid($pattern), $why);
    }

    public function test_is_valid_accepts_a_usable_pattern(): void
    {
        self::assertTrue(EventPattern::isValid('user.*'));
        self::assertTrue(EventPattern::isValid('**'));
    }

    public function test_the_refusal_explains_why(): void
    {
        // The message is shown to whoever typed the pattern, so it has to say
        // what to do instead.
        try {
            EventPattern::of('a.**.b');
            self::fail('expected a refusal');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('only meaningful as the last segment', $e->getMessage());
        }

        try {
            EventPattern::of('user.*ed');
            self::fail('expected a refusal');
        } catch (\InvalidArgumentException $e) {
            self::assertStringContainsString('per segment', $e->getMessage());
        }
    }

    public function test_the_catch_all_is_recognisable(): void
    {
        self::assertTrue(EventPattern::of('**')->isCatchAll());
        self::assertFalse(EventPattern::of('user.**')->isCatchAll());
        self::assertFalse(EventPattern::of('*')->isCatchAll(), 'a single segment is not everything');
    }

    public function test_a_single_star_matches_exactly_one_segment(): void
    {
        // `*` alone is a real and useful pattern — every top-level event — and
        // it is NOT the catch-all.
        $pattern = EventPattern::of('*');

        self::assertTrue($pattern->matches('ping'));
        self::assertFalse($pattern->matches('user.registered'));
    }

    public function test_the_pattern_round_trips_as_a_string(): void
    {
        self::assertSame('user.*', (string) EventPattern::of('  user.*  '));
    }
}
