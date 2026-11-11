<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Webhooks\Domain\DeliveryOutcome;
use Plugins\Webhooks\Domain\DeliveryResult;

/**
 * Classifying one attempt, and handling the receiver's reply.
 *
 * The reply is the only ATTACKER-CONTROLLED text in this plugin: a customer's
 * server can return anything at all, and what it returns is stored and then
 * printed into an operator's terminal by `webhooks:status`. These tests exist
 * because a revert check showed the sanitising was not covered at all.
 */
#[CoversClass(DeliveryResult::class)]
#[CoversClass(DeliveryOutcome::class)]
final class DeliveryResultTest extends TestCase
{
    /** @return list<array{int, DeliveryOutcome, string}> */
    public static function statusClassifications(): array
    {
        return [
            [200, DeliveryOutcome::Delivered, 'the ordinary success'],
            [201, DeliveryOutcome::Delivered, 'created'],
            [202, DeliveryOutcome::Delivered, 'accepted — a queue on their side is still an ack'],
            [204, DeliveryOutcome::Delivered, 'no content'],
            [299, DeliveryOutcome::Delivered, 'the top of the 2xx range'],

            // 410 Gone is the one status with a standard meaning worth
            // honouring: it is how a receiver decommissions an endpoint without
            // reaching into our database.
            [410, DeliveryOutcome::Permanent, 'gone, for good'],

            // 3xx is retryable and NOT followed. Following a redirect would let
            // a receiver bounce us to an internal address after the SSRF guard
            // had approved the public one it was given.
            [301, DeliveryOutcome::Retryable, 'a redirect is not an acknowledgement'],
            [302, DeliveryOutcome::Retryable, 'nor is a temporary one'],

            // 4xx is retryable because a 401 or 403 is usually a receiver
            // mid-deploy with its auth not yet wired; the consecutive-failure
            // pause is what stops an endlessly misconfigured endpoint. Treating
            // 4xx as permanent would discard real events over a 30-second deploy.
            [400, DeliveryOutcome::Retryable, 'bad request — possibly our payload, possibly their parser'],
            [401, DeliveryOutcome::Retryable, 'unauthorised — usually a deploy in progress'],
            [403, DeliveryOutcome::Retryable, 'forbidden'],
            [404, DeliveryOutcome::Retryable, 'not found — a route that may come back'],
            [429, DeliveryOutcome::Retryable, 'rate limited, which is exactly what backoff is for'],

            [500, DeliveryOutcome::Retryable, 'their bug'],
            [502, DeliveryOutcome::Retryable, 'their proxy'],
            [503, DeliveryOutcome::Retryable, 'their maintenance window'],
            [0,   DeliveryOutcome::Retryable, 'a nonsense status is not a success'],
        ];
    }

    #[DataProvider('statusClassifications')]
    public function test_a_status_is_classified(int $status, DeliveryOutcome $expected, string $why): void
    {
        self::assertSame($expected, DeliveryResult::fromResponse($status, '', 1.0)->outcome, $why);
    }

    public function test_only_a_2xx_is_a_delivery(): void
    {
        self::assertTrue(DeliveryResult::fromResponse(200, '', 1.0)->isDelivered());
        self::assertFalse(DeliveryResult::fromResponse(302, '', 1.0)->isDelivered());
        self::assertFalse(DeliveryResult::fromResponse(410, '', 1.0)->isDelivered());
    }

    public function test_a_success_records_no_failure_reason(): void
    {
        self::assertSame('', DeliveryResult::fromResponse(200, 'ok', 1.0)->failureReason);
        self::assertSame('HTTP 503', DeliveryResult::fromResponse(503, 'nope', 1.0)->failureReason);
    }

    public function test_a_transport_failure_has_no_status_rather_than_zero(): void
    {
        // "The request did not happen" is genuinely different from "the receiver
        // answered 0", and 0 reads as a status in every table that shows it.
        $result = DeliveryResult::transportFailure('connection timed out after 15s', 15000.0);

        self::assertNull($result->status);
        self::assertSame(DeliveryOutcome::Retryable, $result->outcome);
        self::assertStringContainsString('timed out', $result->failureReason);
        self::assertSame(15000.0, $result->durationMs);
    }

    public function test_a_refused_url_is_permanent_not_retryable(): void
    {
        // It will be refused identically every time, so retrying buys nothing
        // and only delays the endpoint being disabled — which is the thing that
        // actually needs to happen. It is also our configuration's fault rather
        // than the receiver's.
        $result = DeliveryResult::refused('the endpoint has no signing secret');

        self::assertSame(DeliveryOutcome::Permanent, $result->outcome);
        self::assertFalse($result->outcome->willRetry());
        self::assertNull($result->status);
        self::assertStringStartsWith('refused: ', $result->failureReason);
    }

    // ── The receiver's body is untrusted ──────────────────────────────────────

    public function test_the_excerpt_is_truncated(): void
    {
        // A receiver can reply with a document. Only enough to see an error
        // message is kept.
        $result = DeliveryResult::fromResponse(500, str_repeat('x', 10_000), 1.0);

        self::assertSame(DeliveryResult::EXCERPT_MAX_CHARS, mb_strlen($result->responseExcerpt));
    }

    /** @return list<array{string, string, string}> */
    public static function controlCharacters(): array
    {
        return [
            ["before\r\nafter",        "\r",     'a CR rewrites the line it is on in a terminal'],
            ["before\x1b[2Jafter",     "\x1b",   'an ESC sequence can repaint the whole screen'],
            ["before\x00after",        "\x00",   'a NUL can truncate C-side string handling'],
            ["before\x08after",        "\x08",   'a backspace erases what was printed before it'],
            ["before\x07after",        "\x07",   'a BEL'],
            ["before\x7fafter",        "\x7f",   'DEL'],
        ];
    }

    #[DataProvider('controlCharacters')]
    public function test_control_characters_are_stripped_from_the_excerpt(
        string $body,
        string $forbidden,
        string $why,
    ): void {
        // This text is printed into an operator's terminal by `webhooks:status`,
        // so a receiver could otherwise forge the output of the very command
        // being used to investigate it.
        $excerpt = DeliveryResult::fromResponse(500, $body, 1.0)->responseExcerpt;

        self::assertStringNotContainsString($forbidden, $excerpt, $why);
        self::assertStringContainsString('before', $excerpt, 'the readable text survives');
        self::assertStringContainsString('after', $excerpt);
    }

    public function test_a_newline_and_a_tab_are_kept(): void
    {
        // They are not an attack and they are how a multi-line error message is
        // readable. Stripping everything would make the excerpt useless.
        $excerpt = DeliveryResult::fromResponse(500, "line one\nline\ttwo", 1.0)->responseExcerpt;

        self::assertStringContainsString("\n", $excerpt);
        self::assertStringContainsString("\t", $excerpt);
    }

    public function test_an_invalid_utf8_body_does_not_erase_the_excerpt(): void
    {
        // A receiver can send whatever bytes it likes, and `preg_replace` with
        // the /u flag returns NULL on invalid UTF-8 — which without the
        // byte-wise fallback would silently discard the whole excerpt and leave
        // an operator with nothing to look at.
        $result = DeliveryResult::fromResponse(500, "valid \xC3\x28 invalid \x00 bytes", 1.0);

        self::assertNotSame('', $result->responseExcerpt);
        self::assertStringNotContainsString("\x00", $result->responseExcerpt);
    }

    public function test_a_transport_reason_is_also_sanitised_and_bounded(): void
    {
        // The transport reason can embed a receiver-supplied hostname or TLS
        // error, so it gets the same treatment on a shorter leash.
        $result = DeliveryResult::transportFailure("bad\r\nhost " . str_repeat('y', 2000), 1.0);

        self::assertStringNotContainsString("\r", $result->failureReason);
        self::assertLessThanOrEqual(500, mb_strlen($result->failureReason));
    }

    public function test_the_duration_is_carried_through(): void
    {
        self::assertSame(42.5, DeliveryResult::fromResponse(200, '', 42.5)->durationMs);
    }
}
