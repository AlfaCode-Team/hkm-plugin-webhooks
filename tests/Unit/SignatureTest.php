<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Webhooks\Domain\Signature;

/**
 * Signing, and verifying.
 *
 * `verify()` is published for receivers to use, so these tests are the
 * compatibility contract between the two halves: anything asserted here is
 * something a receiver is entitled to rely on.
 */
#[CoversClass(Signature::class)]
final class SignatureTest extends TestCase
{
    private const SECRET = 'a-secret-long-enough-to-be-worth-checking';
    private const BODY   = '{"id":"evt-1","event":"user.registered"}';

    private function at(string $moment): \DateTimeImmutable
    {
        return new \DateTimeImmutable($moment);
    }

    public function test_a_signature_round_trips(): void
    {
        $now = $this->at('2026-11-11 12:00:00');
        $sig = Signature::sign(self::BODY, self::SECRET, $now);

        self::assertTrue(Signature::verify($sig->header(), self::BODY, self::SECRET, 300, $now));
    }

    public function test_the_header_has_the_documented_shape(): void
    {
        // A receiver parses this, so the format is part of the contract.
        $sig = Signature::sign(self::BODY, self::SECRET, $this->at('2026-11-11 12:00:00'));

        self::assertMatchesRegularExpression('/^t=\d+,v1=[0-9a-f]{64}$/', $sig->header());
    }

    public function test_a_changed_body_does_not_verify(): void
    {
        $now = $this->at('2026-11-11 12:00:00');
        $sig = Signature::sign(self::BODY, self::SECRET, $now);

        self::assertFalse(Signature::verify($sig->header(), self::BODY . ' ', self::SECRET, 300, $now));
        self::assertFalse(Signature::verify($sig->header(), '{}', self::SECRET, 300, $now));
    }

    public function test_a_different_secret_does_not_verify(): void
    {
        $now = $this->at('2026-11-11 12:00:00');
        $sig = Signature::sign(self::BODY, self::SECRET, $now);

        self::assertFalse(Signature::verify($sig->header(), self::BODY, 'another-secret-entirely-xxxxxxx', 300, $now));
    }

    // ── Replay ────────────────────────────────────────────────────────────────

    public function test_an_old_signature_is_refused(): void
    {
        // THE reason the timestamp is in the signed string. Appwrite's
        // equivalent signs url+payload and nothing else, so a captured request
        // stays valid for as long as the secret does — anyone who records one
        // POST can resend it a year later and the receiver cannot tell.
        $signedAt = $this->at('2026-11-11 12:00:00');
        $sig      = Signature::sign(self::BODY, self::SECRET, $signedAt);

        $muchLater = $this->at('2026-11-11 12:10:00');

        self::assertFalse(
            Signature::verify($sig->header(), self::BODY, self::SECRET, 300, $muchLater),
            'ten minutes later, with a five-minute tolerance',
        );
    }

    public function test_a_signature_inside_the_tolerance_is_accepted(): void
    {
        $signedAt = $this->at('2026-11-11 12:00:00');
        $sig      = Signature::sign(self::BODY, self::SECRET, $signedAt);

        self::assertTrue(Signature::verify(
            $sig->header(),
            self::BODY,
            self::SECRET,
            300,
            $this->at('2026-11-11 12:04:00'),
        ));
    }

    public function test_a_future_timestamp_is_also_refused(): void
    {
        // The tolerance is symmetric. A signature stamped far in the future
        // would otherwise stay valid for as long as the clock took to catch up
        // — which is the same replay window, opened from the other side.
        $sig = Signature::sign(self::BODY, self::SECRET, $this->at('2026-11-11 13:00:00'));

        self::assertFalse(Signature::verify(
            $sig->header(),
            self::BODY,
            self::SECRET,
            300,
            $this->at('2026-11-11 12:00:00'),
        ));
    }

    public function test_a_zero_tolerance_disables_the_age_check(): void
    {
        // Documented escape hatch for a receiver that cannot keep its clock
        // close enough. It also disables replay protection, which is why it is
        // not the default.
        $sig = Signature::sign(self::BODY, self::SECRET, $this->at('2020-01-01 00:00:00'));

        self::assertTrue(Signature::verify(
            $sig->header(),
            self::BODY,
            self::SECRET,
            0,
            $this->at('2026-11-11 12:00:00'),
        ));
    }

    public function test_the_timestamp_is_part_of_the_signed_string(): void
    {
        // Not merely transmitted alongside it. If it were only transmitted, an
        // attacker could rewrite `t=` on a captured delivery to refresh it and
        // the HMAC would still check out.
        $sig  = Signature::sign(self::BODY, self::SECRET, $this->at('2026-11-11 12:00:00'));
        $hash = substr($sig->header(), strpos($sig->header(), 'v1=') + 3);

        $forged = 't=' . $this->at('2026-11-11 12:00:00')->getTimestamp() . ',v1=' . $hash;
        self::assertTrue(Signature::verify($forged, self::BODY, self::SECRET, 300, $this->at('2026-11-11 12:00:00')));

        // Same hash, a timestamp moved forward to look fresh.
        $refreshed = 't=' . $this->at('2026-11-11 12:30:00')->getTimestamp() . ',v1=' . $hash;
        self::assertFalse(
            Signature::verify($refreshed, self::BODY, self::SECRET, 300, $this->at('2026-11-11 12:30:00')),
            'rewriting t= must break the hash, or the age check buys nothing',
        );
    }

    // ── Malformed input ───────────────────────────────────────────────────────

    /** @return list<array{string, string}> */
    public static function malformedHeaders(): array
    {
        return [
            ['',                           'empty'],
            ['garbage',                     'not key=value at all'],
            ['t=123',                       'no hash'],
            ['v1=abc',                      'no timestamp'],
            ['t=abc,v1=abc',                'a non-numeric timestamp'],
            ['t=,v1=abc',                   'an empty timestamp'],
            ['t=123,v2=abc',                'an unknown scheme version'],
            ['t=99999999999999999999999,v1=abc', 'a timestamp too long to be one'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformedHeaders')]
    public function test_a_malformed_header_does_not_verify(string $header, string $why): void
    {
        self::assertFalse(
            Signature::verify($header, self::BODY, self::SECRET, 300, $this->at('2026-11-11 12:00:00')),
            $why,
        );
    }

    public function test_an_empty_secret_cannot_sign_and_cannot_verify(): void
    {
        // An empty secret produces a perfectly valid-looking HMAC that anybody
        // can compute — worse than sending no signature, because the receiver
        // believes it checked something.
        $this->expectException(\InvalidArgumentException::class);

        Signature::sign(self::BODY, '', $this->at('2026-11-11 12:00:00'));
    }

    public function test_verify_refuses_an_empty_secret_rather_than_computing_one(): void
    {
        $header = 't=' . $this->at('2026-11-11 12:00:00')->getTimestamp()
            . ',v1=' . hash_hmac('sha256', '1763020800.' . self::BODY, '');

        self::assertFalse(
            Signature::verify($header, self::BODY, '', 300, $this->at('2026-11-11 12:00:00')),
            'a receiver with no secret configured must fail closed',
        );
    }

    public function test_the_algorithm_is_sha256(): void
    {
        // Pinned, because it is the one thing a receiver hard-codes. Appwrite
        // signs with HMAC-SHA1; every comparable product uses SHA-256, and a
        // receiver's security reviewer should not have to litigate it.
        self::assertSame('sha256', Signature::ALGORITHM);

        $now      = $this->at('2026-11-11 12:00:00');
        $expected = hash_hmac('sha256', $now->getTimestamp() . '.' . self::BODY, self::SECRET);

        self::assertStringContainsString($expected, Signature::sign(self::BODY, self::SECRET, $now)->header());
    }

    public function test_the_comparison_is_constant_time(): void
    {
        // A GUARDRAIL, not a behaviour test, and it is here because a
        // behaviour test cannot exist: `===` and `hash_equals()` return the
        // same boolean for every input, so no assertion on the result can tell
        // them apart. A revert check confirmed that — swapping in `===` passed
        // the entire suite.
        //
        // The difference is timing: `===` on a hex string returns as soon as
        // two bytes differ and leaks how long a correct prefix was, and a
        // webhook endpoint is by design something an attacker can make us call
        // repeatedly. So the one thing that can be checked is that the source
        // still uses the constant-time comparison.
        $source = file_get_contents(
            \dirname(__DIR__, 2) . '/Domain/Signature.php',
        );

        self::assertIsString($source);
        self::assertStringContainsString(
            'hash_equals($expected, $hash)',
            $source,
            'Signature::verify() must compare with hash_equals(), never ===',
        );
    }

    public function test_the_signed_string_is_the_timestamp_a_dot_and_the_raw_body(): void
    {
        // Spelled out so a receiver in another language can reimplement it from
        // this test alone.
        $now  = $this->at('2026-11-11 12:00:00');
        $body = '{"a":1}';

        $sig = Signature::sign($body, self::SECRET, $now);

        self::assertSame(
            'v1=' . hash_hmac('sha256', "{$now->getTimestamp()}.{$body}", self::SECRET),
            substr($sig->header(), strpos($sig->header(), 'v1=')),
        );
    }
}
