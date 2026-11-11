<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * The signature a receiver checks to know the request came from us.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHAT IS SIGNED, AND WHY THE TIMESTAMP IS IN IT
 * ──────────────────────────────────────────────────────────────────────────
 * The signed string is `"{timestamp}.{body}"` and the header carries both:
 *
 *     X-Webhook-Signature: t=1763000000,v1=<hex sha256>
 *
 * Appwrite's equivalent signs `url + payload` with HMAC-SHA1 and nothing else.
 * That authenticates the body, and it leaves a captured request replayable
 * FOREVER — the signature stays valid for as long as the secret does, so anyone
 * who records one POST can resend it a year later and the receiver cannot tell.
 * Binding a timestamp into the signed string, and having the receiver refuse an
 * old one, is what closes that. The window is the receiver's policy, which is
 * why {@see verify()} takes a tolerance rather than assuming one.
 *
 * SHA-256, NOT SHA-1. HMAC-SHA1 is not practically broken, but SHA-1's
 * collision resistance is, every comparable product (Stripe, GitHub, Shopify)
 * signs with SHA-256, and a receiver's security reviewer should not have to
 * litigate the difference.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE BODY IS SIGNED AS BYTES, AND THAT IS THE WHOLE CONTRACT
 * ──────────────────────────────────────────────────────────────────────────
 * The single most common way webhook verification fails in the wild is a
 * receiver that parses the JSON, re-encodes it, and verifies against the
 * result — which differs from what was sent in key order, unicode escaping and
 * float formatting, so the signature never matches and the integration is
 * declared broken. The sender has the same hazard in reverse, so the body
 * string is built ONCE, signed, and sent verbatim; nothing re-serialises it.
 *
 * {@see verify()} is published for receivers and used by the tests, so the two
 * sides cannot drift.
 */
final readonly class Signature
{
    public const ALGORITHM = 'sha256';
    public const HEADER    = 'X-Webhook-Signature';

    /** The scheme version in the header, so the format can change later. */
    public const VERSION = 'v1';

    private function __construct(
        public int $timestamp,
        public string $hash,
    ) {}

    /**
     * Sign a body for a given moment.
     *
     * @param string $body      the EXACT bytes that will be sent
     * @param string $secret    this endpoint's signing secret
     */
    public static function sign(string $body, string $secret, \DateTimeImmutable $at): self
    {
        if ($secret === '') {
            // An empty secret produces a perfectly valid-looking HMAC that
            // anybody can compute, which is worse than no signature at all
            // because the receiver believes it checked something.
            throw new \InvalidArgumentException('Cannot sign a webhook with an empty secret.');
        }

        $timestamp = $at->getTimestamp();

        return new self(
            $timestamp,
            hash_hmac(self::ALGORITHM, self::payload($timestamp, $body), $secret),
        );
    }

    /** The header value: `t=<unix>,v1=<hex>`. */
    public function header(): string
    {
        return sprintf('t=%d,%s=%s', $this->timestamp, self::VERSION, $this->hash);
    }

    /**
     * Verify a received signature header against the raw body.
     *
     * @param string $header    the `X-Webhook-Signature` value, verbatim
     * @param string $body      the RAW request body — not a re-encoded version of it
     * @param int    $tolerance seconds either side of now that are accepted; 0 disables
     *                          the age check entirely, which also disables replay
     *                          protection
     */
    public static function verify(
        string $header,
        string $body,
        string $secret,
        int $tolerance = 300,
        ?\DateTimeImmutable $now = null,
    ): bool {
        if ($secret === '') {
            return false;
        }

        $parsed = self::parse($header);

        if ($parsed === null) {
            return false;
        }

        [$timestamp, $hash] = $parsed;

        if ($tolerance > 0) {
            $age = abs(($now ?? new \DateTimeImmutable())->getTimestamp() - $timestamp);

            // Checked BEFORE the HMAC. An expired signature is refused on its
            // age whether or not the hash is right, and refusing early means a
            // flood of stale replays costs a subtraction rather than a hash.
            if ($age > $tolerance) {
                return false;
            }
        }

        $expected = hash_hmac(self::ALGORITHM, self::payload($timestamp, $body), $secret);

        // hash_equals, because `===` on a hex string returns as soon as two
        // bytes differ and leaks how long a correct prefix was. A webhook
        // endpoint is, by design, something an attacker can make us call
        // repeatedly.
        return hash_equals($expected, $hash);
    }

    /**
     * @return array{int, string}|null the timestamp and hash, or null when the
     *         header is not a v1 signature at all
     */
    private static function parse(string $header): ?array
    {
        $timestamp = null;
        $hash      = null;

        foreach (explode(',', $header) as $part) {
            $pair = explode('=', trim($part), 2);

            if (\count($pair) !== 2) {
                continue;
            }

            [$key, $value] = $pair;

            if ($key === 't' && preg_match('/^\d{1,20}$/', $value) === 1) {
                $timestamp = (int) $value;
            }

            if ($key === self::VERSION) {
                $hash = $value;
            }
        }

        if ($timestamp === null || $hash === null) {
            return null;
        }

        return [$timestamp, $hash];
    }

    /**
     * The exact string that is signed.
     *
     * `.` is a separator the hex timestamp cannot contain, so there is no way
     * to shift bytes between the two halves — the concatenation is unambiguous
     * rather than merely conventional.
     */
    private static function payload(int $timestamp, string $body): string
    {
        return $timestamp . '.' . $body;
    }
}
