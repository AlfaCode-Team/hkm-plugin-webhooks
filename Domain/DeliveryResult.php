<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * What came back from one POST.
 *
 * `responseExcerpt` is the receiver's body, truncated. It is **attacker-
 * controlled text** — a customer's server can return anything at all — so it is
 * stored for debugging and must never be rendered as markup, interpolated into
 * a shell command, or echoed into one of our own responses. It is truncated and
 * stripped of control characters at construction so there is no path where the
 * raw value reaches storage.
 */
final readonly class DeliveryResult
{
    /** Enough to see a receiver's error message; far short of a response body. */
    public const EXCERPT_MAX_CHARS = 2000;

    private function __construct(
        public DeliveryOutcome $outcome,
        public ?int $status,
        public string $responseExcerpt,
        public float $durationMs,
        public string $failureReason,
    ) {}

    public static function fromResponse(int $status, string $body, float $durationMs): self
    {
        return new self(
            outcome:         DeliveryOutcome::fromStatus($status),
            status:          $status,
            responseExcerpt: self::sanitise($body),
            durationMs:      $durationMs,
            failureReason:   $status >= 200 && $status < 300 ? '' : 'HTTP ' . $status,
        );
    }

    /**
     * The request never completed: a timeout, a DNS failure, a refused
     * connection, a TLS error.
     *
     * There is no status, and `status` stays NULL rather than becoming 0 —
     * because 0 reads as a status in every table and dashboard that displays
     * it, and "the request did not happen" is genuinely different from "the
     * receiver answered 0".
     */
    public static function transportFailure(string $reason, float $durationMs): self
    {
        return new self(
            outcome:         DeliveryOutcome::Retryable,
            status:          null,
            responseExcerpt: '',
            durationMs:      $durationMs,
            failureReason:   self::sanitise($reason, 500),
        );
    }

    /**
     * The URL was refused before any request was made — the SSRF guard, or a
     * scheme that is not allowed.
     *
     * PERMANENT, not retryable, and deliberately so: the URL will be refused
     * identically every time, so retrying buys nothing and only delays the
     * endpoint being disabled, which is the thing that actually needs to
     * happen. It is also the one failure that is OUR configuration's fault
     * rather than the receiver's.
     */
    public static function refused(string $reason): self
    {
        return new self(
            outcome:         DeliveryOutcome::Permanent,
            status:          null,
            responseExcerpt: '',
            durationMs:      0.0,
            failureReason:   'refused: ' . self::sanitise($reason, 500),
        );
    }

    public function isDelivered(): bool
    {
        return $this->outcome->isDelivered();
    }

    /**
     * Truncate, and remove control characters.
     *
     * The control characters matter more than the length. This text is written
     * to a database column and then printed by `webhooks:status` into somebody's
     * terminal, where a CR rewrites the line it is on and an ESC sequence can
     * repaint the screen — so a receiver could forge the output of the very
     * command an operator is using to investigate it.
     */
    private static function sanitise(string $text, int $max = self::EXCERPT_MAX_CHARS): string
    {
        $clean = preg_replace(self::CONTROL_CHARACTERS . 'u', '', $text);

        // preg_replace returns null on invalid UTF-8, and a receiver can send
        // whatever bytes it likes. Falling back to a byte-wise strip keeps a
        // malformed body from erasing the excerpt entirely.
        if ($clean === null) {
            $clean = preg_replace(self::CONTROL_CHARACTERS, '', $text) ?? '';
        }

        return mb_substr($clean, 0, $max);
    }

    /**
     * Everything except TAB (0x09) and LF (0x0A).
     *
     * `\r` IS IN HERE, and getting that wrong is easy: the usual "keep tab and
     * newline" class is written `\x00-\x08\x0B\x0C\x0E-\x1F`, which skips 0x0D
     * entirely. That class comes from XML and JSON text handling, where CRLF is
     * ordinary and harmless — and it is wrong here, because the threat is a
     * TERMINAL. A lone CR returns the cursor to the start of the line without
     * advancing it, so a receiver replying
     * `"ok\r  delivered 500/500, 0 failed"` can overwrite the line
     * `webhooks:status` just printed and forge the output of the command being
     * used to investigate it.
     *
     * This was let through until a test of this class caught it, while the
     * comment above claimed CR was handled.
     */
    private const CONTROL_CHARACTERS = '/[\x00-\x08\x0B-\x1F\x7F]/';
}
