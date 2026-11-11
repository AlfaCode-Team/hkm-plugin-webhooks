<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Config;

final readonly class WebhookConfig
{
    private function __construct(
        /** Seconds one POST may take. */
        public int $timeout,
        /** Deliveries attempted per run. */
        public int $batch,
        /** Attempts on one delivery before it is parked. */
        public int $maxAttempts,
        /** First retry delay, in seconds; doubles each attempt. */
        public int $backoffBase,
        /** Ceiling on the retry delay. */
        public int $backoffMax,
        /** Consecutive failures before an endpoint is paused. 0 never pauses. */
        public int $pauseAfterFailures,
        /** Seconds before a claimed-but-unsettled delivery is released. */
        public int $claimTimeout,
        /** Days a settled delivery is kept. */
        public int $pruneAfterDays,
        /** Seconds a signature stays acceptable, for the documented default. */
        public int $signatureTolerance,
        /** Refuse a URL that is not https. */
        public bool $requireHttps,
        /** Allow endpoints on private/reserved addresses. */
        public bool $allowPrivate,
    ) {}

    public static function fromEnv(): self
    {
        return new self(
            // 15s, matching what Appwrite allows a webhook. Long enough for a
            // receiver that does a little work inline, short enough that a
            // batch of 50 against a black-holing endpoint cannot run past a
            // minute-by-minute schedule.
            timeout: max(1, (int) env('WEBHOOKS_TIMEOUT', 15)),
            batch:   self::clampBatch((int) env('WEBHOOKS_BATCH', 50)),
            maxAttempts: max(1, (int) env('WEBHOOKS_MAX_ATTEMPTS', 10)),
            // 60s doubling to a 1h ceiling: ten attempts then span about a day,
            // which is long enough to ride out a receiver's unplanned outage
            // without holding a row forever.
            backoffBase: max(1, (int) env('WEBHOOKS_BACKOFF_BASE', 60)),
            backoffMax:  max(1, (int) env('WEBHOOKS_BACKOFF_MAX', 3600)),
            pauseAfterFailures: max(0, (int) env('WEBHOOKS_PAUSE_AFTER_FAILURES', 10)),
            claimTimeout:   max(30, (int) env('WEBHOOKS_CLAIM_TIMEOUT', 300)),
            pruneAfterDays: max(1, (int) env('WEBHOOKS_PRUNE_AFTER_DAYS', 7)),
            signatureTolerance: max(0, (int) env('WEBHOOKS_SIGNATURE_TOLERANCE', 300)),
            // HTTPS required by default. The body is signed, not encrypted, so
            // over http:// every event's contents cross the network in the clear
            // to anyone on the path — and the signature proves authorship, not
            // confidentiality.
            requireHttps: self::bool(env('WEBHOOKS_REQUIRE_HTTPS', true)),
            // OFF by default, which INVERTS the http-client's own setting on
            // purpose. There, private addresses are allowed because a
            // first-party gateway legitimately calls an internal service. Here
            // the URL was typed by a user, so `http://169.254.169.254/` and
            // `http://127.0.0.1:6379/` are the attack rather than the use case.
            allowPrivate: self::bool(env('WEBHOOKS_ALLOW_PRIVATE', false)),
        );
    }

    public static function of(
        int $timeout = 15,
        int $batch = 50,
        int $maxAttempts = 10,
        int $backoffBase = 60,
        int $backoffMax = 3600,
        int $pauseAfterFailures = 10,
        int $claimTimeout = 300,
        int $pruneAfterDays = 7,
        int $signatureTolerance = 300,
        bool $requireHttps = true,
        bool $allowPrivate = false,
    ): self {
        return new self(
            max(1, $timeout),
            self::clampBatch($batch),
            max(1, $maxAttempts),
            max(1, $backoffBase),
            max(1, $backoffMax),
            max(0, $pauseAfterFailures),
            max(1, $claimTimeout),
            max(1, $pruneAfterDays),
            max(0, $signatureTolerance),
            $requireHttps,
            $allowPrivate,
        );
    }

    /**
     * How long to wait before attempt number $attempts + 1.
     *
     * Doubling from the base, capped. Computed here rather than in the service
     * so the ceiling cannot be forgotten at one of the call sites: without it,
     * attempt 10 of a 60-second base would be scheduled 8 hours out, and attempt
     * 20 next year.
     */
    public function backoffSeconds(int $attempts): int
    {
        $exponent = max(0, $attempts - 1);

        // Clamped before the shift. 2 ** 60 overflows to a float and then to a
        // negative int when cast, which would schedule the retry in the PAST
        // and spin the row through the queue as fast as the deliverer runs.
        if ($exponent > 30) {
            return $this->backoffMax;
        }

        return min($this->backoffMax, $this->backoffBase * (2 ** $exponent));
    }

    private static function clampBatch(int $batch): int
    {
        // The batch reaches SQL as an inlined integer, so the clamp is what
        // makes that safe. The ceiling is also real: one run holds its claims
        // until it finishes, and every delivery can take the full timeout.
        return max(1, min(500, $batch));
    }

    private static function bool(mixed $value): bool
    {
        if (\is_bool($value)) {
            return $value;
        }

        return \in_array(strtolower(trim((string) $value)), ['1', 'true', 'on', 'yes'], true);
    }
}
