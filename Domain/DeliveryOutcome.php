<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * What one delivery attempt established.
 *
 * Three outcomes, because there are exactly three things worth doing next:
 * stop happily, try again later, or stop for good.
 */
enum DeliveryOutcome: string
{
    case Delivered = 'delivered';
    case Retryable = 'retryable';
    case Permanent = 'permanent';

    /**
     * Classify a response status.
     *
     * 2xx — delivered. The ONLY success. Anything else means the receiver did
     * not acknowledge, whatever it meant by it.
     *
     * 410 Gone — permanent, and the one status with a standard meaning worth
     * honouring here: "this resource is intentionally gone". It is the only way
     * a receiver can decommission an endpoint without reaching into our
     * database, so it stops delivery for good rather than being retried for
     * days against a URL whose owner has already said it is finished.
     *
     * 3xx — RETRYABLE, not followed. Redirects are deliberately not followed
     * for a webhook: the SSRF check and the connection pin apply to the URL
     * that was checked, and following a 302 would let a receiver redirect us to
     * `169.254.169.254` and read the response back out of the delivery log. A
     * receiver that has genuinely moved should be re-registered at its new URL.
     *
     * 4xx — retryable. A 401 or 403 is usually a receiver mid-deploy with its
     * auth not yet wired, and the consecutive-failure pause is what stops an
     * endlessly misconfigured endpoint. Treating 4xx as permanent would
     * discard real events during a thirty-second deploy.
     *
     * 5xx and anything else — retryable.
     */
    public static function fromStatus(int $status): self
    {
        if ($status >= 200 && $status < 300) {
            return self::Delivered;
        }

        if ($status === 410) {
            return self::Permanent;
        }

        return self::Retryable;
    }

    public function isDelivered(): bool
    {
        return $this === self::Delivered;
    }

    /** Should this attempt be made again? */
    public function willRetry(): bool
    {
        return $this === self::Retryable;
    }
}
