<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Infrastructure\Exceptions;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\ServiceException;

/**
 * Lives in Infrastructure/ because it extends a kernel exception and the Domain
 * layer imports nothing outside Domain/ — the Domain classes here throw
 * `\InvalidArgumentException`.
 *
 * `ServiceException` (HTTP 422) rather than `RepositoryException` (500): every
 * one of these is a rejected REGISTRATION, and a registration is something a
 * person or an API client submitted. A bad URL in a form is a 422 and the
 * message is meant to be shown; a 500 would say the fault was ours.
 */
final class WebhookException extends ServiceException
{
    public static function invalidUrl(string $url, string $why): self
    {
        return new self(
            "Cannot register a webhook for [{$url}]: {$why}",
            layer: 'service.webhooks.register',
            context: ['url' => $url],
        );
    }

    /**
     * The endpoint could not be persisted.
     *
     * Separate from {@see invalidUrl()} because the cause is ours, not the
     * submitter's — reporting a database failure as a bad URL would send them
     * to re-type a URL that was fine.
     */
    public static function saveFailed(string $id, \Throwable $previous): self
    {
        return new self(
            'The webhook endpoint could not be saved.',
            layer: 'repository.webhooks.save',
            context: ['endpoint' => $id],
            previous: $previous,
        );
    }

    public static function invalidPattern(string $pattern, string $why): self
    {
        return new self(
            "Event pattern [{$pattern}] cannot be used: {$why}",
            layer: 'service.webhooks.register',
            context: ['pattern' => $pattern],
        );
    }

    public static function unknownEndpoint(string $id): self
    {
        return new self(
            "No webhook endpoint [{$id}].",
            layer: 'service.webhooks',
            context: ['endpoint' => $id],
        );
    }

    /**
     * A secret too short to be worth checking.
     *
     * The length is the whole strength of an HMAC here: the receiver's
     * signature check is only as good as the secret's entropy, and a six-
     * character secret is brute-forceable offline from a single captured
     * delivery.
     */
    public static function weakSecret(int $given, int $minimum): self
    {
        return new self(
            "A webhook signing secret must be at least {$minimum} characters; got {$given}. "
            . 'Omit it entirely to have one generated.',
            layer: 'service.webhooks.register',
        );
    }
}
