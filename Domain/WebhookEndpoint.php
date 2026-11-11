<?php

declare(strict_types=1);

namespace Plugins\Webhooks\Domain;

/**
 * A registered receiver: where to post, what to post, and how to sign it.
 *
 * The secret is held in plaintext ON THIS OBJECT because the HMAC cannot be
 * computed without it. It is the Infrastructure layer's job to keep it
 * encrypted at rest and to keep it out of anything an operator can read — see
 * {@see describe()}, which exists so there is an obvious correct way to print
 * an endpoint.
 */
final readonly class WebhookEndpoint
{
    /** @param list<EventPattern> $patterns */
    private function __construct(
        public string $id,
        public string $url,
        public array $patterns,
        public string $secret,
        public EndpointStatus $status,
        public int $consecutiveFailures,
        public string $description,
    ) {}

    /**
     * @param list<string>|list<EventPattern> $patterns
     */
    public static function of(
        string $id,
        string $url,
        array $patterns,
        string $secret,
        EndpointStatus $status = EndpointStatus::Active,
        int $consecutiveFailures = 0,
        string $description = '',
    ): self {
        if ($patterns === []) {
            // An endpoint with no patterns matches nothing, so it would sit in
            // the table looking registered and silently receive nothing at all.
            throw new \InvalidArgumentException(
                'A webhook endpoint must subscribe to at least one event pattern.',
            );
        }

        return new self(
            id:                  $id,
            url:                 $url,
            patterns:            array_values(array_map(
                static fn (EventPattern|string $p): EventPattern
                    => $p instanceof EventPattern ? $p : EventPattern::of($p),
                $patterns,
            )),
            secret:              $secret,
            status:              $status,
            consecutiveFailures: max(0, $consecutiveFailures),
            description:         $description,
        );
    }

    public function subscribesTo(string $eventName): bool
    {
        foreach ($this->patterns as $pattern) {
            if ($pattern->matches($eventName)) {
                return true;
            }
        }

        return false;
    }

    public function isReceiving(): bool
    {
        return $this->status->isReceiving();
    }

    /** @return list<string> */
    public function patternStrings(): array
    {
        return array_map(static fn (EventPattern $p): string => $p->pattern, $this->patterns);
    }

    /**
     * Safe to log, print or return from an API.
     *
     * NEVER includes the secret. The URL is included because an operator cannot
     * identify an endpoint without it — but its QUERY STRING is dropped, since
     * a receiver that authenticates by `?token=…` has put a credential there
     * and would otherwise have it copied into every log line and status table.
     *
     * @return array<string, mixed>
     */
    public function describe(): array
    {
        return [
            'id'                   => $this->id,
            'url'                  => self::withoutQuery($this->url),
            'events'               => $this->patternStrings(),
            'status'               => $this->status->value,
            'consecutiveFailures'  => $this->consecutiveFailures,
            'description'          => $this->description,
        ];
    }

    private static function withoutQuery(string $url): string
    {
        $cut = strpos($url, '?');

        return $cut === false ? $url : substr($url, 0, $cut) . '?…';
    }
}
