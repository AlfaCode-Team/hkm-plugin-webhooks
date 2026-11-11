<?php

declare(strict_types=1);

namespace Tests\Plugins\Webhooks\Support;

use Plugins\Webhooks\Domain\Contracts\WebhookTransport;
use Plugins\Webhooks\Domain\DeliveryResult;

/**
 * Records what was sent and returns whatever the test queued.
 *
 * The real transport is a socket, so the retry and pause policy could not be
 * tested at all without this. What it must NOT be allowed to hide is the
 * headers: the signature, the stable delivery id and the attempt counter are
 * part of the contract with a receiver, so every send is captured whole and
 * asserted on.
 */
final class FakeTransport implements WebhookTransport
{
    /** @var list<array{url: string, body: string, headers: array<string, string>, timeout: int}> */
    public array $sent = [];

    /** @var list<DeliveryResult> */
    private array $queued = [];

    private DeliveryResult $default;

    public function __construct()
    {
        $this->default = DeliveryResult::fromResponse(200, 'ok', 1.0);
    }

    public function willReturn(DeliveryResult ...$results): self
    {
        $this->queued = array_values($results);

        return $this;
    }

    public function alwaysReturn(DeliveryResult $result): self
    {
        $this->default = $result;
        $this->queued  = [];

        return $this;
    }

    public function send(string $url, string $body, array $headers, int $timeoutSeconds): DeliveryResult
    {
        $this->sent[] = [
            'url'     => $url,
            'body'    => $body,
            'headers' => $headers,
            'timeout' => $timeoutSeconds,
        ];

        return array_shift($this->queued) ?? $this->default;
    }

    public function describe(): string
    {
        return 'fake';
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    public function count(): int
    {
        return \count($this->sent);
    }

    /** @return array{url: string, body: string, headers: array<string, string>, timeout: int} */
    public function last(): array
    {
        return $this->sent[\count($this->sent) - 1];
    }

    public function header(string $name, int $index = 0): ?string
    {
        return $this->sent[$index]['headers'][$name] ?? null;
    }

    /** @return list<string> every body sent, in order */
    public function bodies(): array
    {
        return array_map(static fn (array $s): string => $s['body'], $this->sent);
    }
}
