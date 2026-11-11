<?php

declare(strict_types=1);

use AlfaCode\LetMigrate\Contract\MigrationInterface;
use AlfaCode\LetMigrate\Contract\SchemaBuilderInterface;

/**
 * Registered receivers, and the deliveries owed to them.
 *
 * Two tables rather than one because their lifetimes are nothing alike: an
 * endpoint is configuration that lives as long as the integration, and a
 * delivery is a work item that is created, attempted and pruned within days.
 */
return new class implements MigrationInterface {
    public function up(SchemaBuilderInterface $schema): void
    {
        $schema->create('webhook_endpoints', static function ($t) {
            // The UUID is the identity, not a surrogate key. It is what the
            // application stores against its own tenant records and what appears
            // in an API, so a second auto-increment id would be a column that
            // means nothing to anybody.
            $t->char('id', 36);

            // 2048 is the practical ceiling browsers and proxies enforce. A URL
            // longer than the column would be TRUNCATED on write by MySQL in
            // non-strict mode and then POSTed to a different address than the
            // one that was registered and validated.
            $t->string('url', 2048);

            // The subscription patterns, as a JSON list. Not a join table: they
            // are read as a set on every dispatch, never queried individually,
            // and a second table would turn the hot path into a join.
            $t->json('event_patterns');

            // The signing secret, as stored. ENCRYPTED when the application
            // binds an EncryptionPort — `secret_encrypted` records which, so a
            // deployment that adds the port later keeps reading its old rows
            // instead of signing with ciphertext and silently failing every
            // receiver's verification.
            $t->text('secret');
            $t->boolean('secret_encrypted')->default(false);

            $t->string('status', 16)->default('active')
                ->comment('active | paused | disabled');

            // Consecutive failures, reset by any success. The streak is what
            // pauses an endpoint, so it must not be a lifetime total — a
            // receiver with one bad day two years ago is not paused today.
            $t->unsignedInteger('consecutive_failures')->default(0);

            $t->string('description', 255)->default('');

            $t->timestamp('created_at')->default('CURRENT_TIMESTAMP');
            $t->timestamp('updated_at')->nullable();

            $t->primary(['id'], 'pk_webhook_endpoint');

            // The dispatch path asks for exactly one thing — every endpoint that
            // is receiving — and it asks on every event in the application.
            $t->index(['status'], 'idx_webhook_endpoint_status');

            $t->engine('InnoDB');
            $t->charset('utf8mb4');
        });

        $schema->create('webhook_deliveries', static function ($t) {
            $t->id();

            // The DELIVERY id, stable across retries, sent as X-Webhook-Delivery.
            // It is what a receiver dedupes on, which is why it is not
            // regenerated per attempt: a receiver that processed attempt 1 and
            // timed out answering must be able to recognise attempt 2.
            $t->char('delivery_id', 36);

            $t->char('endpoint_id', 36);

            $t->string('event_name', 150);

            // The EVENT id — the same value for every endpoint that received
            // this event, and the same one `event.outbox` recorded when the
            // event was relayed from there. Lets an operator find every
            // delivery of one event.
            $t->char('event_id', 36);

            // The exact bytes that are signed and sent. Nothing re-serialises
            // this between here and the socket: re-encoding would change key
            // order and unicode escaping, so the body that was signed and the
            // body that arrives would differ and every signature would fail.
            $t->json('body');

            // 0=pending 1=delivered 2=failed(parked) 3=claimed.
            $t->tinyInteger('status')->unsigned()->default(0)
                ->comment('0=pending,1=delivered,2=failed,3=claimed');

            $t->unsignedInteger('attempts')->default(0);

            // When this row becomes eligible again. The backoff lives HERE
            // rather than being recomputed from `attempts` at read time, so a
            // change to the backoff curve cannot retroactively move rows that
            // are already waiting.
            $t->timestamp('next_attempt_at')->nullable();

            // Nullable, and never 0: a transport failure means the request did
            // not happen, which is genuinely different from a receiver that
            // answered 0 — and 0 reads as a status in every table that shows it.
            $t->smallInteger('response_status')->unsigned()->nullable();

            // The receiver's body, truncated and stripped of control characters
            // by DeliveryResult. ATTACKER-CONTROLLED TEXT: it belongs in a
            // terminal or a log, and must never be rendered as markup or echoed
            // into one of our own responses.
            $t->text('response_excerpt')->nullable();

            $t->text('last_error')->nullable();
            $t->unsignedInteger('duration_ms')->nullable();

            $t->string('claimed_by', 64)->nullable()->comment('host:pid:rand — diagnostic only');
            $t->timestamp('claimed_at')->nullable();

            $t->timestamp('delivered_at')->nullable();
            $t->timestamp('created_at')->default('CURRENT_TIMESTAMP');

            // One row per delivery id. Also what makes enqueue() an
            // insert-if-absent, so a re-dispatched event cannot double-queue.
            $t->unique(['delivery_id'], 'uniq_webhook_delivery');

            // The deliverer's hot query: due rows, oldest first. `status` first
            // because it is the most selective, then the time it is ordered and
            // filtered by.
            $t->index(['status', 'next_attempt_at'], 'idx_webhook_due');

            // The reclaim scan, which orders on a different column — a
            // composite whose second column is wrong is an index the planner
            // ignores.
            $t->index(['status', 'claimed_at'], 'idx_webhook_lease');

            // Answering "what happened to this endpoint" and "every delivery of
            // this event", which are the two questions an operator actually
            // asks of this table.
            $t->index(['endpoint_id', 'created_at'], 'idx_webhook_endpoint');
            $t->index(['event_id'], 'idx_webhook_event');

            $t->engine('InnoDB');
            $t->charset('utf8mb4');
        });
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        // Deliveries first: they reference an endpoint id, so dropping the
        // endpoints first would leave a window where the rows point at nothing
        // on a driver that enforces the order.
        $schema->dropIfExists('webhook_deliveries');
        $schema->dropIfExists('webhook_endpoints');
    }
};
