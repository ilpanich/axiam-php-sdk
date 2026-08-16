<?php

declare(strict_types=1);

/**
 * An AXIAM Reactor — the AMQP extension actor of CONTRACT.md §22.
 *
 * A reactor is an external process that subscribes to named hook events on the
 * AXIAM bus and answers back — allow, deny, or a field-allow-listed mutation —
 * inside a timeout the server declared. Zitadel Actions and Keycloak SPIs solve
 * the same problem by loading third-party code INTO the authorization server; a
 * reactor stays outside it, reachable only through a signed reply schema the
 * server validates before it believes a word of it.
 *
 * The handler below covers all three answers:
 *
 *   - token.pre_issue -> a mutation adding two claims under the `ext.` namespace,
 *     which is the COMPLETE allow-list for that event (§22.5).
 *   - login.post_auth -> a veto for one embargoed region, an allow for everything
 *     else, and a commented step-up branch.
 *
 * Two things this example deliberately does NOT do, because §22 forbids them:
 *
 *   - It never declares an exchange, a queue or a binding. The server declares the
 *     per-reactor queue from the registration; a reactor that could bind could
 *     bind itself to another tenant's routing key (§22.1). The SDK gives it no way
 *     to try.
 *   - It never answers `allow` on its own behalf when something goes wrong. A
 *     handler that cannot decide throws, no reply is published, and the operator's
 *     registered failure_policy decides — which for login.post_auth defaults to
 *     fail_closed (§22.8, §22.10 rule 2).
 *
 * THIS IS A LONG-RUNNING CLI PROCESS, not a web-request path: it blocks until the
 * broker session ends or SIGTERM arrives. `php-amqplib` has no built-in
 * reconnection, so run it under a process supervisor (systemd
 * `Restart=on-failure`, a Kubernetes restart policy, supervisord) exactly as you
 * would `bin/axiam-amqp-worker.php`.
 *
 * Run:
 *   AXIAM_AMQP_URL=amqps://guest:guest@localhost:5671 \
 *   AXIAM_TENANT_ID=... AXIAM_REACTOR_ID=... AXIAM_AMQP_SIGNING_KEY_HEX=... \
 *   php examples/reactor/reactor.php
 *
 * Running it end to end needs a reachable RabbitMQ over TLS and a reactor
 * registered through POST /api/v1/reactors (§22.9).
 */

require __DIR__ . '/../../vendor/autoload.php';

use Axiam\Sdk\Attributes\OnReactorEvent;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Reactor\AmqpLibReactorTransport;
use Axiam\Sdk\Reactor\ReactorAnswer;
use Axiam\Sdk\Reactor\ReactorConfig;
use Axiam\Sdk\Reactor\ReactorEvent;
use Axiam\Sdk\Reactor\ReactorEvents;
use Axiam\Sdk\Reactor\ReactorHandlers;
use Axiam\Sdk\Reactor\ReactorServer;
use Axiam\Sdk\Reactor\ReactorTelemetryEvent;

$amqpUrl = getenv('AXIAM_AMQP_URL') ?: 'amqps://guest:guest@localhost:5671';
$tenantId = getenv('AXIAM_TENANT_ID') ?: '11111111-1111-1111-1111-111111111111';
$reactorId = getenv('AXIAM_REACTOR_ID') ?: '99999999-9999-9999-9999-999999999999';

// §8.1: the per-tenant AMQP subkey MUST come from the AXIAM management API —
// never hardcoded. The SAME key verifies the server's event and signs this
// reactor's reply: §22.2's signing is symmetric in direction, with no second key
// and no asymmetric variant in v1.
//
// §22.12 requires the Sensitive wrapper: the key is a credential, it is never
// logged at any level, and it never appears in a reconnect diagnostic.
$signingKeyHex = getenv('AXIAM_AMQP_SIGNING_KEY_HEX');
if ($signingKeyHex === false || $signingKeyHex === '') {
    fwrite(STDERR, "axiam reactor: AXIAM_AMQP_SIGNING_KEY_HEX is required (fetch the tenant AMQP subkey, §8.1)\n");
    exit(1);
}
$signingKey = hex2bin($signingKeyHex);
if ($signingKey === false) {
    fwrite(STDERR, "axiam reactor: AXIAM_AMQP_SIGNING_KEY_HEX is not hex\n");
    exit(1);
}

$config = new ReactorConfig(
    tenantId: $tenantId,
    signingKey: new Sensitive($signingKey),
    reactorId: $reactorId,
    mode: ReactorEvents::MODE_INTERCEPT,
);

printf("Reactor %s serving tenant %s\n", $reactorId, $tenantId);
printf("  queue (declared by the SERVER): %s\n", $config->queue());
echo "  hookable events:\n";
foreach (ReactorEvents::all() as $spec) {
    printf(
        "    %-16s mutable=%-5s allow-list=%-28s default=%s\n",
        $spec->name,
        $spec->mutable ? 'true' : 'false',
        $spec->mutableFields === [] ? '(veto only)' : implode(', ', $spec->mutableFields),
        $spec->defaultFailurePolicy,
    );
}

/**
 * Logs the fields §22.12 says are explicitly not secrets.
 *
 * The payload is readable by design — a handler that cannot inspect the event
 * cannot decide anything — but it is tenant business data, so it is not logged
 * at info level here and should not be in yours.
 *
 * Chained events also carry the patch earlier reactors already produced, so a
 * handler decides against the state that will actually be committed. That is
 * READ-ONLY context: echoing it back inside your own patch is not how a field
 * is preserved — the server merges (§22.6).
 */
function logEvent(ReactorEvent $event): void
{
    printf("event=%s correlation=%s budget=%dms\n", $event->event, $event->correlationId, $event->timeoutMs);

    $prior = $event->chainPatch();
    if ($prior !== null) {
        printf("  an earlier reactor in the chain already set %d field(s)\n", count($prior));
    }
}

/**
 * The reactor's handlers, one per event (§22.14), instead of a `switch` whose
 * fall-through answers `allow` on behalf of code that never ran.
 *
 * A misspelled event name below is refused when `#[OnReactorEvent]` is
 * instantiated — at wiring time, not as an event that silently never fires. An
 * event nobody bound here abstains, so the registration's `failure_policy`
 * decides rather than this file.
 *
 * `$event->timeoutMs` is the budget the server will actually wait — it is
 * inside the signed body, so it cannot be widened in transit. A handler doing
 * real work (a fraud lookup, a directory query) should honour it and shed load
 * rather than answer into a window the server has already closed (§22.3).
 */
final class ExampleReactor
{
    /**
     * `ext.` is the COMPLETE allow-list for this event. `sub`, `aud`, `exp`,
     * `scope` and every other standard claim are unreachable, and a correctly
     * signed reply setting one is refused exactly as a forged one is.
     *
     * Note also that a single forbidden key rejects the WHOLE patch — the SDK
     * sends what you return, UNFILTERED, rather than quietly dropping the
     * offender and leaving you believing it was set (§22.4 rule 1).
     */
    #[OnReactorEvent(ReactorEvents::TOKEN_PRE_ISSUE)]
    public function enrichToken(ReactorEvent $event): ReactorAnswer
    {
        logEvent($event);

        $sub = is_string($event->payload['sub'] ?? null) ? $event->payload['sub'] : 'unknown';

        return ReactorAnswer::mutate([
            'ext.cost_center' => lookupCostCenter($sub),
            'ext.department' => 'eng',
        ]);
    }

    /** Veto-only, plus step-up. */
    #[OnReactorEvent(ReactorEvents::LOGIN_POST_AUTH)]
    public function screenLogin(ReactorEvent $event): ReactorAnswer
    {
        logEvent($event);

        $ip = is_string($event->payload['ip'] ?? null) ? $event->payload['ip'] : '';
        if (str_starts_with($ip, '203.0.113.')) {
            // A deny short-circuits the chain: no later reactor is consulted.
            // The reason is audited; the server substitutes "denied by reactor"
            // when one is absent.
            return ReactorAnswer::deny('embargoed region');
        }

        // Step-up is an `allow` carrying require_mfa, and it is valid on this
        // event ONLY. On the federated paths (SAML ACS, OIDC callback) there is
        // no step-up branch, so a require_mfa answer FAILS the sign-in rather
        // than being dropped — answer deny there and drive enrolment out of
        // band (§22.5).
        //
        // return ReactorAnswer::allowWithStepUp();

        return ReactorAnswer::allow();
    }
}

$handlers = ReactorHandlers::of(new ExampleReactor());

/** Stands in for whatever directory or HR system a real reactor would consult. */
function lookupCostCenter(string $subject): string
{
    return substr(sha1($subject), 0, 4);
}

$caFile = getenv('AXIAM_AMQP_CA_PEM');

// §8b: amqps:// only, with an optional CA bundle. There is no verification-skip
// switch anywhere in this SDK.
$transport = AmqpLibReactorTransport::connect($amqpUrl, $caFile === false || $caFile === '' ? null : $caFile);

$server = new ReactorServer(
    config: $config,
    transport: $transport,
    handler: $handlers->handler(),
    // §19: worth wiring rather than optional. A fail_open timeout produces `allow`
    // AND an audit record, and that pair is the whole difference between "no
    // reactor was configured" and "the reactor never answered" — reactor health
    // must never be inferred from the outcome alone (§22.8).
    telemetryHook: static function (ReactorTelemetryEvent $event): void {
        printf(
            "  telemetry phase=%s event=%s reason=%s decision=%s\n",
            $event->phase,
            $event->event,
            $event->reason ?? '-',
            $event->decision ?? '-',
        );
    },
);

// §18: a graceful stop finishes the delivery in flight and answers it, rather
// than abandoning a decision the server is still waiting for.
if (function_exists('pcntl_signal')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, static fn () => $server->stop());
    pcntl_signal(SIGINT, static fn () => $server->stop());
}

$server->reactorServe();
$transport->close();

echo "Reactor stopped; the delivery in flight was answered before returning.\n";
