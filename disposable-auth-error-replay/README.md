# Disposable Auth Error Replay Workflow

This is the canonical bounty-tools copy of the Caido-first prototype for Ryushe's "browse normally, replay with disposable auth, alert on useful error bugs" idea.

It has three pieces:

- `caido-passive-replay.workflow.json` - JSON workflow definition with the passive node graph and safe default `extra` values.
- `caido-passive-replay.js` - paste into a Caido Passive Workflow JavaScript node.
- `replay_worker.py` - local helper for testing the same safety/error logic from a saved request JSON.

## Caido Workflow Shape

Create a Passive workflow:

```text
On Intercept Request -> In Scope -> Javascript
```

Paste `caido-passive-replay.js` into the JavaScript node.

Use `caido-passive-replay.workflow.json` as the JSON source of truth for the node graph and default configuration. Configure these JavaScript node `extra` values:

```json
{
  "mode": "safe",
  "disposableAuthorization": "Bearer <DISPOSABLE_TOKEN>",
  "disposableCookie": "session=<DISPOSABLE_SESSION>",
  "ownedPathMarkers": ["/drafts/", "/projects/disposable-"],
  "maxProbes": 8
}
```

Use either `disposableAuthorization` or `disposableCookie`; both are optional so the workflow can also run as a passive detector. Treat those values as secrets in Caido and do not commit/export a workflow with real values.

## Modes

- `safe` - only read-like requests: `GET`, `HEAD`, `OPTIONS`, and query-param probes.
- `disposable` - allows broader route coverage with disposable auth, but still blocks global-danger surfaces.
- `owned-resource` - allows stateful methods only when the URL includes one of the configured `ownedPathMarkers`.

Disposable auth does not mean all actions are safe. It protects the test account, not other users, staff-visible workflows, payments, email sends, or shared org state.

## Alert Model

The workflow only raises findings when a probe produces a high-signal error that was absent in the alternate-auth baseline:

- SQL/ORM: PostgreSQL, MySQL, SQLite, SQL syntax, Prisma, Sequelize, ActiveRecord
- GraphQL: GraphQL error, resolver stack, unknown field/type
- Template/parser: Jinja, Twig, Handlebars, Liquid, template syntax
- Deserialization/type parsing: Jackson, JsonMappingException, pickle, Marshal, unserialize

Generic `500` alone is logged as interesting by the local worker, but should not be treated as a finding without a concrete signature or security-relevant differential.

## Local Worker

Example request JSON:

```json
{
  "method": "GET",
  "url": "http://127.0.0.1:8080/search?q=test",
  "headers": {
    "User-Agent": "ghost-error-replay/0.1"
  },
  "body": ""
}
```

Dry-run planned probes:

```bash
python3 ~/projects/bounty-tools/disposable-auth-error-replay/replay_worker.py \
  --request-json /tmp/request.json \
  --mode safe \
  --dry-run
```

Live replay against an owned/local/lab target:

```bash
DISPOSABLE_AUTH="Bearer fake-token" \
python3 ~/projects/bounty-tools/disposable-auth-error-replay/replay_worker.py \
  --request-json /tmp/request.json \
  --mode safe \
  --alt-authorization-env DISPOSABLE_AUTH
```

## Safety Defaults

Default denied paths include checkout, billing, refunds, password/auth/MFA, invites, email sends, webhooks, uploads, admin, delete, purchase, subscribe, transfer, and similar action words.

Default denied methods are `POST`, `PUT`, `PATCH`, and `DELETE` unless using `owned-resource` mode with an owned marker.

## MCP Status

Caido MCP is used for inspection/export/replay integration when reachable. This prototype does not require MCP to run tests; MCP connectivity should be checked before any attempt to install or exercise it against real Caido traffic.
