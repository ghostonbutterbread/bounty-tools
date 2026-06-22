#!/usr/bin/env python3
"""Disposable-auth error replay worker.

This helper mirrors the Caido workflow's core policy and detection logic so the
workflow can be tested without touching a live bug bounty target.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_PROBES = ("'", '"', "%27", "%22", "--", ")", "{", "bad_enum__")

GLOBAL_DANGER_RE = re.compile(
    r"/(checkout|billing|payment|refund|subscribe|purchase|cart/(add|remove|update)|"
    r"password|mfa|2fa|invite|email|message|webhook|upload|admin|delete|destroy|"
    r"transfer|fulfill|ship)(/|$|\?)",
    re.I,
)
ACTION_WORD_RE = re.compile(
    r"(create|update|delete|destroy|send|invite|subscribe|purchase|refund|transfer|"
    r"upload|fulfill|ship|submit|approve)",
    re.I,
)

SIGNATURES: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "sql_orm",
        re.compile(
            r"SQL syntax|PostgreSQL|pg_query|MySQL|MariaDB|SQLite|ORA-\d+|ODBC|"
            r"JDBC|Prisma|Sequelize|ActiveRecord|Doctrine\\DBAL|Knex|Hibernate",
            re.I,
        ),
    ),
    (
        "graphql",
        re.compile(
            r"GraphQL error|Cannot query field|Unknown argument|Unknown type|"
            r"Cannot return null for non-nullable field|Resolver|graphql-js|"
            r"GraphQLException",
            re.I,
        ),
    ),
    (
        "template",
        re.compile(
            r"Jinja|Twig|Handlebars|Liquid error|TemplateSyntaxError|template syntax|"
            r"mustache|ERB::|Razor|Velocity|FreeMarker",
            re.I,
        ),
    ),
    (
        "parser",
        re.compile(
            r"JsonMappingException|MismatchedInputException|TypeError|ValueError|"
            r"SyntaxError|unexpected token|invalid character|unmarshal|deserialize|"
            r"pickle|Marshal|unserialize",
            re.I,
        ),
    ),
)


@dataclass(frozen=True)
class RequestCase:
    method: str
    url: str
    headers: Dict[str, str]
    body: bytes = b""


@dataclass(frozen=True)
class RouteDecision:
    allow: bool
    reason: str


@dataclass(frozen=True)
class Mutation:
    location: str
    name: str
    probe: str
    request: RequestCase


@dataclass(frozen=True)
class ResponseSummary:
    status: int
    length: int
    text: str


@dataclass(frozen=True)
class Alert:
    family: str
    location: str
    name: str
    probe: str
    baseline_status: int
    probe_status: int
    baseline_length: int
    probe_length: int


def load_request(path: str) -> RequestCase:
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)

    body = raw.get("body", b"")
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    elif isinstance(body, list):
        body_bytes = bytes(body)
    else:
        body_bytes = b""

    return RequestCase(
        method=str(raw.get("method", "GET")).upper(),
        url=str(raw["url"]),
        headers={str(k): str(v) for k, v in raw.get("headers", {}).items()},
        body=body_bytes,
    )


def classify_request(
    request: RequestCase,
    mode: str = "safe",
    owned_markers: Sequence[str] = (),
) -> RouteDecision:
    parsed = urllib.parse.urlsplit(request.url)
    path_with_query = parsed.path + (("?" + parsed.query) if parsed.query else "")

    if GLOBAL_DANGER_RE.search(path_with_query) or ACTION_WORD_RE.search(path_with_query):
        return RouteDecision(False, "dangerous-route")

    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return RouteDecision(True, "read-like")

    if mode == "owned-resource" and any(marker and marker in parsed.path for marker in owned_markers):
        return RouteDecision(True, "owned-resource")

    if mode == "disposable":
        return RouteDecision(False, "stateful-requires-owned-resource-marker")

    return RouteDecision(False, "non-read-method")


def with_alt_auth(
    request: RequestCase,
    authorization: Optional[str] = None,
    cookie: Optional[str] = None,
) -> RequestCase:
    headers = dict(request.headers)
    if authorization:
        headers["Authorization"] = authorization
    if cookie:
        headers["Cookie"] = cookie
    return RequestCase(request.method, request.url, headers, request.body)


def mutate_query(request: RequestCase, probes: Sequence[str] = DEFAULT_PROBES) -> List[Mutation]:
    parsed = urllib.parse.urlsplit(request.url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    mutations: List[Mutation] = []

    for key, value in pairs:
        for probe in probes:
            changed_pairs = [(k, (v + probe) if k == key else v) for k, v in pairs]
            new_query = urllib.parse.urlencode(changed_pairs, doseq=True)
            new_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
            )
            mutations.append(Mutation("query", key, probe, RequestCase(request.method, new_url, dict(request.headers), request.body)))

    return mutations


def mutate_json_body(request: RequestCase, probes: Sequence[str] = DEFAULT_PROBES) -> List[Mutation]:
    content_type = next((v for k, v in request.headers.items() if k.lower() == "content-type"), "")
    if "json" not in content_type.lower() or not request.body:
        return []

    try:
        body = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []

    if not isinstance(body, dict):
        return []

    mutations: List[Mutation] = []
    for key, value in body.items():
        if isinstance(value, (dict, list)):
            continue
        for probe in probes:
            changed = dict(body)
            changed[key] = f"{value}{probe}"
            changed_body = json.dumps(changed, separators=(",", ":")).encode("utf-8")
            mutations.append(Mutation("json", str(key), probe, RequestCase(request.method, request.url, dict(request.headers), changed_body)))

    return mutations


def build_mutations(
    request: RequestCase,
    probes: Sequence[str] = DEFAULT_PROBES,
    max_probes: int = 8,
) -> List[Mutation]:
    mutations = mutate_query(request, probes)
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        mutations.extend(mutate_json_body(request, probes))
    return mutations[:max(1, max_probes)]


def detect_signatures(text: str) -> List[str]:
    return [name for name, regex in SIGNATURES if regex.search(text)]


def send_request(request: RequestCase, timeout: float = 10.0) -> ResponseSummary:
    req = urllib.request.Request(
        request.url,
        data=request.body if request.body else None,
        headers=request.headers,
        method=request.method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read(1024 * 1024)
            text = data.decode("utf-8", errors="replace")
            return ResponseSummary(response.status, len(data), text)
    except urllib.error.HTTPError as exc:
        data = exc.read(1024 * 1024)
        text = data.decode("utf-8", errors="replace")
        return ResponseSummary(exc.code, len(data), text)


def compare_baseline_probe(
    baseline: ResponseSummary,
    probe: ResponseSummary,
    mutation: Mutation,
) -> List[Alert]:
    baseline_hits = set(detect_signatures(baseline.text))
    probe_hits = [hit for hit in detect_signatures(probe.text) if hit not in baseline_hits]

    return [
        Alert(
            family=hit,
            location=mutation.location,
            name=mutation.name,
            probe=mutation.probe,
            baseline_status=baseline.status,
            probe_status=probe.status,
            baseline_length=baseline.length,
            probe_length=probe.length,
        )
        for hit in probe_hits
    ]


def run_replay(
    request: RequestCase,
    mode: str,
    owned_markers: Sequence[str],
    authorization: Optional[str],
    cookie: Optional[str],
    max_probes: int,
    timeout: float,
    dry_run: bool,
) -> Tuple[RouteDecision, List[Mutation], List[Alert]]:
    decision = classify_request(request, mode=mode, owned_markers=owned_markers)
    if not decision.allow:
        return decision, [], []

    alt_request = with_alt_auth(request, authorization=authorization, cookie=cookie)
    mutations = build_mutations(alt_request, max_probes=max_probes)
    if dry_run:
        return decision, mutations, []

    baseline = send_request(alt_request, timeout=timeout)
    alerts: List[Alert] = []
    for mutation in mutations:
        probe = send_request(mutation.request, timeout=timeout)
        alerts.extend(compare_baseline_probe(baseline, probe, mutation))

    return decision, mutations, alerts


def env_value(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    value = os.environ.get(name)
    if value == "":
        return None
    return value


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-json", required=True, help="Request JSON with method, url, headers, body.")
    parser.add_argument("--mode", choices=("safe", "disposable", "owned-resource"), default="safe")
    parser.add_argument("--owned-marker", action="append", default=[], help="Path fragment that marks an owned disposable resource.")
    parser.add_argument("--alt-authorization-env", help="Environment variable containing disposable Authorization value.")
    parser.add_argument("--alt-cookie-env", help="Environment variable containing disposable Cookie value.")
    parser.add_argument("--max-probes", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    request = load_request(args.request_json)
    decision, mutations, alerts = run_replay(
        request=request,
        mode=args.mode,
        owned_markers=args.owned_marker,
        authorization=env_value(args.alt_authorization_env),
        cookie=env_value(args.alt_cookie_env),
        max_probes=args.max_probes,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )

    output = {
        "decision": {"allow": decision.allow, "reason": decision.reason},
        "planned_probe_count": len(mutations),
        "planned_probes": [
            {
                "location": mutation.location,
                "name": mutation.name,
                "probe": mutation.probe,
                "url": mutation.request.url,
            }
            for mutation in mutations
        ],
        "alerts": [alert.__dict__ for alert in alerts],
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 2 if alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
