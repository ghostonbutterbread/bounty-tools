/**
 * Disposable Auth Error Replay - Caido Passive Workflow JavaScript node.
 *
 * Workflow shape:
 *   On Intercept Request -> In Scope -> Javascript
 *
 * Expected extra values:
 *   mode: "safe" | "disposable" | "owned-resource"
 *   disposableAuthorization: optional Authorization header value for disposable auth
 *   disposableCookie: optional Cookie header value for disposable auth
 *   ownedPathMarkers: optional array of path fragments that identify disposable owned resources
 *   maxProbes: optional integer probe cap per request
 *
 * Do not commit or export real tokens/cookies. Prefer secret environment-backed
 * workflow inputs where possible.
 */

const DEFAULT_PROBES = ["'", "\"", "%27", "%22", "--", ")", "{", "bad_enum__"];

const GLOBAL_DANGER_RE = /\/(checkout|billing|payment|refund|subscribe|purchase|cart\/(add|remove|update)|password|mfa|2fa|invite|email|message|webhook|upload|admin|delete|destroy|transfer|fulfill|ship)(\/|$|\?)/i;
const ACTION_WORD_RE = /(create|update|delete|destroy|send|invite|subscribe|purchase|refund|transfer|upload|fulfill|ship|submit|approve)/i;

const SIGNATURES = [
  ["sql_orm", /(SQL syntax|PostgreSQL|pg_query|MySQL|MariaDB|SQLite|ORA-\d+|ODBC|JDBC|Prisma|Sequelize|ActiveRecord|Doctrine\\DBAL|Knex|Hibernate)/i],
  ["graphql", /(GraphQL error|Cannot query field|Unknown argument|Unknown type|Cannot return null for non-nullable field|Resolver|graphql-js|GraphQLException)/i],
  ["template", /(Jinja|Twig|Handlebars|Liquid error|TemplateSyntaxError|template syntax|mustache|ERB::|Razor|Velocity|FreeMarker)/i],
  ["parser", /(JsonMappingException|MismatchedInputException|TypeError|ValueError|SyntaxError|unexpected token|invalid character|unmarshal|deserialize|pickle|Marshal|unserialize)/i]
];

function asText(value, sdk) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try {
    return sdk.asString(value);
  } catch (_err) {
    return String(value);
  }
}

function responseText(response, sdk) {
  if (!response) return "";
  try {
    if (response.getBody) return asText(response.getBody(), sdk);
  } catch (_err) {
    return "";
  }
  return "";
}

function responseCode(response) {
  if (!response) return 0;
  try {
    if (response.getCode) return response.getCode();
  } catch (_err) {
    return 0;
  }
  try {
    if (response.getStatusCode) return response.getStatusCode();
  } catch (_err) {
    return 0;
  }
  return 0;
}

function methodOf(request) {
  try {
    return request.getMethod().toUpperCase();
  } catch (_err) {
    return "";
  }
}

function pathOf(request) {
  try {
    return request.getPath() || "/";
  } catch (_err) {
    return "/";
  }
}

function queryOf(request) {
  try {
    return request.getQuery() || "";
  } catch (_err) {
    const path = pathOf(request);
    const idx = path.indexOf("?");
    return idx >= 0 ? path.slice(idx + 1) : "";
  }
}

function hasOwnedMarker(path, markers) {
  if (!Array.isArray(markers)) return false;
  return markers.some((marker) => marker && path.indexOf(marker) >= 0);
}

function classifyRequest(request, extra) {
  const mode = extra.mode || "safe";
  const method = methodOf(request);
  const path = pathOf(request);

  if (GLOBAL_DANGER_RE.test(path) || ACTION_WORD_RE.test(path)) {
    return { allow: false, reason: "dangerous-route" };
  }

  if (["GET", "HEAD", "OPTIONS"].indexOf(method) >= 0) {
    return { allow: true, reason: "read-like" };
  }

  if (mode === "owned-resource" && hasOwnedMarker(path, extra.ownedPathMarkers || [])) {
    return { allow: true, reason: "owned-resource" };
  }

  if (mode === "disposable") {
    return { allow: false, reason: "stateful-requires-owned-resource-marker" };
  }

  return { allow: false, reason: "non-read-method" };
}

function findSignatures(text) {
  const hits = [];
  for (const [name, regex] of SIGNATURES) {
    if (regex.test(text)) hits.push(name);
  }
  return hits;
}

function makeQueryMutations(request, probes, maxProbes) {
  const query = queryOf(request);
  if (!query) return [];
  const params = new URLSearchParams(query);
  const mutations = [];

  for (const key of params.keys()) {
    const original = params.get(key) || "";
    for (const probe of probes) {
      const changed = new URLSearchParams(query);
      changed.set(key, original + probe);
      mutations.push({ param: key, probe, query: changed.toString() });
      if (mutations.length >= maxProbes) return mutations;
    }
  }

  return mutations;
}

async function sendWithDisposableAuth(request, extra, query, sdk) {
  const spec = request.toSpec();
  if (extra.disposableAuthorization) spec.setHeader("Authorization", extra.disposableAuthorization);
  if (extra.disposableCookie) spec.setHeader("Cookie", extra.disposableCookie);
  if (query !== undefined) spec.setQuery(query);
  return await sdk.requests.send(spec);
}

/**
 * @param {HttpInput} input
 * @param {SDK} sdk
 * @returns {MaybePromise<Data | undefined>}
 */
export async function run({ request, response, extra }, sdk) {
  if (!request) return;

  const cfg = extra || {};
  const decision = classifyRequest(request, cfg);
  if (!decision.allow) {
    sdk.console.debug(`Disposable error replay skipped: ${decision.reason} ${methodOf(request)} ${pathOf(request)}`);
    return;
  }

  const maxProbes = Math.max(1, Math.min(Number(cfg.maxProbes || 8), 32));
  const probes = Array.isArray(cfg.probeValues) && cfg.probeValues.length ? cfg.probeValues : DEFAULT_PROBES;
  const mutations = makeQueryMutations(request, probes, maxProbes);
  if (!mutations.length) return;

  const baseline = await sendWithDisposableAuth(request, cfg, undefined, sdk);
  const baselineText = responseText(baseline.response, sdk);
  const baselineHits = findSignatures(baselineText);

  for (const mutation of mutations) {
    const replay = await sendWithDisposableAuth(request, cfg, mutation.query, sdk);
    const probeText = responseText(replay.response, sdk);
    const probeHits = findSignatures(probeText).filter((hit) => baselineHits.indexOf(hit) < 0);

    if (!probeHits.length) continue;

    const title = `Disposable auth error signal: ${probeHits.join(", ")}`;
    const desc = [
      `Route: ${methodOf(request)} ${pathOf(request)}`,
      `Mode: ${cfg.mode || "safe"}`,
      `Safety decision: ${decision.reason}`,
      `Parameter: ${mutation.param}`,
      `Probe: ${mutation.probe}`,
      `Baseline status: ${responseCode(baseline.response)}`,
      `Probe status: ${responseCode(replay.response)}`,
      "",
      "Finding was created only because the alternate-auth baseline did not show the same high-signal signature."
    ].join("\n");

    await sdk.findings.create({
      title,
      description: desc,
      reporter: "Disposable Auth Error Replay",
      request: replay.request
    });

    return;
  }
}
