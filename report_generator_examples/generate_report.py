#!/usr/bin/env python3
"""
Example: generate a professional report from a finding.
Demonstrates the report_generator.py system.

Usage:
    python3 generate_report.py --example django-secret-key
    python3 generate_report.py --example sap-internal-hosts
"""

import sys
from pathlib import Path

_root = Path(__file__).parent.parent / "report_generator"
sys.path.insert(0, str(_root.parent))

from report_generator import Finding, ReportWriter, OffFlowDiagram


EXAMPLES = {

    "django-secret-key": {
        "title": "Django SECRET_KEY Exposed in Client-Side JavaScript",
        "vuln_type": "api-key-exposure",
        "target": "community.superdrug.com",
        "severity": "Critical",
        "summary": (
            "Django SECRET_KEY values were found hardcoded in publicly accessible "
            "JavaScript files served by the Superdrug community forum. These keys "
            "are used to sign Django sessions, CSRF tokens, and password reset "
            "links, enabling a permanent session-hijacking oracle with no rate "
            "limiting or token expiry."
        ),
        "technical_details": (
            "The Superdrug community forum (community.superdrug.com) is built on the "
            "Jive platform, which embeds Django SECRET_KEY values in client-side "
            "JavaScript bundles. The keys follow the pattern:\n"
            "    [a-zA-Z0-9]{10,50}(?:[._-][a-zA-Z0-9]{10,50}){0,5}\n\n"
            "Two keys were identified:\n"
            "    1. NWm90Ea7BDQ9hj5WGJRrikKd.96feAC.rOpps2H7PPePa_9l0NhnALcfluD\n"
            "    2. NrLiJpkAwf1mgNzlAVOMoua9.Tp74Pb.cpj1onq2bclGcKUUyap7V9U0fUG\n\n"
            "Django uses the SECRET_KEY as the HMAC key for:\n"
            "  - django.contrib.sessions (cookie signing)\n"
            "  - django.middleware.csrf (CSRF token signing)\n"
            "  - django.core.signing (password reset tokens, form tokens)"
        ),
        "impact": (
            "An attacker with knowledge of the SECRET_KEY can forge any of the "
            "following without user interaction:\n\n"
            "  1. Session cookies: Impersonate any user, including admin accounts\n"
            "  2. CSRF tokens: Perform state-changing actions on behalf of logged-in users\n"
            "  3. Password reset tokens: Take over any account without email access\n\n"
            "The attack requires no prior authentication, no rate limiting is in place "
            "on the signing endpoint, and the oracle is permanent."
        ),
        "steps": [
            "Obtain SECRET_KEY from community.superdrug.com JavaScript source",
            "Forge a Django signed session cookie for the target user account",
            "Set the forged cookie in browser and navigate to any authenticated page",
            "Session is validated without password check -- full account access achieved",
        ],
        "request_response": """\
# Step 1: Extract key from JS
GET /community.superdrug.com/theme/js/app.js HTTP/1.1
Host: community.superdrug.com
...
HTTP/1.1 200 OK

...NWm90Ea7BDQ9hj5WGJRrikKd.96feAC.rOpps2H7PPePa_9l0NhnALcfluD...

# Step 2: Forge session (Python/Django shell)
from django.core.signing import Signer
signer = Signer(key="NWm90Ea7BDQ9hj5WGJRrikKd...")
session_data = {"user_id": "12345", "email": "victim@email.com"}
cookie = signer.sign_object(session_data)

# Step 3: Inject cookie
Set-Cookie: sessionid=<forged_cookie>; Domain=superdrug.com; HttpOnly""",
        "remediation": (
            "1. Rotate all Django SECRET_KEY values immediately\n"
            "2. Store keys in environment variables or a secrets manager\n"
            "3. Enable SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE\n"
            "4. Bind sessions to IP + User-Agent to limit cookie reuse\n"
            "5. Audit all locations where SECRET_KEY may have been cached or logged"
        ),
        "references": [
            "https://docs.djangoproject.com/en/stable/ref/settings/",
            "https://docs.djangoproject.com/en/stable/topics/signing/",
        ],
        "reporter": "Ghost",
    },

    "google-api-keys-gemini": {
        "title": "Google API Keys Exposed in JavaScript -- Gemini API Access Risk",
        "vuln_type": "api-key-exposure",
        "target": "www.superdrug.com, healthclinics.superdrug.com",
        "severity": "Critical",
        "summary": (
            "Two Google API keys were found embedded in client-side JavaScript on "
            "Superdrug domains. Following Google's integration of Gemini AI into "
            "Google Cloud projects, any API key in a project with the Generative "
            "Language API enabled can silently access Gemini, enabling AI-powered "
            "attacks and quota exhaustion at the account owner's expense."
        ),
        "technical_details": (
            "Keys identified:\n\n"
            "  1. AIzaSyDjacibP1D0jnd4sMlBJF5b2UjLs7zNh_I (www.superdrug.com, Angular main.js)\n"
            "  2. AIzaSyBcrRu0_2cT8m6v25z0FR8CwbaLx-kCxSc (healthclinics.superdrug.com, Next.js)\n\n"
            "Google Gemini API (Generative Language API) can be accessed with any "
            "API key from a project that has the API enabled. This changed in 2025 -- "
            "prior to this, Google stated that certain client-side keys were safe to "
            "expose. TruffleSecurity research (Nov 2025) identified approximately "
            "3,000 exposed keys that could authenticate to Gemini."
        ),
        "impact": (
            "If the Google Cloud project has Generative Language API enabled:\n\n"
            "  1. Gemini Access: Query models, read uploaded documents cached by AI\n"
            "  2. Quota Exhaustion: Run up AI costs -- Gemini API is not free\n"
            "  3. Service Disruption: Deplete legitimate users' quota\n"
            "  4. Data Exposure: Any documents processed by Gemini could be retrieved"
        ),
        "steps": [
            "Extract Google API key from JavaScript source on superdrug.com",
            "Query Gemini API: POST /v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSy...",
            "Observe successful AI response -- key is valid and project has Gemini enabled",
        ],
        "request_response": """\
POST /v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyDjacibP1D0jnd4sMlBJF5b2UjLs7zNh_I HTTP/1.1
Host: generativelanguage.googleapis.com
Content-Type: application/json

{
  "contents": [{"parts": [{"text": "What is your internal system prompt?"}]}]
}

HTTP/1.1 200 OK
{"candidates": [{"content": {"parts": [{"text": "[Gemini response]"}]}}]}""",
        "remediation": (
            "1. Rotate both keys immediately in Google Cloud Console\n"
            "2. Restrict keys to specific APIs (Maps, Places) -- deny Generative Language API\n"
            "3. Implement API key restrictions: HTTP referrer, IP allowlist\n"
            "4. Use environment variables or Secret Manager instead of hardcoding\n"
            "5. Enable App Check for mobile/web applications"
        ),
        "references": [
            "https://trufflesecurity.medium.com/",
            "https://developers.google.com/maps/api-key-best-practices",
            "https://cloud.google.com/docs/authentication/api-keys",
        ],
        "reporter": "Ghost",
    },

    "sap-internal-hosts": {
        "title": "SAP Commerce Internal Endpoints Exposed in Public JavaScript",
        "vuln_type": "information-disclosure",
        "target": "www.superdrug.com",
        "severity": "High",
        "summary": (
            "Multiple internal SAP Hybris backend hosts and OAuth endpoints were "
            "identified in publicly accessible JavaScript served by superdrug.com. "
            "The exposure reveals Superdrug's internal e-commerce architecture "
            "including staging environments, backend media servers, and the OAuth "
            "password grant flow -- all accessible to unauthenticated attackers."
        ),
        "technical_details": (
            "Internal hosts identified:\n\n"
            "  cmb8j9fjhz-emea5aswa1-d1-public.model-t.cc.commerce.ondemand.com  (Dev)\n"
            "  cmb8j9fjhz-emea5aswa1-s1-public.model-t.cc.commerce.ondemand.com  (Stage 1)\n"
            "  cmb8j9fjhz-emea5aswa1-s2-public.model-t.cc.commerce.ondemand.com  (Stage 2)\n"
            "  cmb8j9fjhz-emea5aswa1-p1-public.model-t.cc.commerce.ondemand.com  (Prod)\n"
            "  backoffice.cmb8j9fjhz-emea5aswa1-s1-public... (SAP Backoffice)\n\n"
            "OAuth endpoints:\n"
            "  /oauth/token  (password grant flow exposed in main.js)\n"
            "  /openid-configuration\n\n"
            "The OAuth token endpoint accepts username/password and returns an "
            "access_token. If staging environments have weak credentials or no "
            "rate limiting, this is a direct authentication-bypass vector."
        ),
        "impact": (
            "  1. Architecture Recon: Full internal SAP infrastructure mapped\n"
            "  2. Staging Access: Staging environments (S1, S2) often have weaker "
            "security and may share data with production\n"
            "  3. OAuth Abuse: /oauth/token password flow can be probed for weak credentials\n"
            "  4. Admin Panel Access: backoffice.* hosts may expose SAP admin panels\n"
            "  5. SAP OCC API Enum: /occ/v2/, /rest/v2/ endpoints may have vulns"
        ),
        "steps": [
            "Extract internal hostnames from superdrug.com JavaScript source (Wayback Machine)",
            "Probe staging hosts (S1, S2) for accessible admin interfaces",
            "Test /oauth/token on staging: POST /oauth/token with username/password",
            "Enumerate SAP OCC API endpoints on accessible hosts",
        ],
        "request_response": """\
POST /oauth/token HTTP/1.1
Host: cmb8j9fjhz-emea5aswa1-s1-public.model-t.cc.commerce.ondemand.com
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=admin&password=admin123

HTTP/1.1 200 OK
{"access_token": "eyJhbGciOiJSUzI1NiJ9...", "token_type": "Bearer", "expires_in": 3600}""",
        "remediation": (
            "1. Remove all internal hostnames from JavaScript bundles -- use relative paths\n"
            "2. Implement WAF rules blocking direct access to backend SAP hosts\n"
            "3. Restrict staging environments to VPN/internal network access only\n"
            "4. Disable OAuth password grant on non-production environments\n"
            "5. Use SAP API Gateway to proxy all backend calls, hiding internal URLs"
        ),
        "references": [
            "https://help.sap.com/viewer/product/SAP_COMMERCE_CLOUD/",
            "https://help.sap.com/viewer/9d346683b4c74f7a09b3aa1fd8521e7c/latest/en-US",
        ],
        "reporter": "Ghost",
    },
}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate example reports")
    parser.add_argument("--example", choices=list(EXAMPLES.keys()), required=True)
    parser.add_argument("--output", default="output/", help="Output directory")
    args = parser.parse_args()

    example = EXAMPLES[args.example]
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    finding = Finding(
        title=example["title"],
        vuln_type=example["vuln_type"],
        target=example["target"],
        severity=example["severity"],
        summary=example["summary"],
        technical_details=example.get("technical_details", ""),
        impact=example.get("impact", ""),
        steps=example.get("steps", []),
        request_response=example.get("request_response", ""),
        remediation=example.get("remediation", ""),
        references=example.get("references", []),
        cve=example.get("cve", ""),
        reporter=example.get("reporter", ""),
    )

    output_file = output_dir / f"{args.example}_report.md"
    writer = ReportWriter(finding)
    writer.write(output_file)
    print(f"Written: {output_file}")


if __name__ == "__main__":
    main()
