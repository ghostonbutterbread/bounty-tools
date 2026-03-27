"""
BAC Checks — Broken Access Control test cases and checklists.
Built from security research, podcast findings, and OWASP standards.

Usage:
    from bac_checks import BACChecks
    checks = BACChecks()
    checks.run_all(target, credentials)
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BACFinding:
    category: str           # e.g. "idor", "escalation", "auth_bypass"
    test_name: str          # Human-readable test name
    endpoint: str           # URL or endpoint pattern
    method: str = "GET"    # HTTP method
    severity: Severity = Severity.MEDIUM
    description: str = ""
    expected: str = ""      # What should happen (secure behavior)
    actual: str = ""        # What actually happened (vulnerable behavior)
    poc: str = ""           # Proof of concept steps
    references: list[str] = field(default_factory=list)
    resolved: bool = False
    notes: str = ""


# ─── Priority Test Catalog ────────────────────────────────────────────────────

# P0 — Critical: Account Takeover, Token Misuse
P0_TESTS = [
    {
        "category": "auth_bypass",
        "test_name": "Token tied to correct user?",
        "description": "Test if a password reset token can be used to change another user's password",
        "expected": "Token only valid for the email it was sent to",
        "method": "POST",
        "endpoint": "/api/v*/resetpassword",
        "poc_steps": [
            "1. Request reset for userA@example.com",
            "2. Intercept the reset token",
            "3. Attempt to use userA's token on userB@example.com's account",
            "4. Check if userB's password is changed"
        ],
        "refs": ["OWASP AT-006", "CWE-287"]
    },
    {
        "category": "auth_bypass",
        "test_name": "Token valid after password change?",
        "description": "Reset tokens should be invalidated when password is changed",
        "expected": "Old reset tokens rejected after password change",
        "method": "POST",
        "endpoint": "/api/v*/resetpassword",
        "poc_steps": [
            "1. Request password reset",
            "2. Change account password (while logged in)",
            "3. Attempt to use the reset token from step 1",
            "4. Token should be rejected"
        ],
        "refs": ["OWASP AT-006"]
    },
    {
        "category": "auth_bypass",
        "test_name": "Email takeover without verification?",
        "description": "Can an attacker update email without password confirmation?",
        "expected": "Email changes require password re-entry",
        "method": "PUT",
        "endpoint": "/api/v*/users/*/email",
        "poc_steps": [
            "1. Log in as userA",
            "2. Attempt to change email to userB@example.com",
            "3. Check if password confirmation required",
            "4. Check if email verification sent to NEW email only"
        ],
        "refs": ["OWASP AT-002"]
    },
    {
        "category": "auth_bypass",
        "test_name": "Plus-addressing account duplication",
        "description": "user+tag@example.com vs user@example.com — same inbox or different accounts?",
        "expected": "Backend normalizes plus-addressing OR treats as same account",
        "method": "POST",
        "endpoint": "/api/v*/users",
        "poc_steps": [
            "1. Register userA@example.com",
            "2. Attempt to register userA+test@example.com",
            "3. Check if separate account created or 'already exists' returned"
        ],
        "refs": ["CWE-287"]
    },
]

# P1 — High: Missing Authorization, IDOR
P1_TESTS = [
    {
        "category": "idor",
        "test_name": "Token state bypass (ignoreState)",
        "description": "Can reset token be used without prior request?",
        "expected": "Token only valid after forgottenPasswordTokens API called",
        "method": "POST",
        "endpoint": "/api/v*/resetpassword",
        "poc_steps": [
            "1. Directly POST to reset endpoint WITHOUT requesting token first",
            "2. Check if token validation is stateful or stateless"
        ],
        "refs": ["OWASP AT-005"]
    },
    {
        "category": "idor",
        "test_name": "Email enumeration via timing",
        "description": "Different response times for real vs non-existent emails",
        "expected": "Identical response times and messages for all emails",
        "method": "POST",
        "endpoint": "/api/v*/forgottenpasswordtokens",
        "poc_steps": [
            "1. Send forgot password for real@example.com — measure time",
            "2. Send forgot password for nonexistent@example.com — measure time",
            "3. Compare response times (difference >100ms = leak)"
        ],
        "refs": ["OWASP AT-001"]
    },
    {
        "category": "escalation",
        "test_name": "Horizontal privilege escalation via IDOR",
        "description": "Can user A access user B's resources by manipulating IDs?",
        "expected": "403 Forbidden when accessing another user's resources",
        "method": "GET",
        "endpoint": "/api/v*/users/{user_id}/profile",
        "poc_steps": [
            "1. Log in as userA, note your user_id",
            "2. Replace user_id with userB's ID in URL",
            "3. If 200 returned with userB's data = IDOR"
        ],
        "refs": ["OWASP AZ-002", "CWE-639"]
    },
    {
        "category": "escalation",
        "test_name": "Vertical privilege escalation — admin functions",
        "description": "Can a regular user access admin endpoints?",
        "expected": "403 Forbidden for non-admin users on admin routes",
        "method": "GET",
        "endpoint": "/api/v*/admin/*",
        "poc_steps": [
            "1. Log in as regular user",
            "2. Attempt to access /admin, /dashboard, /manage, etc.",
            "3. Check for 200 (should be 401/403)"
        ],
        "refs": ["OWASP AZ-003", "CWE-269"]
    },
    {
        "category": "auth_bypass",
        "test_name": "OAuth implicit flow token leak",
        "description": "Access tokens exposed in URL fragments (browser history, logs)",
        "expected": "Tokens in POST body or secure cookies, not URL",
        "method": "GET",
        "endpoint": "/oauth/authorize",
        "poc_steps": [
            "1. Initiate OAuth flow",
            "2. Check redirect URI for access_token in URL fragment",
            "3. Check browser history, server logs for token exposure"
        ],
        "refs": ["OWASP AT-008"]
    },
    {
        "category": "auth_bypass",
        "test_name": "HTTP verb tampering",
        "description": "Does the server properly restrict HTTP methods?",
        "expected": "Only allowed methods return 200, others return 405",
        "method": "PUT",
        "endpoint": "/api/v*/users/*",
        "poc_steps": [
            "1. Try GET, POST, PUT, DELETE on protected endpoints",
            "2. Check if authorization enforced on all methods"
        ],
        "refs": ["OWASP AT-004"]
    },
]

# P2 — Medium: Informational, Configuration Issues
P2_TESTS = [
    {
        "category": "auth_bypass",
        "test_name": "Case-sensitivity account duplication",
        "description": "Can A@example.com and a@example.com be registered as separate accounts?",
        "expected": "Email normalized to lowercase before lookup",
        "method": "POST",
        "endpoint": "/api/v*/users",
        "poc_steps": [
            "1. Register A@example.com",
            "2. Attempt to register a@example.com",
            "3. Check if 'already exists' or separate account created"
        ],
        "refs": ["CWE-287"]
    },
    {
        "category": "idor",
        "test_name": "Sequential ID enumeration",
        "description": "Can resource IDs be predicted by iterating numbers?",
        "expected": "UUIDs or non-guessable IDs, or proper authorization on all IDs",
        "method": "GET",
        "endpoint": "/api/v*/orders/{id}",
        "poc_steps": [
            "1. Access your own resource, note the ID format",
            "2. Try incrementing/decrementing ID by 1",
            "3. Check for 200 responses on other users' resources"
        ],
        "refs": ["OWASP AZ-002", "CWE-639"]
    },
    {
        "category": "auth_bypass",
        "test_name": "Missing rate limiting on auth endpoints",
        "description": "No rate limiting allows unlimited password guesses or token requests",
        "expected": "After 5-10 attempts, further requests blocked for 15+ minutes",
        "method": "POST",
        "endpoint": "/api/v*/login",
        "poc_steps": [
            "1. Send 10+ rapid login attempts",
            "2. Check if account locks, CAPTCHA required, or requests blocked",
            "3. No protection = vulnerability"
        ],
        "refs": ["OWASP AT-007"]
    },
    {
        "category": "auth_bypass",
        "test_name": "Weak password policy",
        "description": "Can trivial passwords be set?",
        "expected": "Min 8 chars, mixed case, numbers, special chars, not in common lists",
        "method": "POST",
        "endpoint": "/api/v*/users",
        "poc_steps": [
            "1. Attempt to register with password: '123456', 'password', 'admin'",
            "2. Check if weak passwords are accepted"
        ],
        "refs": ["OWASP AT-001"]
    },
    {
        "category": "escalation",
        "test_name": "Forceful browsing to protected routes",
        "description": "Can protected pages be accessed directly without auth check?",
        "expected": "All protected pages redirect to login when unauthenticated",
        "method": "GET",
        "endpoint": "/dashboard/*",
        "poc_steps": [
            "1. Without logging in, try accessing /dashboard, /settings, /profile",
            "2. Check if redirected to login or content accessible"
        ],
        "refs": ["OWASP AZ-001"]
    },
    {
        "category": "auth_bypass",
        "test_name": "JWT algorithm confusion / none algorithm",
        "description": "Can JWT signature be bypassed by changing algorithm to 'none'?",
        "expected": "Server rejects tokens with 'none' algorithm",
        "method": "POST",
        "endpoint": "/api/v*/graphql",
        "poc_steps": [
            "1. Take a JWT token",
            "2. Change algorithm from 'RS256' to 'none'",
            "3. Remove signature, change payload to admin",
            "4. Send request with modified token"
        ],
        "refs": ["OWASP AT-009", "CWE-347"]
    },
]


class BACChecks:
    """
    Runs prioritized BAC tests against a target.
    
    Usage:
        from bac_checks import BACChecks
        
        checks = BACChecks()
        findings = checks.run_all(
            target="https://api.example.com",
            credentials=creds  # from CredentialStore
        )
    """
    
    def __init__(self):
        self.all_tests = P0_TESTS + P1_TESTS + P2_TESTS
    
    def get_tests_by_priority(self, priority: str) -> list[dict]:
        """Get tests by priority: 'P0', 'P1', 'P2', or 'all'.
        
        Tests are indexed: P0=tests[0:4], P1=tests[4:10], P2=tests[10:].
        """
        priority = priority.upper()
        if priority == "ALL":
            return self.all_tests
        elif priority == "P0":
            return self.all_tests[0:4]
        elif priority == "P1":
            return self.all_tests[4:10]
        elif priority == "P2":
            return self.all_tests[10:]
        return []
    
    def get_tests_by_category(self, category: str) -> list[dict]:
        """Get tests by category: 'idor', 'escalation', 'auth_bypass', or 'all'."""
        if category.lower() == "all":
            return self.all_tests
        return [t for t in self.all_tests if t["category"] == category]
    
    def build_test_matrix(self, target_base: str) -> list[BACFinding]:
        """Generate the full test matrix with target URLs populated."""
        findings = []
        for test in self.all_tests:
            endpoint = test["endpoint"].replace("v*", "v2")
            full_url = f"{target_base.rstrip('/')}{endpoint}" if endpoint.startswith("/") else f"{target_base}/{endpoint}"
            
            severity = Severity.CRITICAL
            if test in P1_TESTS:
                severity = Severity.HIGH
            elif test in P2_TESTS:
                severity = Severity.MEDIUM
            
            finding = BACFinding(
                category=test["category"],
                test_name=test["test_name"],
                endpoint=full_url,
                method=test["method"],
                severity=severity,
                description=test["description"],
                expected=test["expected"],
                poc="\n".join(test["poc_steps"]),
                references=test["refs"]
            )
            findings.append(finding)
        
        return findings
    
    def format_findings(self, findings: list[BACFinding]) -> str:
        """Format findings as markdown report."""
        lines = [
            "# BAC Test Results\n",
            "| # | Category | Test | Severity | Status |",
            "|---|----------|------|----------|--------|"
        ]
        for i, f in enumerate(findings, 1):
            status = "✅ Resolved" if f.resolved else "❌ Open"
            lines.append(f"| {i} | {f.category} | {f.test_name} | {f.severity.value} | {status} |")
        return "\n".join(lines)
    
    def format_detailed_report(self, findings: list[BACFinding]) -> str:
        """Format as detailed findings report."""
        lines = ["# Detailed BAC Findings\n"]
        for f in findings:
            lines.extend([
                f"## {f.test_name}",
                f"**Severity:** {f.severity.value.upper()}",
                f"**Category:** {f.category}",
                f"**Endpoint:** `{f.method} {f.endpoint}`",
                f"**Expected:** {f.expected}",
                f"**Actual:** {f.actual or 'Not tested'}",
                f"**Description:** {f.description}",
                f"**PoC Steps:**\n{f.poc}",
                f"**References:** {', '.join(f.references)}",
                f"**Status:** {'✅ Resolved' if f.resolved else '❌ Open'}",
                f"**Notes:** {f.notes or 'None'}",
                ""
            ])
        return "\n".join(lines)
