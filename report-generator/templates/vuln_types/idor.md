### IDOR Template
- Identify object reference pattern (numeric ID, UUID, predictable token).
- Show unauthorized read/update/delete across account boundaries.
- Include at least one low-privileged -> high-privileged access example.

Checklist:
- Missing ownership check
- Missing authorization middleware
- Insecure direct reference in endpoint or GraphQL resolver
