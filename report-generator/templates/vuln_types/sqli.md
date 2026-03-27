### SQL Injection Template
- State injection point (query/body/header/path).
- Mention DB behavior evidence (error-based, boolean-based, time-based).
- Confirm whether data extraction or privilege escalation is feasible.

Example test payloads:
- `' OR '1'='1`
- `1 AND SLEEP(5)`
