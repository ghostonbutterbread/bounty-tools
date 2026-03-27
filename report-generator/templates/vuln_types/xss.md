### XSS Template
- Confirm whether payload executes in reflected, stored, or DOM context.
- Identify impacted users (self, privileged users, all visitors).
- Demonstrate data exfiltration/session impact where safe.

Example payload:
```html
<script>alert(document.domain)</script>
```
