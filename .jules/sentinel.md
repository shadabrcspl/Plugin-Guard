## 2024-05-18 - [IP Spoofing Vulnerability]
**Vulnerability:** The application was vulnerable to IP spoofing because the `psc_get_client_ip()` function trusted user-controlled HTTP headers (`HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR`) before relying on `$_SERVER['REMOTE_ADDR']`.
**Learning:** Attackers can easily forge HTTP headers. If an IP blocking mechanism relies on these headers, an attacker can bypass the block by supplying a fake IP address in the header.
**Prevention:** Always use `$_SERVER['REMOTE_ADDR']` for IP-based security checks and blocking, as it accurately reflects the actual network connection IP. Only trust forwarded headers if the application is definitively running behind a trusted reverse proxy that strips and securely sets these headers.
