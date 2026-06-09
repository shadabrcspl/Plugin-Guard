## 2024-06-09 - Client IP Spoofing Vulnerability
**Vulnerability:** The `psc_get_client_ip()` function trusted user-controllable headers (`HTTP_CLIENT_IP`, `HTTP_X_FORWARDED_FOR`) before falling back to `REMOTE_ADDR`. This allowed attackers to spoof their IP address to bypass rate limiting and IP blocking.
**Learning:** Never trust HTTP headers for security-critical operations like IP blocking or rate limiting, as they can easily be manipulated by the client.
**Prevention:** Exclusively use `$_SERVER['REMOTE_ADDR']` for determining client IP addresses in security checks. If behind a reverse proxy, configure the web server to correctly set `REMOTE_ADDR` from trusted headers.
