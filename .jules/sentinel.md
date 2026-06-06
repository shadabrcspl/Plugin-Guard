## 2024-05-24 - [IP Spoofing Vulnerability in IP Blocking Mechanism]
**Vulnerability:** The `psc_get_client_ip()` function trusted user-supplied headers (`HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR`) before falling back to `REMOTE_ADDR`. This allowed attackers to bypass IP-based blocking by spoofing these headers.
**Learning:** Never trust client-provided HTTP headers for security-critical functionality like IP blocking or rate limiting, as they can be easily manipulated by attackers.
**Prevention:** Always use `$_SERVER['REMOTE_ADDR']` for determining the client's IP address unless explicitly configured to work behind a trusted reverse proxy (where only the specific proxy's headers should be trusted).
