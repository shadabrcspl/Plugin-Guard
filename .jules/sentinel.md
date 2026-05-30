## 2026-05-30 - [IP Spoofing Vulnerability]
**Vulnerability:** The function `psc_get_client_ip()` trusted user-manipulatable headers like `HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR` before falling back to `REMOTE_ADDR`.
**Learning:** These headers can be easily spoofed by attackers to bypass IP-based bans and rate limiting, rendering the IP blocking system ineffective.
**Prevention:** Exclusively use `$_SERVER['REMOTE_ADDR']` to reliably identify the true client IP address, avoiding reliance on easily manipulated headers.
