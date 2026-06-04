## 2024-11-20 - [IP Spoofing Vulnerability]
**Vulnerability:** The `psc_get_client_ip` function was trusting `HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR` headers to determine the client's IP.
**Learning:** These headers can be spoofed by an attacker, allowing them to bypass IP blocks or block legitimate admins via denial of service.
**Prevention:** Unless configured properly behind a trusted reverse proxy, use `$_SERVER['REMOTE_ADDR']` exclusively to get the real client IP.
