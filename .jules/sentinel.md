## 2024-05-19 - Client IP Spoofing Prevention
**Vulnerability:** Client IP spoofing in `psc_get_client_ip()`.
**Learning:** Checking headers like `HTTP_X_FORWARDED_FOR` or `HTTP_CLIENT_IP` for IP address can easily be spoofed by attackers to bypass IP blocklists or rate limiting.
**Prevention:** Use `$_SERVER['REMOTE_ADDR']` exclusively to prevent IP spoofing vulnerabilities unless explicitly configured for a trusted reverse proxy.
