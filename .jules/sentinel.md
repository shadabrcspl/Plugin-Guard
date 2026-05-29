## 2024-05-29 - [Fix IP Spoofing Vulnerability]
**Vulnerability:** Client IP retrieved from HTTP_CLIENT_IP or HTTP_X_FORWARDED_FOR.
**Learning:** These headers can be easily spoofed by attackers to bypass IP-based blocking and rate-limiting measures.
**Prevention:** Always use $_SERVER['REMOTE_ADDR'] exclusively to determine the client IP address in the plugin, unless explicitly configured for a trusted reverse proxy.
