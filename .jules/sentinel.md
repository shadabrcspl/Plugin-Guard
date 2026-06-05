## 2024-06-05 - IP Spoofing via HTTP Headers
**Vulnerability:** The `psc_get_client_ip` function prioritized checking `HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR` headers before checking `REMOTE_ADDR` to determine the user's IP.
**Learning:** These headers are client-controlled and can easily be spoofed by attackers to bypass IP blocking features or impersonate other users. Unless specifically configured behind a trusted reverse proxy, these headers should not be relied upon for security purposes like IP bans.
**Prevention:** Always use `$_SERVER['REMOTE_ADDR']` for security-sensitive IP checks unless the application is verified to be behind a trusted proxy and proxy headers are properly validated.
