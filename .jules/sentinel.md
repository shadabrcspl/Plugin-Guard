## 2025-02-28 - [IP Spoofing Vulnerability]
**Vulnerability:** The `psc_get_client_ip()` function trusted user-controllable HTTP headers (`HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR`) to determine the client's IP address.
**Learning:** This allowed attackers to easily spoof their IP address, potentially bypassing IP-based blocking systems or maliciously causing other users' IPs to be blocked.
**Prevention:** Always rely exclusively on `$_SERVER['REMOTE_ADDR']` to determine the client IP address, unless explicitly configured to trust a reverse proxy.
