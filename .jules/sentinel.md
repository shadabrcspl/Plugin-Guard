## 2024-06-01 - [CRITICAL] Prevent IP Spoofing in Client IP Detection
**Vulnerability:** The plugin's `psc_get_client_ip()` function trusted user-controllable HTTP headers (`HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR`) before falling back to `REMOTE_ADDR`.
**Learning:** Malicious actors could easily spoof these headers to bypass IP blocking features and obscure their true IP addresses. Since this application isn't strictly configured for a specific trusted proxy environment, trusting these headers creates a serious spoofing risk.
**Prevention:** Exclusively rely on `$_SERVER['REMOTE_ADDR']` to obtain the client IP, as it represents the true IP connection hitting the server and cannot be easily spoofed. Do not trust arbitrary headers for any critical security mechanisms.
