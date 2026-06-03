## 2024-06-03 - [IP Spoofing via HTTP Headers]
**Vulnerability:** The application was using HTTP headers (`HTTP_CLIENT_IP`, `HTTP_X_FORWARDED_FOR`) to get the client IP for security features (e.g., IP blocking).
**Learning:** These HTTP headers can be easily spoofed by attackers, allowing them to bypass IP blocks or pretend to be coming from an allowed IP address. `$_SERVER['REMOTE_ADDR']` is the only reliable way to get the real source IP address, unless the application is explicitly running behind a trusted reverse proxy configuration.
**Prevention:** For any security checks (like IP blocking or rate limiting), only use `$_SERVER['REMOTE_ADDR']`. Only trust proxy headers if there is explicit configuration and verification of trusted proxies.
