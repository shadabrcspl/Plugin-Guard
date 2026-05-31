## 2024-10-31 - [IP Spoofing Risk in Client IP Detection]
**Vulnerability:** The `psc_get_client_ip` function trusted `HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR` headers to determine the client's IP address.
**Learning:** This approach is vulnerable to IP spoofing because these headers can be easily manipulated by an attacker, allowing them to bypass IP blocks or rate limits.
**Prevention:** To avoid IP spoofing, rely exclusively on `$_SERVER['REMOTE_ADDR']` to identify the client's true IP address, unless the application is explicitly configured to trust specific, known reverse proxies.
