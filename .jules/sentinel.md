## 2024-05-28 - IP Spoofing via Unsafe Headers
**Vulnerability:** The `psc_get_client_ip` function was trusting the `HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR` headers to determine the client's IP address.
**Learning:** These headers can be trivially spoofed by an attacker, allowing them to bypass IP-based blocking and rate-limiting protections.
**Prevention:** Only trust `$_SERVER['REMOTE_ADDR']` for client IP identification, as it is determined by the underlying TCP connection and cannot be spoofed in the same manner.
