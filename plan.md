1. **Fix IP Spoofing Vulnerability**
   - In `plugin-security-check.php`, update the `psc_get_client_ip` function.
   - Remove the trust in `HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR` headers, which can be easily spoofed by attackers to bypass IP blocking or rate limiting.
   - Restrict it to only use `$_SERVER['REMOTE_ADDR']`.
2. **Update Sentinel Journal**
   - Add a critical learning about IP spoofing via `HTTP_X_FORWARDED_FOR` to `.jules/sentinel.md`.
3. **Run tests**
   - Ensure the PHPUnit tests pass.
4. **Pre-commit checks**
   - Follow instructions from `pre_commit_instructions` tool to verify the codebase.
5. **Submit PR**
   - Submit the change with Sentinel formatted PR.
