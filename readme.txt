=== Plugin Security Check ===
Contributors: shadabrcspl
Tags: security, malware scanner, firewall, login protection, hardening
Requires at least: 5.0
Tested up to: 6.4
Requires PHP: 7.2
Stable tag: 1.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

An essential, all-in-one security suite to protect your WordPress installation from unauthorized plugins, malware, brute force attacks, and core file modifications.

== Description ==

Plugin Security Check (Plugin Guard) is an advanced security tool designed to give WordPress administrators complete control over their site's integrity. It actively monitors for hacks, blocks unauthorized actions, and provides a powerful suite of hardening tools to keep your site safe.

= Key Features =

*   **Unauthorized Plugin Protection:** Automatically blocks any unapproved plugins from being activated or installed. Requires an admin to manually review and approve new plugins.
*   **Core Integrity Scanner:** Scans your WordPress core files against the official WordPress.org checksums to detect malicious backdoors or modifications. Includes a one-click "Repair Core Files" feature to seamlessly reinstall a clean version of WordPress if compromised.
*   **Malware & DB Scanner:** Heuristically scans `wp-content` directories (plugins, themes, uploads) for suspicious PHP payloads (e.g., `eval`, `base64`). Scans your database for injected payloads and warns if your database prefix is vulnerable.
*   **Advanced Monitoring:** Automatically creates baselines of your plugin and theme directories. Warns you if files are modified outside of standard upgrades. Detects suspicious scheduled cron jobs.
*   **Rogue Admin Defense:** Maintains a secure list of known administrators. Automatically locks and demotes any unknown admin accounts created via exploits.
*   **Uploads Directory Protection:** Blocks PHP execution in the `wp-content/uploads/` directory to neutralize uploaded web shells. Automatically handles `.htaccess` generation (with NGINX instructions provided).
*   **WordPress Hardening:**
    *   Disable the built-in Theme and Plugin editors (`DISALLOW_FILE_EDIT`).
    *   Disable Plugin/Theme installations (`DISALLOW_FILE_MODS`).
    *   Hide the WordPress version number from page source and asset URLs.
    *   Disable Application Passwords.
    *   Disable XML-RPC to block brute-force and DDoS attacks.
    *   Restrict the entire REST API to authenticated users.
    *   Block User Enumeration via `?author=1` and REST API endpoints.
    *   Disable Directory Browsing.
    *   Protect `wp-config.php` from direct web access.
*   **Email Alerts:** Receive immediate notifications for new admin users, privilege escalations, theme changes, new plugin installations, and daily malware scan results.
*   **Live Testing Tool:** An integrated loopback testing tool allows you to manually verify that your security settings (like blocking `wp-config.php` or `xmlrpc.php`) are actively working on your live server.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/plugin-security-check` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to the new 'Plugin Approvals' menu in the WordPress admin dashboard to configure your security settings.

== Frequently Asked Questions ==

= I'm locked out or a plugin won't activate! =
Go to the "Plugin Approvals" tab in the admin menu. You will see a list of plugins pending approval. Click "Approve" to whitelist and activate them.

= My server runs NGINX. Will the Uploads protection work? =
NGINX ignores `.htaccess` files. The plugin will detect this and provide you with the exact NGINX configuration block you need to copy into your server's `nginx.conf` file to ensure protection.

= Does this slow down my website? =
No. The core protections rely on lightweight WordPress hooks and server-level rules (`.htaccess`). The heavier scans (Malware and Baseline checks) are scheduled efficiently via WP-Cron to run once daily in the background.

== Changelog ==

= 1.2 =
* Added Core Integrity Scanner and Repair tool.
* Added Database payload scanner.
* Added CSRF protection to all administrative actions.
* Added advanced monitoring for cron jobs and rogue admin accounts.
* Added live loopback testing tool.
* Refactored settings into a tabbed dashboard.

= 1.1 =
* Added `.htaccess` protections for uploads directory, directory browsing, and `wp-config.php`.
* Added options to disable XML-RPC, REST API, Application Passwords, and File Editors.
* Fixed self-identification bug preventing the plugin from activating.

= 1.0 =
* Initial release. Basic plugin approval queue.
