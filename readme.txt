===Plugin Guard===
Contributors: shadabcse2020
Tags: security, admin, plugins management, email notifications
Short Description: A powerful plugin that ensures only authorized plugins are active on your WordPress site, preventing unauthorized access and enhancing security.
Requires at least: 5.0
Tested up to: 6.6
Stable tag: 1.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
== Description ==
Plugin Guard is an essential security tool for WordPress administrators who want to ensure the integrity of their website. This plugin actively monitors the installation of new plugins and prevents unauthorized plugins from being activated without administrative approval. 

### Key Features
- Automatic Deactivation of Unauthorized Plugins**: If a new plugin is installed that is not on your approved list, the plugin will automatically deactivate it to protect your site.
  
- Pending Approval System: Any new plugins that require approval will be sent to a pending status. Administrators will receive an email notification detailing the newly installed plugin, including its name and description.
  
- Email Notifications: Administrators will receive an email whenever a new plugin is installed, allowing for quick responses and decisions on whether to approve or not the plugin.
  
- Easy Approval Process: Administrators can easily approve plugins through the WordPress dashboard, allowing for safe and controlled plugin management.

- User-Friendly Interface: The plugin integrates seamlessly into the WordPress admin area, providing an intuitive interface for managing pending plugin approvals.

### Installation
1. Upload the plugin files to the `/wp-content/plugins/plugin-security-check` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Configure the settings as needed by navigating to **Settings > Plugin Security Check** in the WordPress dashboard.

### How It Works
Upon activation, the plugin stores the currently active plugins in the WordPress options table. Any new plugin installed will trigger an email notification to the admin. The admin can review the details of the new plugin in the "Pending Plugin Approvals" section of the dashboard. The admin must approve the plugin for it to be activated; otherwise, it remains deactivated.

### Frequently Asked Questions
= How does the plugin handle unauthorized plugins? =
The plugin will deactivate any newly installed plugin that is not in the allowed list and notify the admin via email.

= Can I customize the list of allowed plugins? =
No, you can't modify the allowed plugins list directly in the plugin's settings.

= What happens if I want to use a new plugin? =
Simply install the plugin, and it will be sent to the admin for approval. Once you approved from dashboard, It will be activated.

= Where can I find more support? =
You can find additional support on the [WordPress Support Forum](https://wordpress.org/support/plugin/plugin-security-check).

== Changelog ==

= 1.1 =
* Fixed issue where the plugin was requiring its own approval.
* Excluded "Security Check" from deactivation and pending approval logic.
* Updated version in code to reflect the latest improvements.

= 1.0 =
* Initial release of Security Check.
* Automatically deactivates unauthorized plugins.
* Sends an email notification to admin for plugin approval.
