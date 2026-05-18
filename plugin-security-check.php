<?php
/**
 * Plugin Name: Security Check
 * Plugin URI: https://codxpert.com/security-check/
 * Description: Security Check is an essential security tool for WordPress administrators who want to ensure the integrity of their website. This plugin actively monitors the installation of new plugins and prevents unauthorized plugins from being activated without administrative approval.
 * Version: 1.2
 * Author: Shadab alam
 * Author URI: https://codxpert.com
 * License: GPL2
 */

// Store initial active plugins on activation
function store_initial_active_plugins() {
    $active_plugins = get_option('active_plugins');
    if (!is_array($active_plugins)) {
        $active_plugins = array();
    }

    $plugin_file = plugin_basename(__FILE__);
    if (!in_array($plugin_file, $active_plugins)) {
        $active_plugins[] = $plugin_file;
    }

    $allowed_plugins = get_option('allowed_plugins');
    if (!$allowed_plugins) {
        update_option('allowed_plugins', $active_plugins);
    } else {
        if (!in_array($plugin_file, $allowed_plugins)) {
            $allowed_plugins[] = $plugin_file;
            update_option('allowed_plugins', $allowed_plugins);
        }
    }
}
register_activation_hook(__FILE__, 'store_initial_active_plugins');

// Function to check for unauthorized plugins
function check_for_unauthorized_plugins() {
    $allowed_plugins = get_option('allowed_plugins', array());
    $active_plugins = get_option('active_plugins');

    // Find any plugins that are not in the allowed list
    $new_plugins = array_diff($active_plugins, $allowed_plugins);

    if (!empty($new_plugins)) {
        // Deactivate the unauthorized plugins
        foreach ($new_plugins as $plugin) {
            // Skip deactivation for the Plugin Security Check itself
            if ($plugin === plugin_basename(__FILE__)) {
                continue;
            }
            deactivate_plugins($plugin);
        }

        // Store the new plugins pending approval, excluding this plugin
        $pending_approval_plugins = get_option('pending_approval_plugins', array());
        $pending_approval_plugins = array_merge($pending_approval_plugins, array_diff($new_plugins, array(plugin_basename(__FILE__))));
        update_option('pending_approval_plugins', $pending_approval_plugins);

        // Send email to admin for approval
        send_plugin_approval_email($new_plugins);
    }
}
add_action('admin_init', 'check_for_unauthorized_plugins');

// Prevent plugin activation without approval
function prevent_activation_without_approval($plugin) {
    $allowed_plugins = get_option('allowed_plugins', array());
    $pending_approval_plugins = get_option('pending_approval_plugins', array());

    // Check if the plugin is the Plugin Security Check itself
    if ($plugin === plugin_basename(__FILE__)) {
        return; // Skip validation for this plugin
    }

    // If the plugin is not allowed or pending approval, deactivate it
    if (!in_array($plugin, $allowed_plugins) && in_array($plugin, $pending_approval_plugins)) {
        deactivate_plugins($plugin);
        wp_die('This plugin needs to be approved by the admin before activation.');
    }
}
add_action('activate_plugin', 'prevent_activation_without_approval');

// Disable the activate button for plugins not approved
function disable_activate_button($actions, $plugin_file, $plugin_data, $context) {
    $allowed_plugins = get_option('allowed_plugins', array());
    $pending_approval_plugins = get_option('pending_approval_plugins', array());

    // If the plugin is not allowed or pending approval, disable the activate button
    if (!in_array($plugin_file, $allowed_plugins) && in_array($plugin_file, $pending_approval_plugins)) {
        if (isset($actions['activate'])) {
            $actions['activate'] = '<span style="color: red;">Pending Admin Approval</span>';
        }
    }

    return $actions;
}
add_filter('plugin_action_links', 'disable_activate_button', 10, 4);

// Function to send email to admin for approval
function send_plugin_approval_email($new_plugins) {
    $admin_email = get_option('admin_email');
    $subject = 'New Plugin Installation Request';

    // Retrieve the list of plugins that have already been notified
    $notified_plugins = get_option('notified_plugins', array());

    // Prepare the message to include only plugins that have not been notified yet
    $message = "The following new plugins were installed and need approval:\n\n";
    $plugins_to_notify = array();

    foreach ($new_plugins as $plugin) {
        // Skip sending email for the Plugin Security Check itself
        if ($plugin === plugin_basename(__FILE__)) {
            continue;
        }

        // Only add plugins that haven't been notified yet
        if (!in_array($plugin, $notified_plugins)) {
            $message .= "- $plugin\n";
            $plugins_to_notify[] = $plugin; // Collect plugins to notify
        }
    }

    // If there are plugins to notify, send the email
    if (!empty($plugins_to_notify)) {
        $message .= "\nPlease review and approve them by visiting the admin panel.";

        // Email the admin
        $sent = wp_mail($admin_email, $subject, $message);

        if ($sent) {
            // If the email is successfully sent, update the list of notified plugins
            $notified_plugins = array_merge($notified_plugins, $plugins_to_notify);
            update_option('notified_plugins', $notified_plugins);
            error_log("Email sent successfully to admin.");
        } else {
            error_log("Email to admin not sent. Please check mail server configuration.");
        }
    } else {
        error_log("No new plugins to notify.");
    }
}

// Admin interface for plugin approvals
function plugin_approval_menu() {
    add_menu_page(
        'Plugin Approvals',         // Page title
        'Plugin Approvals',         // Menu title
        'manage_options',           // Capability
        'plugin-approvals',         // Menu slug
        'plugin_approval_page'      // Callback function
    );
}
add_action('admin_menu', 'plugin_approval_menu');

// Callback for plugin approval admin page
function plugin_approval_page() {
    // Tab navigation
    $active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'approvals';

    echo '<div class="wrap">';
    echo '<h1>Plugin Security Check Settings</h1>';
    echo '<h2 class="nav-tab-wrapper">';
    echo '<a href="?page=plugin-approvals&tab=approvals" class="nav-tab ' . ($active_tab == 'approvals' ? 'nav-tab-active' : '') . '">Plugin Approvals</a>';
    echo '<a href="?page=plugin-approvals&tab=security" class="nav-tab ' . ($active_tab == 'security' ? 'nav-tab-active' : '') . '">Security Settings</a>';
    echo '</h2>';

    if ($active_tab == 'approvals') {
    // Handle plugin approval
    if (isset($_POST['approve_plugin'])) {
        $plugin_slug = sanitize_text_field($_POST['plugin_slug']);
        approve_plugin($plugin_slug);
        echo '<div class="updated"><p>Plugin approved and activated!</p></div>';
    }

    // Handle plugin rejection
    if (isset($_POST['reject_plugin'])) {
        $plugin_slug = sanitize_text_field($_POST['plugin_slug']);
        reject_plugin($plugin_slug);
        echo '<div class="updated"><p>Plugin rejected and deleted!</p></div>';
    }

    // Handle clearing all pending approval plugins
    if (isset($_POST['clear_pending_plugins'])) {
        clear_pending_plugins();
        echo '<div class="updated"><p>All pending approval plugins have been removed!</p></div>';
    }


    // Retrieve the list of pending plugins
    $pending_approval_plugins = get_option('pending_approval_plugins', array());

    echo '<h2>Pending Plugin Approvals</h2>';

    // If there are any plugins pending approval, list them
    if (!empty($pending_approval_plugins)) {
        echo '<ul>';
        foreach ($pending_approval_plugins as $plugin) {
            echo '<li>';
            echo esc_html($plugin);

            // Approval and rejection forms
            echo ' <form method="post" action="" style="display:inline;">';
            echo '<input type="hidden" name="plugin_slug" value="' . esc_attr($plugin) . '">';
            echo '<input type="submit" name="approve_plugin" value="Approve" style="margin-right:10px;">';
            echo '</form>';

            echo ' <form method="post" action="" style="display:inline;">';
            echo '<input type="hidden" name="plugin_slug" value="' . esc_attr($plugin) . '">';
            echo '<input type="submit" name="reject_plugin" value="Reject">';
            echo '</form>';
            echo '</li>';
        }
        echo '</ul>';
    } else {
        echo '<p>No new plugins to approve or reject.</p>';
    }

    // Clear all pending plugins form
    echo '<form method="post" action="" style="margin-top: 20px;">';
    echo '<input type="submit" name="clear_pending_plugins" value="Clear All Pending Plugins" class="button-primary">';
    echo '</form>';

    } elseif ($active_tab == 'security') {
        // Handle saving security settings
        if (isset($_POST['save_security_settings'])) {
            update_option('psc_disable_xmlrpc', isset($_POST['psc_disable_xmlrpc']) ? 'yes' : 'no');
            update_option('psc_prevent_enumeration', isset($_POST['psc_prevent_enumeration']) ? 'yes' : 'no');
            update_option('psc_disable_directory_browsing', isset($_POST['psc_disable_directory_browsing']) ? 'yes' : 'no');
            update_option('psc_protect_wpconfig', isset($_POST['psc_protect_wpconfig']) ? 'yes' : 'no');
            update_option('psc_disable_app_passwords', isset($_POST['psc_disable_app_passwords']) ? 'yes' : 'no');
            update_option('psc_restrict_rest_api', isset($_POST['psc_restrict_rest_api']) ? 'yes' : 'no');

            // Update root .htaccess based on new settings
            psc_update_root_htaccess();

            // Handle toggling PHP execution in uploads directory
            $upload_dir = wp_upload_dir();
            $htaccess_file = $upload_dir['basedir'] . '/.htaccess';
            if (isset($_POST['psc_secure_uploads'])) {
                secure_uploads_directory();
            } else {
                remove_secure_uploads_directory();
            }

            echo '<div class="updated"><p>Security settings saved.</p></div>';
        }

        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';
        $is_uploads_secure = file_exists($htaccess_file) && strpos(file_get_contents($htaccess_file), '<Files *.php>') !== false;

        echo '<form method="post" action="">';
        echo '<table class="form-table">';
        echo '<tr><th scope="row">Secure Uploads Directory</th>';
        echo '<td><label><input type="checkbox" name="psc_secure_uploads" value="1" ' . checked($is_uploads_secure, true, false) . '> Disable PHP execution in the uploads directory</label></td></tr>';

        echo '<tr><th scope="row">Disable XML-RPC</th>';
        echo '<td><label><input type="checkbox" name="psc_disable_xmlrpc" value="1" ' . checked(get_option('psc_disable_xmlrpc', 'no'), 'yes', false) . '> Disable XML-RPC to prevent pingback and brute-force attacks</label></td></tr>';

        echo '<tr><th scope="row">Prevent User Enumeration</th>';
        echo '<td><label><input type="checkbox" name="psc_prevent_enumeration" value="1" ' . checked(get_option('psc_prevent_enumeration', 'no'), 'yes', false) . '> Block author scans and REST API user endpoint access</label></td></tr>';

        echo '<tr><th scope="row">Disable Directory Browsing</th>';
        echo '<td><label><input type="checkbox" name="psc_disable_directory_browsing" value="1" ' . checked(get_option('psc_disable_directory_browsing', 'no'), 'yes', false) . '> Prevent attackers from seeing a list of files in directories without an index file</label></td></tr>';

        echo '<tr><th scope="row">Protect wp-config.php</th>';
        echo '<td><label><input type="checkbox" name="psc_protect_wpconfig" value="1" ' . checked(get_option('psc_protect_wpconfig', 'no'), 'yes', false) . '> Block web access to wp-config.php</label></td></tr>';

        echo '<tr><th scope="row">Disable Application Passwords</th>';
        echo '<td><label><input type="checkbox" name="psc_disable_app_passwords" value="1" ' . checked(get_option('psc_disable_app_passwords', 'no'), 'yes', false) . '> Disable Application Passwords for REST API authentication</label></td></tr>';

        echo '<tr><th scope="row">Restrict REST API</th>';
        echo '<td><label><input type="checkbox" name="psc_restrict_rest_api" value="1" ' . checked(get_option('psc_restrict_rest_api', 'no'), 'yes', false) . '> Restrict the entire REST API to logged-in users only</label></td></tr>';

        echo '</table>';
        echo '<p class="submit"><input type="submit" name="save_security_settings" class="button button-primary" value="Save Settings"></p>';
        echo '</form>';
    }
    echo '</div>'; // Close .wrap
}

// Approve plugin function
function approve_plugin($plugin_slug) {
    $allowed_plugins = get_option('allowed_plugins', array());

    // Add the plugin to the allowed list and update the option
    $allowed_plugins[] = $plugin_slug;
    update_option('allowed_plugins', $allowed_plugins);

    // Reactivate the approved plugin
    activate_plugin($plugin_slug);

    // Remove from pending approval list
    $pending_approval_plugins = get_option('pending_approval_plugins', array());
    if (($key = array_search($plugin_slug, $pending_approval_plugins)) !== false) {
        unset($pending_approval_plugins[$key]);
        update_option('pending_approval_plugins', $pending_approval_plugins);
    }
}

// Reject plugin function
function reject_plugin($plugin_slug) {
    // Remove the plugin from the pending approval list
    $pending_approval_plugins = get_option('pending_approval_plugins', array());
    if (($key = array_search($plugin_slug, $pending_approval_plugins)) !== false) {
        unset($pending_approval_plugins[$key]);
        update_option('pending_approval_plugins', $pending_approval_plugins);
    }

    // Deactivate the plugin permanently
    deactivate_plugins($plugin_slug);

    // Delete the plugin files
    if (file_exists(WP_PLUGIN_DIR . '/' . $plugin_slug)) {
        delete_plugins(array($plugin_slug));
        error_log("Plugin $plugin_slug has been deleted.");
    } else {
        error_log("Plugin $plugin_slug could not be found for deletion.");
    }
}

// Function to clear all pending approval plugins
function clear_pending_plugins() {
    $pending_approval_plugins = get_option('pending_approval_plugins', array());
    if(!empty($pending_approval_plugins)) {
        foreach($pending_approval_plugins as $plugin_slug) {
            deactivate_plugins($plugin_slug);
            delete_plugins(array($plugin_slug));
        }
    }
    // Remove the pending approval plugins option from the database
    delete_option('pending_approval_plugins');
}

// Disable daily plugin check
// No cron job scheduling for daily checks
// if (!wp_next_scheduled('daily_plugin_check_event')) {
//    wp_schedule_event(time(), 'daily', 'daily_plugin_check_event');
// }
// add_action('daily_plugin_check_event', 'check_for_unauthorized_plugins');

// Prevent unauthorized user creation
function prevent_unauthorized_user_creation($user_id) {
    if (!current_user_can('create_users') && !get_option('users_can_register')) {
        require_once(ABSPATH . 'wp-admin/includes/user.php');
        wp_delete_user($user_id);
        error_log("Unauthorized user creation blocked and user deleted: ID $user_id");
    }
}
add_action('user_register', 'prevent_unauthorized_user_creation');

// Prevent unauthorized plugin installation
function prevent_unauthorized_plugin_installation($response, $hook_extra) {
    if (isset($hook_extra['type']) && $hook_extra['type'] === 'plugin' && $hook_extra['action'] === 'install') {
        if (!current_user_can('install_plugins')) {
            error_log("Unauthorized plugin installation attempt blocked.");
            return new WP_Error('unauthorized_install', 'You are not authorized to install plugins.');
        }
    }
    return $response;
}
add_filter('upgrader_pre_install', 'prevent_unauthorized_plugin_installation', 10, 2);

// Disable Theme and Plugin Editor
if (!defined('DISALLOW_FILE_EDIT')) {
    define('DISALLOW_FILE_EDIT', true);
}

// Disable PHP execution in the uploads directory
function secure_uploads_directory() {
    $upload_dir = wp_upload_dir();
    $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

    $rules = "<Files *.php>\nDeny from all\n</Files>";

    if (!file_exists($htaccess_file)) {
        file_put_contents($htaccess_file, $rules);
    } else {
        $content = file_get_contents($htaccess_file);
        if (strpos($content, '<Files *.php>') === false) {
            file_put_contents($htaccess_file, $rules . "\n" . $content);
        }
    }
}
register_activation_hook(__FILE__, 'secure_uploads_directory');

// Revert PHP execution disabling in the uploads directory on deactivation
function remove_secure_uploads_directory() {
    $upload_dir = wp_upload_dir();
    $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

    if (file_exists($htaccess_file)) {
        $content = file_get_contents($htaccess_file);
        $rules = "<Files *.php>\nDeny from all\n</Files>\n";
        $new_content = str_replace($rules, '', $content);

        // Also check if it was added without a trailing newline
        $rules_no_newline = "<Files *.php>\nDeny from all\n</Files>";
        $new_content = str_replace($rules_no_newline, '', $new_content);

        // If the file is now empty or just whitespace, delete it
        if (trim($new_content) === '') {
            unlink($htaccess_file);
        } else {
            file_put_contents($htaccess_file, $new_content);
        }
    }
}
register_deactivation_hook(__FILE__, 'remove_secure_uploads_directory');

// Disable XML-RPC
if (get_option('psc_disable_xmlrpc', 'no') === 'yes') {
    add_filter('xmlrpc_enabled', '__return_false');
}

// Prevent User Enumeration
if (get_option('psc_prevent_enumeration', 'no') === 'yes') {
    if (!is_admin()) {
        if (isset($_SERVER['QUERY_STRING']) && preg_match('/author=([0-9]*)/i', $_SERVER['QUERY_STRING'])) {
            add_action('template_redirect', 'psc_block_user_enumeration');
        }
    }
    // Block REST API user enumeration
    add_filter('rest_endpoints', 'psc_block_rest_user_enumeration');
}

function psc_block_user_enumeration() {
    if (is_author()) {
        wp_redirect(home_url(), 301);
        die();
    }
}

function psc_block_rest_user_enumeration($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    }
    return $endpoints;
}

// Write .htaccess rules for Directory Browsing and wp-config.php protection
function psc_update_root_htaccess() {
    // Only attempt if we can find the home path and insert_with_markers is available
    if (function_exists('get_home_path') && function_exists('insert_with_markers')) {
        $home_path = get_home_path();
        $htaccess_file = $home_path . '.htaccess';
        $rules = array();

        if (get_option('psc_disable_directory_browsing', 'no') === 'yes') {
            $rules[] = 'Options -Indexes';
        }

        if (get_option('psc_protect_wpconfig', 'no') === 'yes') {
            $rules[] = '<Files wp-config.php>';
            $rules[] = 'order allow,deny';
            $rules[] = 'deny from all';
            $rules[] = '</Files>';
        }

        // Insert or remove the rules based on the options
        if (!empty($rules)) {
            insert_with_markers($htaccess_file, 'Plugin Security Check', $rules);
        } else {
            // Remove the markers completely if both are disabled
            insert_with_markers($htaccess_file, 'Plugin Security Check', array());
        }
    }
}
// Hook into plugin activation and deactivation to apply/remove these rules safely
register_activation_hook(__FILE__, 'psc_update_root_htaccess');

function psc_remove_root_htaccess_rules() {
    if (function_exists('get_home_path') && function_exists('insert_with_markers')) {
        $home_path = get_home_path();
        $htaccess_file = $home_path . '.htaccess';
        insert_with_markers($htaccess_file, 'Plugin Security Check', array());
    }
}
register_deactivation_hook(__FILE__, 'psc_remove_root_htaccess_rules');

// Disable Application Passwords
if (get_option('psc_disable_app_passwords', 'no') === 'yes') {
    add_filter('wp_is_application_passwords_available', '__return_false');
}

// Restrict REST API to Authenticated Users Only
if (get_option('psc_restrict_rest_api', 'no') === 'yes') {
    add_filter('rest_authentication_errors', 'psc_restrict_rest_api_to_authenticated_users');
}

function psc_restrict_rest_api_to_authenticated_users($result) {
    if (!empty($result)) {
        return $result;
    }
    if (!is_user_logged_in()) {
        return new WP_Error('rest_not_logged_in', 'You are not currently logged in. The REST API is restricted to authenticated users.', array('status' => 401));
    }
    return $result;
}
