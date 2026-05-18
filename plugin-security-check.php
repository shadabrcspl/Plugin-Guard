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
    echo '<a href="?page=plugin-approvals&tab=scanner" class="nav-tab ' . ($active_tab == 'scanner' ? 'nav-tab-active' : '') . '">Malware & DB Scanner</a>';
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
            update_option('psc_disallow_file_mods', isset($_POST['psc_disallow_file_mods']) ? 'yes' : 'no');
            update_option('psc_hide_wp_version', isset($_POST['psc_hide_wp_version']) ? 'yes' : 'no');

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

        // Handle running manual security tests
        if (isset($_POST['run_security_tests'])) {
            echo '<h3>Security Test Results</h3>';
            echo '<div class="notice notice-info" style="padding: 10px;">';

            // Test 1: User Enumeration
            $response = wp_remote_get(home_url('/?author=1'), array('timeout' => 5));
            if (!is_wp_error($response)) {
                $code = wp_remote_retrieve_response_code($response);
                $status = ($code == 301 || $code == 302 || $code == 404 || $code == 403) ? '<span style="color:green">Protected</span>' : '<span style="color:red">Vulnerable</span>';
                echo "<p><strong>User Enumeration (?author=1):</strong> HTTP $code - $status</p>";
            } else {
                echo "<p><strong>User Enumeration (?author=1):</strong> HTTP Error - <span style=\"color:orange\">Test could not complete</span></p>";
            }

            // Test 2: REST API Users Endpoint
            $response = wp_remote_get(rest_url('wp/v2/users'), array('timeout' => 5));
            if (!is_wp_error($response)) {
                $code = wp_remote_retrieve_response_code($response);
                $status = ($code == 401 || $code == 404 || $code == 403) ? '<span style="color:green">Protected</span>' : '<span style="color:red">Vulnerable</span>';
                echo "<p><strong>REST API Users Endpoint:</strong> HTTP $code - $status</p>";
            } else {
                echo "<p><strong>REST API Users Endpoint:</strong> HTTP Error - <span style=\"color:orange\">Test could not complete</span></p>";
            }

            // Test 3: wp-config.php access
            $response = wp_remote_get(home_url('/wp-config.php'), array('timeout' => 5));
            if (!is_wp_error($response)) {
                $code = wp_remote_retrieve_response_code($response);
                $status = ($code == 403) ? '<span style="color:green">Protected (403 Forbidden)</span>' : '<span style="color:red">Vulnerable</span>';
                echo "<p><strong>wp-config.php direct access:</strong> HTTP $code - $status</p>";
                if ($code != 403 && get_option('psc_protect_wpconfig', 'no') === 'yes') {
                    echo "<p style=\"color:orange; margin-left: 20px; font-size: 12px;\"><em>Note: You enabled this setting, but the file is still accessible. If you are running NGINX, `.htaccess` files are ignored. You must manually add a rule to your nginx.conf to block access to wp-config.php.</em></p>";
                }
            } else {
                echo "<p><strong>wp-config.php direct access:</strong> HTTP Error - <span style=\"color:orange\">Test could not complete</span></p>";
            }

            // Test 4: XML-RPC
            $response = wp_remote_post(home_url('/xmlrpc.php'), array(
                'timeout' => 5,
                'body' => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
            ));
            if (!is_wp_error($response)) {
                $code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                $status = ($code == 403 || strpos($body, 'XML-RPC server accepts POST requests only') !== false || strpos($body, 'parse error') !== false) ? '<span style="color:green">Protected</span>' : '<span style="color:red">Vulnerable</span>';
                echo "<p><strong>XML-RPC access:</strong> HTTP $code - $status</p>";
            } else {
                echo "<p><strong>XML-RPC access:</strong> HTTP Error - <span style=\"color:orange\">Test could not complete</span></p>";
            }

            // Test 5: Uploads PHP Execution
            $upload_dir = wp_upload_dir();
            $test_file_path = $upload_dir['basedir'] . '/test-execution.php';
            $test_file_url = (isset($upload_dir['baseurl']) ? $upload_dir['baseurl'] : '') . '/test-execution.php';
            file_put_contents($test_file_path, '<?php echo "executed"; ?>');

            $response = wp_remote_get($test_file_url, array('timeout' => 5));
            if (!is_wp_error($response)) {
                $code = wp_remote_retrieve_response_code($response);
                $body = wp_remote_retrieve_body($response);
                $status = ($code == 403 || trim($body) !== 'executed') ? '<span style="color:green">Protected</span>' : '<span style="color:red">Vulnerable (File executed)</span>';
                echo "<p><strong>Uploads Directory PHP Execution:</strong> HTTP $code - $status</p>";
                $upload_dir_info = wp_upload_dir();
                $htaccess_exists = file_exists($upload_dir_info['basedir'] . '/.htaccess') && strpos(file_get_contents($upload_dir_info['basedir'] . '/.htaccess'), '<Files *.php>') !== false;
                if ($code != 403 && trim($body) === 'executed' && $htaccess_exists) {
                    echo "<p style=\"color:orange; margin-left: 20px; font-size: 12px;\"><em>Note: The security setting is enabled, but the file still executed. If you are running NGINX, `.htaccess` files are ignored. You must manually add a rule to your nginx.conf to disable PHP execution in wp-content/uploads/.</em></p>";
                }
            } else {
                echo "<p><strong>Uploads Directory PHP Execution:</strong> HTTP Error - <span style=\"color:orange\">Test could not complete</span></p>";
            }

            // Cleanup
            if (file_exists($test_file_path)) {
                unlink($test_file_path);
            }

            // Test 6: Disable Plugin/Theme Installation
            $file_mods_disabled = (defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS === true);
            $status = $file_mods_disabled ? '<span style="color:green">Protected (Disabled)</span>' : '<span style="color:red">Vulnerable (Enabled)</span>';
            echo "<p><strong>Plugin/Theme Installation:</strong> $status</p>";

            // Test 7: Hide WordPress Version
            $response = wp_remote_get(home_url('/'), array('timeout' => 5));
            if (!is_wp_error($response)) {
                $body = wp_remote_retrieve_body($response);
                $has_generator = (strpos($body, '<meta name="generator" content="WordPress') !== false);
                // A simplistic check to see if scripts/styles have the default WP version appended
                global $wp_version;
                $has_version_args = (strpos($body, '?ver=' . $wp_version) !== false);

                $status = (!$has_generator && !$has_version_args) ? '<span style="color:green">Protected (Hidden)</span>' : '<span style="color:red">Vulnerable (Visible)</span>';
                echo "<p><strong>WordPress Version Visibility:</strong> $status</p>";
            } else {
                echo "<p><strong>WordPress Version Visibility:</strong> HTTP Error - <span style=\"color:orange\">Test could not complete</span></p>";
            }

            echo '</div>';
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

        echo '<tr><th scope="row">Disable Plugin/Theme Installation</th>';
        echo '<td><label><input type="checkbox" name="psc_disallow_file_mods" value="1" ' . checked(get_option('psc_disallow_file_mods', 'no'), 'yes', false) . '> Define DISALLOW_FILE_MODS to prevent installing/updating plugins and themes</label></td></tr>';

        echo '<tr><th scope="row">Hide WordPress Version</th>';
        echo '<td><label><input type="checkbox" name="psc_hide_wp_version" value="1" ' . checked(get_option('psc_hide_wp_version', 'no'), 'yes', false) . '> Remove WP version from meta tags and script/style URLs</label></td></tr>';

        echo '</table>';
        echo '<p class="submit"><input type="submit" name="save_security_settings" class="button button-primary" value="Save Settings"></p>';
        echo '</form>';

        echo '<hr>';
        echo '<form method="post" action="">';
        echo '<p class="submit"><input type="submit" name="run_security_tests" class="button button-secondary" value="Run Manual Security Tests"></p>';
        echo '<p class="description">This will make loopback requests to your site to check if the protections are actively blocking access.</p>';
        echo '</form>';

        // NGINX Rules Section
        $is_nginx = (strpos($_SERVER['SERVER_SOFTWARE'] ?? '', 'nginx') !== false);
        if ($is_nginx || isset($_POST['show_nginx_rules'])) {
            echo '<hr>';
            echo '<h3>NGINX Server Configuration</h3>';
            echo '<p>It appears you are running NGINX (or requested NGINX rules). NGINX ignores `.htaccess` files. For the <strong>Secure Uploads Directory</strong> and <strong>Protect wp-config.php</strong> settings to work, you must manually add the following rules to your server configuration block (usually located in <code>/etc/nginx/sites-available/</code>) inside the <code>server { ... }</code> block:</p>';

            $nginx_rules = "# Plugin Security Check Rules\n";
            if (get_option('psc_protect_wpconfig', 'no') === 'yes') {
                $nginx_rules .= "location ~* wp-config.php {\n    deny all;\n}\n";
            }
            if ($is_uploads_secure) {
                $nginx_rules .= "location ~* /wp-content/uploads/.*\\.php$ {\n    deny all;\n}\n";
            }
            if (get_option('psc_disable_directory_browsing', 'no') === 'yes') {
                $nginx_rules .= "autoindex off;\n";
            }
            if (trim($nginx_rules) === "# Plugin Security Check Rules") {
                $nginx_rules .= "# Enable settings above to generate rules.\n";
            }

            echo '<textarea readonly style="width:100%; height:150px; font-family:monospace; background:#f0f0f1;">' . esc_textarea($nginx_rules) . '</textarea>';
            echo '<p class="description">After adding these rules, remember to reload NGINX (e.g., <code>sudo systemctl reload nginx</code>).</p>';
        } elseif (!$is_nginx) {
            echo '<hr>';
            echo '<form method="post" action="">';
            echo '<p class="submit"><input type="submit" name="show_nginx_rules" class="button button-secondary" value="Show NGINX Rules"></p>';
            echo '</form>';
        }
    } elseif ($active_tab == 'scanner') {
        echo '<h2>Malware & DB Scanner</h2>';
        echo '<p>This tool checks your WordPress core files against the official checksums from WordPress.org to detect malicious modifications.</p>';

        if (isset($_POST['run_core_scan']) && isset($_POST['psc_scanner_nonce']) && wp_verify_nonce($_POST['psc_scanner_nonce'], 'psc_run_scan')) {
            psc_run_core_checksum_scan();
            psc_run_malware_scan();
            psc_run_database_checks();
        }

        if (isset($_POST['repair_core']) && isset($_POST['psc_scanner_nonce']) && wp_verify_nonce($_POST['psc_scanner_nonce'], 'psc_repair_core')) {
            psc_repair_core_files();
        }

        echo '<form method="post" action="">';
        wp_nonce_field('psc_run_scan', 'psc_scanner_nonce');
        echo '<p><input type="submit" name="run_core_scan" class="button button-primary" value="Scan Core Files Now"></p>';
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

    $rules = "<Files *.php>\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n</Files>";

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
        $rules = "<Files *.php>\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n</Files>\n";
        $new_content = str_replace($rules, '', $content);

        // Also check if it was added without a trailing newline
        $rules_no_newline = "<Files *.php>\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n</Files>";
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
        add_action('template_redirect', 'psc_block_user_enumeration');
    }
    // Block REST API user enumeration
    add_filter('rest_endpoints', 'psc_block_rest_user_enumeration');
}

function psc_block_user_enumeration() {
    if (is_author() || (isset($_SERVER['QUERY_STRING']) && preg_match('/author=([0-9]*)/i', $_SERVER['QUERY_STRING']))) {
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
            $rules[] = '<IfModule mod_authz_core.c>';
            $rules[] = '    Require all denied';
            $rules[] = '</IfModule>';
            $rules[] = '<IfModule !mod_authz_core.c>';
            $rules[] = '    Order deny,allow';
            $rules[] = '    Deny from all';
            $rules[] = '</IfModule>';
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

// Run core checksum scan
function psc_run_core_checksum_scan() {
    global $wp_version;

    // Remove any development suffixes like -RC1 or -alpha
    $version = preg_replace('/-.*$/', '', $wp_version);
    if (empty($version)) {
        $version = get_bloginfo('version');
    }

    $locale = get_locale();

    // Fetch checksums from WP API
    $response = wp_remote_get("https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}");
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    // Fallback to en_US if local translation checksums are missing
    if (empty($data['checksums']) || empty($data['checksums'][$version])) {
        $response = wp_remote_get("https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale=en_US");
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
    }

    if (is_wp_error($response)) {
        echo '<div class="error"><p>Failed to connect to WordPress.org API to fetch checksums.</p></div>';
        return;
    }

    // If exact version fails, try to grab the latest minor release for that major version
    $checksums = array();
    if (!empty($data['checksums']) && is_array($data['checksums'])) {
        if (isset($data['checksums'][$version])) {
            $checksums = $data['checksums'][$version];
        } else {
            // Fallback: Just grab the first available version from the API response
            // Since we queried specifically for the version, if they return anything, it's the closest match.
            reset($data['checksums']);
            $closest_version = key($data['checksums']);
            if ($closest_version) {
                $checksums = $data['checksums'][$closest_version];
                echo '<div class="notice notice-warning"><p>Could not find exact checksums for ' . esc_html($version) . '. Falling back to ' . esc_html($closest_version) . '.</p></div>';
            }
        }
    }

    if (empty($checksums)) {
        echo '<div class="error"><p>Could not retrieve checksums for WordPress version ' . esc_html($version) . '. This can happen if you are running an unofficial or beta version of WordPress.</p></div>';
        return;
    }
    $modified_files = array();
    $missing_files = array();

    foreach ($checksums as $file => $expected_hash) {
        $local_file_path = ABSPATH . $file;

        // Skip wp-config-sample.php as it's often modified/deleted harmlessly
        if ($file === 'wp-config-sample.php') {
            continue;
        }

        if (!file_exists($local_file_path)) {
            $missing_files[] = $file;
        } else {
            $local_hash = md5_file($local_file_path);
            if ($local_hash !== $expected_hash) {
                $modified_files[] = $file;
            }
        }
    }

    echo '<div class="notice notice-info" style="padding:15px; margin-top:20px;">';
    echo '<h3>Scan Results for WordPress ' . esc_html($version) . '</h3>';

    $has_issues = false;

    if (!empty($modified_files)) {
        $has_issues = true;
        echo '<h4 style="color:red;">Modified Core Files:</h4><ul>';
        foreach ($modified_files as $file) {
            echo '<li><code>' . esc_html($file) . '</code></li>';
        }
        echo '</ul>';
    }

    if (!empty($missing_files)) {
        $has_issues = true;
        echo '<h4 style="color:orange;">Missing Core Files:</h4><ul>';
        foreach ($missing_files as $file) {
            echo '<li><code>' . esc_html($file) . '</code></li>';
        }
        echo '</ul>';
    }

    if (!$has_issues) {
        echo '<p style="color:green; font-weight:bold;">Success! All WordPress core files match the official repository. No modifications detected.</p>';
    } else {
        echo '<div style="background:#fcebea; border-left:4px solid #dc3232; padding:10px; margin-top:20px;">';
        echo '<p><strong>Warning:</strong> Core file modifications often indicate a hacked website. If you did not intentionally modify these files, you should repair your core files immediately.</p>';
        echo '<form method="post" action="" onsubmit="return confirm(\'Are you sure you want to reinstall WordPress core? This will overwrite any custom modifications you have made to core files.\');">';
        wp_nonce_field('psc_repair_core', 'psc_scanner_nonce');
        echo '<input type="submit" name="repair_core" class="button button-primary" style="background:#dc3232; border-color:#dc3232;" value="Repair Core Files Now">';
        echo '</form>';
        echo '</div>';
    }
    echo '</div>';
}

// Reinstall WordPress Core to fix modified/missing files
function psc_repair_core_files() {
    // Make sure we have the required files loaded for the Upgrader
    require_once(ABSPATH . 'wp-admin/includes/class-wp-upgrader.php');
    require_once(ABSPATH . 'wp-admin/includes/update.php');

    // Check if user has permission
    if (!current_user_can('update_core')) {
        echo '<div class="error"><p>You do not have sufficient permissions to update core files.</p></div>';
        return;
    }

    echo '<div class="updated" style="padding:15px; margin-top:20px;">';
    echo '<h3>Repairing Core Files...</h3>';

    // We need to flush the update cache to ensure we get a download link
    wp_version_check();

    $current = get_site_transient('update_core');
    if (!isset($current->updates) || !is_array($current->updates)) {
        echo '<p>Could not find WordPress updates. Please try again later.</p>';
        echo '</div>';
        return;
    }

    // Find the update object for the current version to reinstall
    $update = $current->updates[0];
    foreach ($current->updates as $offer) {
        if ($offer->response === 'reinstall') {
            $update = $offer;
            break;
        }
    }

    // Suppress normal upgrader output by using a quiet skin
    if (!class_exists('PSC_Quiet_Upgrader_Skin')) {
        class PSC_Quiet_Upgrader_Skin extends WP_Upgrader_Skin {
            public function feedback($string, ...$args) { /* Quiet */ }
            public function header() { /* Quiet */ }
            public function footer() { /* Quiet */ }
        }
    }

    $skin = new PSC_Quiet_Upgrader_Skin();
    $upgrader = new Core_Upgrader($skin);

    $result = $upgrader->upgrade($update, array(
        'allow_relaxed_file_ownership' => true,
        'clear_update_cache' => true
    ));

    if (is_wp_error($result)) {
        echo '<p style="color:red;">Repair failed: ' . esc_html($result->get_error_message()) . '</p>';
    } else {
        echo '<p style="color:green; font-weight:bold;">Core files successfully repaired! WordPress has been reinstalled.</p>';
    }
    echo '</div>';
}

// Disable File Mods (Plugin/Theme installations)
if (get_option('psc_disallow_file_mods', 'no') === 'yes') {
    if (!defined('DISALLOW_FILE_MODS')) {
        define('DISALLOW_FILE_MODS', true);
    }
}

// Hide WP Version
if (get_option('psc_hide_wp_version', 'no') === 'yes') {
    add_filter('the_generator', '__return_empty_string');
    add_filter('style_loader_src', 'psc_remove_version_scripts_styles', 9999);
    add_filter('script_loader_src', 'psc_remove_version_scripts_styles', 9999);
}
function psc_remove_version_scripts_styles($src) {
    if (strpos($src, 'ver=')) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}

// --- Alerts and Monitoring ---

function psc_get_alert_email() {
    return get_option('admin_email');
}

// Alert on New Admin Users
add_action('user_register', 'psc_alert_new_admin_user', 20);
function psc_alert_new_admin_user($user_id) {
    $user = get_userdata($user_id);
    if ($user && in_array('administrator', (array) $user->roles)) {
        wp_mail(
            psc_get_alert_email(),
            '[Security Alert] New Administrator User Created',
            "A new administrator user has been created on your site.\n\nUsername: {$user->user_login}\nEmail: {$user->user_email}\nDate: " . date('Y-m-d H:i:s')
        );
    }
}

// Alert on Privilege Escalation
add_action('set_user_role', 'psc_alert_privilege_escalation', 10, 3);
function psc_alert_privilege_escalation($user_id, $role, $old_roles) {
    if ($role === 'administrator' && !in_array('administrator', (array) $old_roles)) {
        $user = get_userdata($user_id);
        if ($user) {
            wp_mail(
                psc_get_alert_email(),
                '[Security Alert] Privilege Escalation Detected',
                "A user's privileges have been escalated to administrator.\n\nUsername: {$user->user_login}\nDate: " . date('Y-m-d H:i:s')
            );
        }
    }
}

// Alert on Theme Change
add_action('switch_theme', 'psc_alert_theme_change', 10, 3);
function psc_alert_theme_change($new_name, $new_theme, $old_theme) {
    wp_mail(
        psc_get_alert_email(),
        '[Security Alert] Theme Changed',
        "The active theme has been changed.\n\nNew Theme: {$new_name}\nOld Theme: {$old_theme->name}\nDate: " . date('Y-m-d H:i:s')
    );
}

// Alert on new plugin installation (already covered partially by the original plugin, but we can hook upgrader for real installs)
add_action('upgrader_process_complete', 'psc_alert_plugin_install', 10, 2);
function psc_alert_plugin_install($upgrader_object, $options) {
    if ($options['action'] === 'install' && $options['type'] === 'plugin') {
        $plugin_name = isset($upgrader_object->result['destination_name']) ? $upgrader_object->result['destination_name'] : 'Unknown';
        wp_mail(
            psc_get_alert_email(),
            '[Security Alert] New Plugin Installed',
            "A new plugin has been installed via the admin panel.\n\nPlugin: {$plugin_name}\nDate: " . date('Y-m-d H:i:s')
        );
    }
}

// --- Malware & DB Scanner ---

function psc_run_database_checks() {
    global $table_prefix;
    echo '<div class="notice notice-info" style="padding:15px; margin-top:20px;">';
    echo '<h3>Database Security Check</h3>';

    if ($table_prefix === 'wp_') {
        echo '<p style="color:red;"><strong>Warning:</strong> Your database prefix is set to the default <code>wp_</code>. This makes you vulnerable to automated SQL injection attacks. It is highly recommended to change it.</p>';
    } else {
        echo '<p style="color:green;"><strong>Protected:</strong> Your database prefix is not the default. Good job!</p>';
    }

    $suspicious_options = psc_get_suspicious_db_options();
    if (!empty($suspicious_options)) {
        echo '<h4 style="color:red; margin-top: 15px;">Suspicious Database Options Found:</h4><ul>';
        foreach ($suspicious_options as $opt_name) {
            echo '<li><code>' . esc_html($opt_name) . '</code> (Potential malicious payload detected)</li>';
        }
        echo '</ul><p>Please review these options in your database via phpMyAdmin or a database manager plugin.</p>';
    } else {
        echo '<p style="color:green;"><strong>Clean:</strong> No suspicious payloads detected in the database options table.</p>';
    }

    echo '</div>';
}

function psc_run_malware_scan($silent = false) {
    $upload_dir = wp_upload_dir();
    $scan_dirs = array(WP_PLUGIN_DIR, get_theme_root(), $upload_dir['basedir']);

    $suspicious_patterns = array(
        'eval(base64_decode',
        'eval($_POST',
        'eval($_GET',
        'str_rot13',
        'gzinflate(base64_decode'
    );

    $found_issues = array();

    foreach ($scan_dirs as $dir) {
        if (!is_dir($dir)) continue;

        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
        foreach ($iterator as $file) {
            if ($file->isDir()) continue;
            if (pathinfo($file->getFilename(), PATHINFO_EXTENSION) !== 'php') continue;

            $contents = @file_get_contents($file->getPathname());
            if (!$contents) continue;

            foreach ($suspicious_patterns as $pattern) {
                // simple strpos check for basic malware heuristics
                if (strpos($contents, $pattern) !== false) {
                    $found_issues[] = array('file' => $file->getPathname(), 'pattern' => $pattern);
                }
            }
        }
    }

    if (!$silent) {
        echo '<div class="notice notice-info" style="padding:15px; margin-top:20px;">';
        echo '<h3>Malware & Backdoor Heuristic Scan</h3>';

        if (empty($found_issues)) {
            echo '<p style="color:green; font-weight:bold;">Success! No obvious malicious PHP patterns found in plugins, themes, or uploads.</p>';
        } else {
            echo '<h4 style="color:red;">Suspicious Files Found:</h4><ul>';
            foreach ($found_issues as $issue) {
                echo '<li><code>' . esc_html($issue['file']) . '</code> (Matched: ' . esc_html($issue['pattern']) . ')</li>';
            }
            echo '</ul>';
        }
        echo '</div>';
    }

    return $found_issues;
}

// Scheduled Daily Malware Scan
if (!wp_next_scheduled('psc_daily_malware_scan')) {
    wp_schedule_event(time(), 'daily', 'psc_daily_malware_scan');
}
add_action('psc_daily_malware_scan', 'psc_scheduled_malware_scan');

function psc_scheduled_malware_scan() {
    $issues = psc_run_malware_scan(true);
    if (!empty($issues)) {
        $body = "The Plugin Security Check daily scan found suspicious files:\n\n";
        foreach ($issues as $issue) {
            $body .= "- " . $issue['file'] . " (Pattern: " . $issue['pattern'] . ")\n";
        }
        wp_mail(psc_get_alert_email(), '[Security Alert] Malware Scan Detected Issues', $body);
    }
}

// --- Advanced Missing Features ---

// Scheduled Advanced Checks
if (!wp_next_scheduled('psc_daily_advanced_scan')) {
    wp_schedule_event(time(), 'daily', 'psc_daily_advanced_scan');
}
add_action('psc_daily_advanced_scan', 'psc_scheduled_advanced_scan');

function psc_scheduled_advanced_scan() {
    $alerts = array();

    // Check 1: Suspicious Cron Jobs
    $crons = _get_cron_array();
    $suspicious_crons = array();
    if (is_array($crons)) {
        foreach ($crons as $timestamp => $cronhooks) {
            foreach ($cronhooks as $hook => $keys) {
                // If a cron job contains eval or base64 or doesn't match standard patterns
                if (strpos($hook, 'eval(') !== false || strpos($hook, 'base64_decode') !== false) {
                    $suspicious_crons[] = $hook;
                }
            }
        }
    }
    if (!empty($suspicious_crons)) {
        $alerts[] = "Suspicious Cron Jobs Detected:\n- " . implode("\n- ", $suspicious_crons);
    }

    // Check 2: Unauthorized Admin Accounts
    $admin_users = get_users(array('role' => 'administrator'));
    $known_admins = get_option('psc_known_admins', array());
    $unknown_admins = array();

    // Initialize known admins if empty (first run)
    if (empty($known_admins)) {
        foreach ($admin_users as $admin) {
            $known_admins[] = $admin->ID;
        }
        update_option('psc_known_admins', $known_admins);
    } else {
        foreach ($admin_users as $admin) {
            if (!in_array($admin->ID, $known_admins)) {
                $unknown_admins[] = $admin->user_login;
                // Auto-lock suspicious users
                $user = new WP_User($admin->ID);
                $user->remove_role('administrator');
                $user->add_role('subscriber');
                update_user_meta($admin->ID, 'psc_account_locked', true);
            }
        }
    }
    if (!empty($unknown_admins)) {
        $alerts[] = "Unauthorized Admin Accounts Detected & Demoted to Subscriber:\n- " . implode("\n- ", $unknown_admins);
    }

    // Check 3: Suspicious DB Options
    $suspicious_options = psc_get_suspicious_db_options();
    if (!empty($suspicious_options)) {
        $alerts[] = "Suspicious Database Options Detected (Potential Malicious Payloads):";
        foreach ($suspicious_options as $opt_name) {
            $alerts[] = "- " . $opt_name;
        }
    }

    // Check 4: Modified Plugin/Theme Files (Checksum baseline)
    // To properly do this, we compare md5 hashes of the plugin directories over time.
    // If a hash changes and wasn't preceded by a plugin update action, it's flagged.
    $plugins_hash = psc_generate_directory_hash(WP_PLUGIN_DIR);
    $themes_hash = psc_generate_directory_hash(get_theme_root());

    $stored_plugins_hash = get_option('psc_plugins_baseline_hash', '');
    $stored_themes_hash = get_option('psc_themes_baseline_hash', '');

    if (empty($stored_plugins_hash)) {
        update_option('psc_plugins_baseline_hash', $plugins_hash);
    } elseif ($plugins_hash !== $stored_plugins_hash) {
        $alerts[] = "Plugin files have been modified outside of standard updates!";
    }

    if (empty($stored_themes_hash)) {
        update_option('psc_themes_baseline_hash', $themes_hash);
    } elseif ($themes_hash !== $stored_themes_hash) {
        $alerts[] = "Theme files have been modified outside of standard updates!";
    }

    if (!empty($alerts)) {
        wp_mail(
            psc_get_alert_email(),
            '[CRITICAL Security Alert] Advanced Malware & DB Scan',
            "The daily advanced scan detected severe security risks on your website:\n\n" . implode("\n\n", $alerts)
        );
    }
}

function psc_generate_directory_hash($dir) {
    if (!is_dir($dir)) return '';
    $files = array();
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
    foreach ($iterator as $file) {
        if ($file->isDir()) continue;
        $files[] = md5_file($file->getPathname());
    }
    sort($files);
    return md5(implode('', $files));
}

// Update baselines when admins intentionally update plugins/themes
add_action('upgrader_process_complete', 'psc_update_baselines_on_upgrade', 10, 2);
function psc_update_baselines_on_upgrade($upgrader_object, $options) {
    if ($options['type'] === 'plugin') {
        update_option('psc_plugins_baseline_hash', psc_generate_directory_hash(WP_PLUGIN_DIR));
    } elseif ($options['type'] === 'theme') {
        update_option('psc_themes_baseline_hash', psc_generate_directory_hash(get_theme_root()));
    }
}


// Helper to fetch genuinely suspicious database options
function psc_get_suspicious_db_options() {
    global $wpdb;

    // Whitelist common safe prefixes to reduce processing
    $whitelist_prefixes = array('_transient_timeout_', '_site_transient_timeout_');

    // Broad SQL query to grab potentially risky options (we will filter in PHP)
    // We target transients, site transients, and other options that might hold serialized payloads
    $query = "SELECT option_name, option_value FROM {$wpdb->options} WHERE
             option_value LIKE '%eval(%' OR
             option_value LIKE '%base64_decode%' OR
             option_value LIKE '%gzinflate%' OR
             option_value LIKE '%system(%' OR
             option_value LIKE '%exec(%' OR
             option_value LIKE '%shell_exec(%' OR
             option_value LIKE '%passthru(%' OR
             LENGTH(option_value) > 10000"; // Flag unusually large options for heuristic check

    $results = $wpdb->get_results($query);
    $suspicious = array();

    if (empty($results)) return $suspicious;

    $malware_patterns = array(
        '/eval\s*\(\s*base64_decode/i',
        '/eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i',
        '/gzinflate\s*\(\s*base64_decode/i',
        '/system\s*\(\s*\$_(POST|GET)/i',
        '/exec\s*\(\s*\$_(POST|GET)/i',
        '/passthru\s*\(\s*\$_(POST|GET)/i',
        '/shell_exec\s*\(/i',
        '/(?:[a-zA-Z0-9+\/]{4}){100,}(?:[a-zA-Z0-9+\/]{2}==|[a-zA-Z0-9+\/]{3}=)?/' // Very long base64 strings
    );

    foreach ($results as $row) {
        $name = $row->option_name;
        $val = $row->option_value;

        // Skip explicitly whitelisted prefixes
        $skip = false;
        foreach ($whitelist_prefixes as $prefix) {
            if (strpos($name, $prefix) === 0) {
                $skip = true;
                break;
            }
        }
        if ($skip) continue;

        // If it's a known transient but its value isn't serialized or JSON, it might be a payload
        $is_transient = (strpos($name, '_transient_') === 0 || strpos($name, '_site_transient_') === 0);

        // Apply strict heuristics
        $is_malicious = false;
        foreach ($malware_patterns as $pattern) {
            if (preg_match($pattern, $val)) {
                $is_malicious = true;
                break;
            }
        }

        if ($is_malicious) {
            $suspicious[] = $name;
        }
    }

    return $suspicious;
}
