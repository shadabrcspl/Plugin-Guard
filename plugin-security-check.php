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
    echo '<a href="?page=plugin-approvals&tab=ips" class="nav-tab ' . ($active_tab == 'ips' ? 'nav-tab-active' : '') . '">IP Manager</a>';
    echo '<a href="?page=plugin-approvals&tab=posts" class="nav-tab ' . ($active_tab == 'posts' ? 'nav-tab-active' : '') . '">Post Approvals</a>';
    echo '<a href="?page=plugin-approvals&tab=404logs" class="nav-tab ' . ($active_tab == '404logs' ? 'nav-tab-active' : '') . '">404 Logs</a>';
    echo '</h2>';

    if ($active_tab == 'approvals') {
    // Verify nonce for approval actions
    $nonce_valid = isset($_POST['psc_approvals_nonce']) && wp_verify_nonce($_POST['psc_approvals_nonce'], 'psc_approvals_action');

    // Handle plugin approval
    if (isset($_POST['approve_plugin']) && $nonce_valid) {
        $plugin_slug = sanitize_text_field($_POST['plugin_slug']);
        $pending = get_option('pending_approval_plugins', array());
        if (in_array($plugin_slug, $pending)) {
            approve_plugin($plugin_slug);
            echo '<div class="updated"><p>Plugin approved and activated!</p></div>';
        }
    }

    // Handle plugin rejection
    if (isset($_POST['reject_plugin']) && $nonce_valid) {
        $plugin_slug = sanitize_text_field($_POST['plugin_slug']);
        $pending = get_option('pending_approval_plugins', array());
        if (in_array($plugin_slug, $pending)) {
            reject_plugin($plugin_slug);
            echo '<div class="updated"><p>Plugin rejected and deleted!</p></div>';
        }
    }

    // Handle clearing all pending approval plugins
    if (isset($_POST['clear_pending_plugins']) && $nonce_valid) {
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
            wp_nonce_field('psc_approvals_action', 'psc_approvals_nonce');
            echo '<input type="hidden" name="plugin_slug" value="' . esc_attr($plugin) . '">';
            echo '<input type="submit" name="approve_plugin" value="Approve" style="margin-right:10px;">';
            echo '</form>';

            echo ' <form method="post" action="" style="display:inline;">';
            wp_nonce_field('psc_approvals_action', 'psc_approvals_nonce');
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
    wp_nonce_field('psc_approvals_action', 'psc_approvals_nonce');
    echo '<input type="submit" name="clear_pending_plugins" value="Clear All Pending Plugins" class="button-primary">';
    echo '</form>';

    } elseif ($active_tab == 'security') {
        $security_nonce_valid = isset($_POST['psc_security_nonce']) && wp_verify_nonce($_POST['psc_security_nonce'], 'psc_security_action');
        // Handle saving security settings
        if (isset($_POST['save_security_settings']) && $security_nonce_valid) {
            update_option('psc_disable_xmlrpc', isset($_POST['psc_disable_xmlrpc']) ? 'yes' : 'no');
            update_option('psc_prevent_enumeration', isset($_POST['psc_prevent_enumeration']) ? 'yes' : 'no');
            update_option('psc_disable_directory_browsing', isset($_POST['psc_disable_directory_browsing']) ? 'yes' : 'no');
            update_option('psc_protect_wpconfig', isset($_POST['psc_protect_wpconfig']) ? 'yes' : 'no');
            update_option('psc_disable_app_passwords', isset($_POST['psc_disable_app_passwords']) ? 'yes' : 'no');
            update_option('psc_restrict_rest_api', isset($_POST['psc_restrict_rest_api']) ? 'yes' : 'no');
            update_option('psc_disallow_file_mods', isset($_POST['psc_disallow_file_mods']) ? 'yes' : 'no');
            update_option('psc_hide_wp_version', isset($_POST['psc_hide_wp_version']) ? 'yes' : 'no');
            update_option('psc_require_post_approval', isset($_POST['psc_require_post_approval']) ? 'yes' : 'no');
            update_option('psc_enable_post_monitor', isset($_POST['psc_enable_post_monitor']) ? 'yes' : 'no');
            if (isset($_POST['psc_max_external_links'])) {
                update_option('psc_max_external_links', intval($_POST['psc_max_external_links']));
            }
            if (isset($_POST['psc_blacklisted_domains'])) {
                update_option('psc_blacklisted_domains', sanitize_textarea_field($_POST['psc_blacklisted_domains']));
            }
            update_option('psc_redirect_404_to_home', isset($_POST['psc_redirect_404_to_home']) ? 'yes' : 'no');

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
        if (isset($_POST['run_security_tests']) && $security_nonce_valid) {
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
        wp_nonce_field('psc_security_action', 'psc_security_nonce');
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

        echo '<tr><th scope="row">Require Post Approval</th>';
        echo '<td><label><input type="checkbox" name="psc_require_post_approval" value="1" ' . checked(get_option('psc_require_post_approval', 'no'), 'yes', false) . '> Require admin approval before non-admins can publish blog posts</label></td></tr>';

        echo '<tr><th scope="row">Enable Post Creation Monitor</th>';
        echo '<td><label><input type="checkbox" name="psc_enable_post_monitor" value="1" ' . checked(get_option('psc_enable_post_monitor', 'no'), 'yes', false) . '> Automatically force posts to Draft/Pending if they contain suspicious links or look like bulk spam.</label></td></tr>';

        echo '<tr><th scope="row">Max External Links</th>';
        echo '<td><input type="number" name="psc_max_external_links" value="' . esc_attr(get_option('psc_max_external_links', 5)) . '" style="width: 60px;"> <span class="description">Maximum external links allowed before a post is flagged.</span></td></tr>';

        echo '<tr><th scope="row">Blacklisted Domains</th>';
        echo '<td><textarea name="psc_blacklisted_domains" rows="3" style="width: 100%;" placeholder="example.com&#10;spam-domain.net">' . esc_textarea(get_option('psc_blacklisted_domains', '')) . '</textarea><br><span class="description">One domain per line. Posts containing links to these domains will be flagged immediately.</span></td></tr>';

        echo '<tr><th scope="row">Redirect 404s to Home</th>';
        echo '<td><label><input type="checkbox" name="psc_redirect_404_to_home" value="1" ' . checked(get_option('psc_redirect_404_to_home', 'no'), 'yes', false) . '> Automatically 301 redirect all 404 Not Found errors to the homepage to preserve SEO juice from deleted spam URLs.</label></td></tr>';

        echo '</table>';
        echo '<p class="submit"><input type="submit" name="save_security_settings" class="button button-primary" value="Save Settings"></p>';
        echo '</form>';

        echo '<hr>';
        echo '<form method="post" action="">';
        wp_nonce_field('psc_security_action', 'psc_security_nonce');
        echo '<p class="submit"><input type="submit" name="run_security_tests" class="button button-secondary" value="Run Manual Security Tests"></p>';
        echo '<p class="description">This will make loopback requests to your site to check if the protections are actively blocking access.</p>';
        echo '</form>';

        // NGINX Rules Section
        $is_nginx = (strpos($_SERVER['SERVER_SOFTWARE'] ?? '', 'nginx') !== false);
        if ($is_nginx || (isset($_POST['show_nginx_rules']) && $security_nonce_valid)) {
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
            wp_nonce_field('psc_security_action', 'psc_security_nonce');
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

        if (isset($_POST['delete_db_option']) && isset($_POST['psc_scanner_nonce']) && wp_verify_nonce($_POST['psc_scanner_nonce'], 'psc_delete_option')) {
            $option_name = sanitize_text_field($_POST['option_name']);
            if (delete_option($option_name)) {
                echo '<div class="updated"><p>Database option <strong>' . esc_html($option_name) . '</strong> was successfully deleted.</p></div>';
            } else {
                echo '<div class="error"><p>Failed to delete option <strong>' . esc_html($option_name) . '</strong>. It may have already been removed.</p></div>';
            }
        }

        echo '<form method="post" action="">';
        wp_nonce_field('psc_run_scan', 'psc_scanner_nonce');
        echo '<p><input type="submit" name="run_core_scan" class="button button-primary" value="Scan Core Files Now"></p>';
        echo '</form>';
    } elseif ($active_tab == 'ips') {
        echo '<h2>IP Block Manager</h2>';
        echo '<p>Manage IP addresses that have been blocked from accessing your website.</p>';

        $nonce_valid = isset($_POST['psc_ip_nonce']) && wp_verify_nonce($_POST['psc_ip_nonce'], 'psc_ip_action');

        // Handle unblock
        if (isset($_POST['unblock_ip']) && $nonce_valid) {
            $ip_to_unblock = sanitize_text_field($_POST['ip_address']);
            psc_unblock_ip($ip_to_unblock);
            echo '<div class="updated"><p>IP address ' . esc_html($ip_to_unblock) . ' has been unblocked.</p></div>';
        }

        // Handle manual block
        if (isset($_POST['manual_block_ip']) && $nonce_valid) {
            $ip_to_block = sanitize_text_field($_POST['new_ip']);
            $remark = sanitize_text_field($_POST['block_remark']);
            if (filter_var($ip_to_block, FILTER_VALIDATE_IP)) {
                psc_block_ip($ip_to_block, $remark);
                echo '<div class="updated"><p>IP address ' . esc_html($ip_to_block) . ' has been blocked.</p></div>';
            } else {
                echo '<div class="error"><p>Invalid IP address format.</p></div>';
            }
        }

        // Display manual block form
        echo '<div style="background:#fff; border:1px solid #ccc; padding:15px; margin-bottom:20px;">';
        echo '<h3>Manually Block an IP Address</h3>';
        echo '<form method="post" action="">';
        wp_nonce_field('psc_ip_action', 'psc_ip_nonce');
        echo '<p><label for="new_ip"><strong>IP Address:</strong></label> <input type="text" name="new_ip" id="new_ip" required style="width:200px;"></p>';
        echo '<p><label for="block_remark"><strong>Remark / Reason:</strong></label> <input type="text" name="block_remark" id="block_remark" style="width:400px;" placeholder="e.g., Attempted SQL Injection"></p>';
        echo '<input type="submit" name="manual_block_ip" class="button button-primary" value="Block IP Address">';
        echo '</form>';
        echo '</div>';

        // Display blocked IPs table
        $blocked_ips = get_option('psc_blocked_ips', array());
        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>IP Address</th><th>Time Blocked</th><th>Remark</th><th>Action</th></tr></thead>';
        echo '<tbody>';
        if (empty($blocked_ips)) {
            echo '<tr><td colspan="4">No IP addresses are currently blocked.</td></tr>';
        } else {
            foreach ($blocked_ips as $ip => $data) {
                echo '<tr>';
                echo '<td>' . esc_html($ip) . '</td>';
                echo '<td>' . esc_html($data['time'] ?? 'Unknown') . '</td>';
                echo '<td>' . esc_html($data['remark'] ?? '') . '</td>';
                echo '<td>';
                echo '<form method="post" action="" style="display:inline;">';
                wp_nonce_field('psc_ip_action', 'psc_ip_nonce');
                echo '<input type="hidden" name="ip_address" value="' . esc_attr($ip) . '">';
                echo '<input type="submit" name="unblock_ip" class="button button-small" value="Unlock">';
                echo '</form>';
                echo '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';
    } elseif ($active_tab == 'posts') {
        echo '<h2>Pending Post Approvals</h2>';
        echo '<p>Review and approve blog posts submitted by non-administrators. You can optionally change the author of the post before publishing.</p>';

        $nonce_valid = isset($_POST['psc_posts_nonce']) && wp_verify_nonce($_POST['psc_posts_nonce'], 'psc_posts_action');

        // Handle post approval
        if (isset($_POST['approve_post']) && $nonce_valid) {
            $post_id = intval($_POST['post_id']);
            $new_author_id = intval($_POST['post_author']);

            if ($post_id > 0) {
                $update_args = array(
                    'ID'           => $post_id,
                    'post_status'  => 'publish',
                    'post_author'  => $new_author_id
                );
                wp_update_post($update_args);
                echo '<div class="updated"><p>Post successfully approved and published!</p></div>';
            }
        }

        // Handle post rejection (move to trash)
        if (isset($_POST['reject_post']) && $nonce_valid) {
            $post_id = intval($_POST['post_id']);
            if ($post_id > 0) {
                wp_trash_post($post_id);
                echo '<div class="updated"><p>Post rejected and moved to trash.</p></div>';
            }
        }

        // Fetch pending posts
        $pending_posts = get_posts(array(
            'post_type'   => 'post',
            'post_status' => 'pending',
            'numberposts' => -1
        ));

        // Fetch all users for the author dropdown
        $all_users = get_users();

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>Post Title</th><th>Current Author</th><th>Change Author To</th><th>Actions</th></tr></thead>';
        echo '<tbody>';

        if (empty($pending_posts)) {
            echo '<tr><td colspan="4">No posts currently awaiting approval.</td></tr>';
        } else {
            foreach ($pending_posts as $post) {
                $author_info = get_userdata($post->post_author);
                $current_author_name = $author_info ? $author_info->user_login : 'Unknown';
                $edit_url = admin_url('post.php?action=edit&post=' . $post->ID);

                echo '<tr>';
                echo '<td><strong><a href="' . esc_url($edit_url) . '" target="_blank">' . esc_html($post->post_title) . '</a></strong></td>';
                echo '<td>' . esc_html($current_author_name) . '</td>';
                echo '<td>';
                echo '<form method="post" action="">';
                wp_nonce_field('psc_posts_action', 'psc_posts_nonce');
                echo '<input type="hidden" name="post_id" value="' . esc_attr($post->ID) . '">';
                echo '<select name="post_author">';
                foreach ($all_users as $user) {
                    $selected = ($user->ID == $post->post_author) ? 'selected' : '';
                    echo '<option value="' . esc_attr($user->ID) . '" ' . $selected . '>' . esc_html($user->user_login) . '</option>';
                }
                echo '</select>';
                echo '</td>';
                echo '<td>';
                echo '<input type="submit" name="approve_post" class="button button-primary" value="Approve & Publish" style="margin-right:10px;">';
                echo '<input type="submit" name="reject_post" class="button button-secondary" value="Reject (Trash)" onclick="return confirm(\'Are you sure you want to trash this post?\');">';
                echo '</form>';
                echo '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';
    } elseif ($active_tab == '404logs') {
        echo '<h2>404 Error Logs & Redirects</h2>';
        echo '<p>View all 404 Not Found errors caught by the plugin. If "Redirect 404s to Home" is enabled in Security Settings, they will redirect to the homepage by default. You can override individual URLs to keep them as 404s, or set custom redirects.</p>';

        $nonce_valid = isset($_POST['psc_404_nonce']) && wp_verify_nonce($_POST['psc_404_nonce'], 'psc_404_action');
        $logs = get_option('psc_404_logs', array());
        if (!is_array($logs)) $logs = array();

        if ($nonce_valid) {
            if (isset($_POST['action_delete'])) {
                $url = esc_url_raw($_POST['log_url']);
                if (isset($logs[$url])) {
                    unset($logs[$url]);
                    update_option('psc_404_logs', $logs, false);
                    echo '<div class="updated"><p>Log entry deleted.</p></div>';
                }
            } elseif (isset($_POST['action_update'])) {
                $url = esc_url_raw($_POST['log_url']);
                $action_type = sanitize_text_field($_POST['redirect_action']);
                $custom_url = esc_url_raw($_POST['custom_url']);

                if (isset($logs[$url])) {
                    $logs[$url]['action'] = $action_type;
                    $logs[$url]['custom_url'] = $custom_url;
                    update_option('psc_404_logs', $logs, false);
                    echo '<div class="updated"><p>URL action updated successfully.</p></div>';
                }
            }
        }

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th style="width:35%;">URL</th><th>Hits</th><th>Last Hit</th><th>Action</th><th style="width:15%;">Manage</th></tr></thead>';
        echo '<tbody>';
        if (empty($logs)) {
            echo '<tr><td colspan="5">No 404 errors have been logged yet.</td></tr>';
        } else {
            // Sort by hits descending
            uasort($logs, function($a, $b) { return $b['hits'] - $a['hits']; });

            foreach ($logs as $url => $data) {
                $action = isset($data['action']) ? $data['action'] : 'home';
                $custom_url = isset($data['custom_url']) ? $data['custom_url'] : '';

                echo '<tr>';
                echo '<td style="word-break: break-all;">' . esc_html($url) . '</td>';
                echo '<td>' . intval($data['hits']) . '</td>';
                echo '<td>' . esc_html($data['last_hit']) . '</td>';

                echo '<td>';
                echo '<form method="post" action="">';
                wp_nonce_field('psc_404_action', 'psc_404_nonce');
                echo '<input type="hidden" name="log_url" value="' . esc_attr($url) . '">';

                echo '<select name="redirect_action" onchange="this.parentNode.querySelector(\'div.custom-url-container\').style.display = (this.value == \'custom\') ? \'block\' : \'none\';">';
                echo '<option value="home" ' . selected($action, 'home', false) . '>Redirect to Home</option>';
                echo '<option value="keep" ' . selected($action, 'keep', false) . '>Keep as 404 (No redirect)</option>';
                echo '<option value="custom" ' . selected($action, 'custom', false) . '>Custom Redirect</option>';
                echo '</select>';

                $display = ($action === 'custom') ? 'block' : 'none';
                echo '<div class="custom-url-container" style="display:' . $display . '; margin-top:5px;">';
                echo '<input type="url" name="custom_url" placeholder="https://..." value="' . esc_attr($custom_url) . '" style="width:100%;">';
                echo '</div>';
                echo '</td>';

                echo '<td>';
                echo '<input type="submit" name="action_update" class="button button-small button-primary" value="Save" style="margin-right:5px;">';
                echo '<input type="submit" name="action_delete" class="button button-small button-link-delete" style="color:#a00;" value="Delete">';
                echo '</form>';
                echo '</td>';

                echo '</tr>';
            }
        }
        echo '</tbody></table>';
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
        $creator_ip = psc_get_client_ip();
        $current_user = wp_get_current_user();
        $is_authorized = ($current_user->exists() && in_array('administrator', (array) $current_user->roles));

        if (!$is_authorized && !empty($creator_ip)) {
            psc_block_ip($creator_ip, 'Auto-blocked for unauthorized creation of an administrator account.');
        }

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
        $creator_ip = psc_get_client_ip();
        $current_user = wp_get_current_user();
        $is_authorized = ($current_user->exists() && in_array('administrator', (array) $current_user->roles));

        if (!$is_authorized && !empty($creator_ip)) {
            psc_block_ip($creator_ip, 'Auto-blocked for unauthorized privilege escalation to administrator.');
        }

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
        echo '<h4 style="color:red; margin-top: 15px;">Suspicious Database Options Found:</h4>';
        echo '<p>The following options match known malware signatures. You can delete them here to clean your database.</p>';
        echo '<table class="wp-list-table widefat fixed striped" style="margin-top:10px;">';
        echo '<thead><tr><th>Option Name</th><th>Reason</th><th style="width:150px;">Action</th></tr></thead>';
        echo '<tbody>';
        foreach ($suspicious_options as $opt_name) {
            echo '<tr>';
            echo '<td><code>' . esc_html($opt_name) . '</code></td>';
            echo '<td><span style="color:red;">Potential malicious payload detected</span></td>';
            echo '<td>';
            echo '<form method="post" action="" onsubmit="return confirm(\'Are you sure you want to permanently delete this option?\');">';
            wp_nonce_field('psc_delete_option', 'psc_scanner_nonce');
            echo '<input type="hidden" name="option_name" value="' . esc_attr($opt_name) . '">';
            echo '<input type="submit" name="delete_db_option" class="button button-small button-link-delete" style="color:#a00;" value="Delete Option">';
            echo '</form>';
            echo '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    } else {
        echo '<p style="color:green;"><strong>Clean:</strong> No suspicious payloads detected in the database options table.</p>';
    }

    echo '</div>';
}

function psc_run_malware_scan($silent = false) {
    $upload_dir = wp_upload_dir();
    $scan_dirs = array(WP_PLUGIN_DIR, get_theme_root(), $upload_dir['basedir']);

    // Break up the strings so this file doesn't flag itself during the scan
    $suspicious_patterns = array(
        'eval' . '(base64' . '_decode',
        'eval' . '($_POST',
        'eval' . '($_GET',
        'str' . '_rot13',
        'gzinflate' . '(base64' . '_decode'
    );

    $found_issues = array();

    foreach ($scan_dirs as $dir) {
        if (!is_dir($dir)) continue;

        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
        foreach ($iterator as $file) {
            if ($file->isDir()) continue;
            if (pathinfo($file->getFilename(), PATHINFO_EXTENSION) !== 'php') continue;

            // Ignore common vendor/dependency directories which often contain these strings legitimately (e.g. polyfills, test mocks)
            $path = $file->getPathname();
            if (strpos($path, '/vendor/') !== false || strpos($path, '/node_modules/') !== false) continue;

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
    $current_plugins_hash = psc_generate_directory_hash(WP_PLUGIN_DIR);
    $current_themes_hash = psc_generate_directory_hash(get_theme_root());

    $stored_plugins_hash = get_option('psc_plugins_baseline_hash', array());
    $stored_themes_hash = get_option('psc_themes_baseline_hash', array());

    // Handle backwards compatibility if it was previously a string
    if (!is_array($stored_plugins_hash)) $stored_plugins_hash = array();
    if (!is_array($stored_themes_hash)) $stored_themes_hash = array();

    if (empty($stored_plugins_hash)) {
        update_option('psc_plugins_baseline_hash', $current_plugins_hash, false);
    } else {
        $plugin_report = psc_compare_file_hashes($stored_plugins_hash, $current_plugins_hash, 'Plugin');
        if ($plugin_report) {
            $alerts[] = $plugin_report;
            // Update baseline so we don't alert repeatedly for the same change
            update_option('psc_plugins_baseline_hash', $current_plugins_hash, false);
        }
    }

    if (empty($stored_themes_hash)) {
        update_option('psc_themes_baseline_hash', $current_themes_hash, false);
    } else {
        $theme_report = psc_compare_file_hashes($stored_themes_hash, $current_themes_hash, 'Theme');
        if ($theme_report) {
            $alerts[] = $theme_report;
            update_option('psc_themes_baseline_hash', $current_themes_hash, false);
        }
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
    if (!is_dir($dir)) return array();
    $files = array();
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
    foreach ($iterator as $file) {
        if ($file->isDir()) continue;
        $path = $file->getPathname();
        $files[$path] = md5_file($path);
    }
    return $files;
}

function psc_compare_file_hashes($old_hashes, $new_hashes, $type) {
    if (!is_array($old_hashes) || !is_array($new_hashes)) return false;

    $added = array();
    $deleted = array();
    $modified = array();

    foreach ($new_hashes as $file => $hash) {
        if (!isset($old_hashes[$file])) {
            $added[] = $file;
        } elseif ($old_hashes[$file] !== $hash) {
            $modified[] = $file;
        }
    }

    foreach ($old_hashes as $file => $hash) {
        if (!isset($new_hashes[$file])) {
            $deleted[] = $file;
        }
    }

    if (empty($added) && empty($deleted) && empty($modified)) {
        return false;
    }

    $report = "{$type} files have been modified outside of standard updates!\n";
    if (!empty($added)) {
        $report .= "\n[ADDED FILES]\n- " . implode("\n- ", $added) . "\n";
    }
    if (!empty($modified)) {
        $report .= "\n[MODIFIED FILES]\n- " . implode("\n- ", $modified) . "\n";
    }
    if (!empty($deleted)) {
        $report .= "\n[DELETED FILES]\n- " . implode("\n- ", $deleted) . "\n";
    }

    return $report;
}

// Update baselines when admins intentionally update plugins/themes
add_action('upgrader_process_complete', 'psc_update_baselines_on_upgrade', 10, 2);
function psc_update_baselines_on_upgrade($upgrader_object, $options) {
    if ($options['type'] === 'plugin') {
        update_option('psc_plugins_baseline_hash', psc_generate_directory_hash(WP_PLUGIN_DIR), false);
    } elseif ($options['type'] === 'theme') {
        update_option('psc_themes_baseline_hash', psc_generate_directory_hash(get_theme_root()), false);
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

// --- Content Approval System ---

// Intercept post publishing for non-admins
if (get_option('psc_require_post_approval', 'no') === 'yes') {
    add_filter('wp_insert_post_data', 'psc_require_admin_approval_for_posts', 10, 2);
}

function psc_require_admin_approval_for_posts($data, $postarr) {
    // We only care about standard posts (blogs)
    if ($data['post_type'] !== 'post') {
        return $data;
    }

    // If the user is trying to publish or schedule the post
    if (in_array($data['post_status'], array('publish', 'future'))) {

        // Bypass the check if this is an automated WP-Cron job (e.g., publishing a previously scheduled post by an admin)
        if (defined('DOING_CRON') && DOING_CRON) {
            return $data;
        }

        if (function_exists('wp_get_current_user')) {
            $user = wp_get_current_user();

            // If user is not logged in (e.g. REST API exploit) or is not an administrator
            if (!$user->exists() || !in_array('administrator', (array) $user->roles)) {

                // Force the post back to pending review
                $data['post_status'] = 'pending';

                // Note: We don't send the email here because this filter runs multiple times
                // We use transition_post_status for the email alert.
            }
        }
    }

    return $data;
}

// Alert admin when a post requires approval
if (get_option('psc_require_post_approval', 'no') === 'yes') {
    add_action('transition_post_status', 'psc_alert_pending_post', 10, 3);
}

function psc_alert_pending_post($new_status, $old_status, $post) {
    if ($post->post_type !== 'post') {
        return;
    }

    // Only alert when transitioning to pending (usually from draft, auto-draft, or a blocked publish attempt)
    if ($new_status === 'pending' && $old_status !== 'pending') {

        $author = get_userdata($post->post_author);
        $author_name = $author ? $author->user_login : 'Unknown User';

        $edit_link = admin_url('post.php?action=edit&post=' . $post->ID);

        $subject = '[Security Alert] Blog Post Requires Approval';
        $message = "A new blog post has been submitted and requires administrator approval before it can be published.\n\n";
        $message .= "Title: {$post->post_title}\n";
        $message .= "Author: {$author_name}\n\n";
        $message .= "You can review and publish this post here:\n{$edit_link}";

        wp_mail(psc_get_alert_email(), $subject, $message);
    }
}

// --- IP Blocking System ---

function psc_get_client_ip() {
    $ip = '';
    // Use REMOTE_ADDR exclusively to prevent IP spoofing vulnerabilities via HTTP headers
    if (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = sanitize_text_field($_SERVER['REMOTE_ADDR']);
    }
    return trim($ip);
}

function psc_block_ip($ip, $remark = '') {
    $blocked_ips = get_option('psc_blocked_ips', array());
    if (!isset($blocked_ips[$ip])) {
        $blocked_ips[$ip] = array(
            'remark' => $remark,
            'time' => current_time('mysql')
        );
        update_option('psc_blocked_ips', $blocked_ips, false);
    }
}

function psc_unblock_ip($ip) {
    $blocked_ips = get_option('psc_blocked_ips', array());
    if (isset($blocked_ips[$ip])) {
        unset($blocked_ips[$ip]);
        update_option('psc_blocked_ips', $blocked_ips, false);
    }
}

// Enforce IP blocks early in the WordPress lifecycle
add_action('plugins_loaded', 'psc_enforce_ip_blocks', 1);
function psc_enforce_ip_blocks() {
    $client_ip = psc_get_client_ip();
    if (empty($client_ip)) return;

    $blocked_ips = get_option('psc_blocked_ips', array());
    if (isset($blocked_ips[$client_ip])) {
        header('HTTP/1.1 403 Forbidden');
        die('Your IP address has been blocked for security reasons.');
    }
}

// Post Creation Monitor
if (get_option('psc_enable_post_monitor', 'no') === 'yes') {
    // Priority 11 so it runs after our existing approval system
    add_filter('wp_insert_post_data', 'psc_post_creation_monitor_filter', 11, 2);
}

function psc_post_creation_monitor_filter($data, $postarr) {
    if ($data['post_type'] !== 'post') {
        return $data;
    }

    // Do not interfere if an administrator is the one publishing/updating the post.
    // This solves the "Impossible to Approve" infinite loop problem.
    if (function_exists('wp_get_current_user')) {
        $user = wp_get_current_user();
        if ($user->exists() && in_array('administrator', (array) $user->roles)) {
            return $data;
        }
    }

    // We only need to check if the post is trying to be published/scheduled and is not already pending
    if (in_array($data['post_status'], array('publish', 'future'))) {

        $should_flag = false;
        $reason = '';

        // Determine if this is a brand new post being created, or an update.
        // If $postarr['ID'] is empty or 0 (or matches a new auto-draft ID), it's new.
        // WordPress often sends ID = 0 for brand new inserts before the DB write.
        $is_new_post = empty($postarr['ID']) || (isset($postarr['post_status']) && $postarr['post_status'] === 'auto-draft');

        // 1. Bulk Post Creation Detection (Rate Limiting) - ONLY ON NEW POSTS
        $client_ip = psc_get_client_ip();
        if ($is_new_post && !empty($client_ip)) {
            $transient_name = 'psc_post_rate_' . md5($client_ip);
            $recent_posts = (int) get_transient($transient_name);

            // Allow 3 posts per 3 minutes max. If exceeded, flag it.
            if ($recent_posts >= 3) {
                $should_flag = true;
                $reason = 'Bulk post creation detected from IP.';
            } else {
                set_transient($transient_name, $recent_posts + 1, 3 * MINUTE_IN_SECONDS);
            }
        }

        // 2. Suspicious Link Checks
        if (!$should_flag && !empty($data['post_content'])) {
            $content = $data['post_content'];
            $site_domain = parse_url(home_url(), PHP_URL_HOST);

            // Extract all URLs
            preg_match_all('/href=["\'](http[s]?:\/\/[^"\']+)["\']/i', $content, $matches);
            $links = !empty($matches[1]) ? $matches[1] : array();

            $external_links_count = 0;
            $raw_blacklist = get_option('psc_blacklisted_domains', '');
            $blacklisted_domains = array_filter(array_map('trim', explode("\n", $raw_blacklist)));

            foreach ($links as $link) {
                $link_domain = parse_url($link, PHP_URL_HOST);
                if (!$link_domain) continue;

                // If it's an external link
                if (strcasecmp($link_domain, $site_domain) !== 0 && strcasecmp($link_domain, 'www.' . $site_domain) !== 0) {
                    $external_links_count++;

                    // Check against blacklist
                    foreach ($blacklisted_domains as $bad_domain) {
                        if (stripos($link_domain, $bad_domain) !== false) {
                            $should_flag = true;
                            $reason = 'Contains blacklisted domain: ' . $bad_domain;
                            break 2;
                        }
                    }
                }
            }

            // Check max external links threshold
            if (!$should_flag) {
                $max_allowed = (int) get_option('psc_max_external_links', 5);
                if ($external_links_count > $max_allowed) {
                    $should_flag = true;
                    $reason = "Exceeded maximum allowed external links ({$external_links_count} > {$max_allowed}).";
                }
            }
        }

        if ($should_flag) {
            $data['post_status'] = 'pending';

            // Send alert
            $subject = '[Security Alert] Suspicious Post Flagged';
            $message = "The Post Creation Monitor has intercepted a suspicious post and moved it to Pending Review.\n\n";
            $message .= "Post Title: {$data['post_title']}\n";
            $message .= "Reason: {$reason}\n";
            $message .= "Author IP: {$client_ip}\n\n";
            $message .= "Please review the post carefully before publishing.";
            wp_mail(psc_get_alert_email(), $subject, $message);
        }
    }

    return $data;
}

// 404 to Homepage Redirect
if (get_option('psc_redirect_404_to_home', 'no') === 'yes') {
    add_action('template_redirect', 'psc_redirect_404_to_home_action');
}

function psc_redirect_404_to_home_action() {
    if (is_404()) {
        // Capture the requested URL
        $requested_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

        // Load logs
        $logs = get_option('psc_404_logs', array());
        if (!is_array($logs)) $logs = array();

        // Update log entry
        if (isset($logs[$requested_url])) {
            $logs[$requested_url]['hits'] = isset($logs[$requested_url]['hits']) ? $logs[$requested_url]['hits'] + 1 : 1;
            $logs[$requested_url]['last_hit'] = current_time('mysql');
        } else {
            // Keep array size manageable to prevent DB bloat
            if (count($logs) > 500) {
                array_shift($logs);
            }
            $logs[$requested_url] = array(
                'hits' => 1,
                'last_hit' => current_time('mysql'),
                'action' => 'home', // default action
                'custom_url' => ''
            );
        }

        update_option('psc_404_logs', $logs, false);

        // Execute action based on log setting
        $action = $logs[$requested_url]['action'];
        if ($action === 'keep') {
            return; // Don't redirect, stay as 404
        } elseif ($action === 'custom' && !empty($logs[$requested_url]['custom_url'])) {
            wp_redirect($logs[$requested_url]['custom_url'], 301);
            die();
        }

        // Default action: Redirect to home
        wp_redirect(home_url(), 301);
        die();
    }
}
