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

    // Check if allowed_plugins option is already set, otherwise initialize
    if (!get_option('allowed_plugins')) {
        update_option('allowed_plugins', $active_plugins);
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
            if ($plugin === 'plugin-security-check/plugin-security-check.php') {
                continue;
            }
            deactivate_plugins($plugin);
        }

        // Store the new plugins pending approval, excluding this plugin
        $pending_approval_plugins = get_option('pending_approval_plugins', array());
        $pending_approval_plugins = array_merge($pending_approval_plugins, array_diff($new_plugins, array('plugin-security-check/plugin-security-check.php')));
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
    if ($plugin === 'plugin-security-check/plugin-security-check.php') {
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
        if ($plugin === 'plugin-security-check/plugin-security-check.php') {
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
    // Remove the pending approval plugins option from the database
    delete_option('pending_approval_plugins');
}

// Disable daily plugin check
// No cron job scheduling for daily checks
// if (!wp_next_scheduled('daily_plugin_check_event')) {
//    wp_schedule_event(time(), 'daily', 'daily_plugin_check_event');
// }
// add_action('daily_plugin_check_event', 'check_for_unauthorized_plugins');
