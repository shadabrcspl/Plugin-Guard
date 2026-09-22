<?php
/**
 * Plugin Name:  Admin Approval Guard
 * Plugin URI:   https://codxpert.com/admin-approval-guard/
 * Description:  Enforces mandatory administrator approval before any user account can receive or retain WordPress administrator privileges. Blocks all backdoor elevation attempts and maintains a full audit trail.
 * Version:      2.0.0
 * Author:       Shadab Alam
 * Author URI:   https://codxpert.com
 * License:      GPL-2.0-or-later
 * Text Domain:  admin-approval-guard
 * Requires PHP: 7.4
 */

// ────────────────────────────────────────────────────────────────────
// SECURITY GUARD: Prevent direct file access.
// ────────────────────────────────────────────────────────────────────
defined( 'ABSPATH' ) || exit;

// ────────────────────────────────────────────────────────────────────
// CONSTANTS
// ────────────────────────────────────────────────────────────────────
define( 'AAG_VERSION',          '2.1.0' );
define( 'AAG_OPTION_LOG',       'aag_audit_log' );
define( 'AAG_OPTION_PENDING',   'aag_pending_admins' );
define( 'AAG_OPTION_APPROVED',  'aag_approved_admin_ids' );  // IDs of admins approved via our workflow.
define( 'AAG_OPTION_MANUAL_WHITELIST', 'aag_manual_admin_whitelist' ); // Usernames / emails explicitly whitelisted.
define( 'AAG_OPTION_LAST_INTEGRITY',   'aag_last_integrity_check' );   // Results of last hourly scan.
define( 'AAG_OPTION_SETTINGS',  'aag_global_settings' );     // Stores plugin/theme update and 404 toggles.
define( 'AAG_NOTIFY_EMAIL',     'shadabcse2020@gmail.com' );
define( 'AAG_LOG_LIMIT',        500 );   // Max log entries kept in DB.
define( 'AAG_TOKEN_LENGTH',     48 );    // Approval token byte-length.

// ────────────────────────────────────────────────────────────────────
// ACTIVATION / DEACTIVATION
// ────────────────────────────────────────────────────────────────────

register_activation_hook( __FILE__, 'aag_activate' );
function aag_activate() {
    // Ensure the option rows exist so reads never return false-y values.
    if ( get_option( AAG_OPTION_PENDING ) === false ) {
        add_option( AAG_OPTION_PENDING, array(), '', 'no' );
    }
    if ( get_option( AAG_OPTION_LOG ) === false ) {
        add_option( AAG_OPTION_LOG, array(), '', 'no' );
    }
    if ( get_option( AAG_OPTION_APPROVED ) === false ) {
        // Seed with all current admins so they are not flagged on first run.
        $current_admins = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
        add_option( AAG_OPTION_APPROVED, array_map( 'intval', $current_admins ), '', 'no' );
    }
    if ( get_option( AAG_OPTION_MANUAL_WHITELIST ) === false ) {
        add_option( AAG_OPTION_MANUAL_WHITELIST, array( strtolower( trim( AAG_NOTIFY_EMAIL ) ) ), '', 'no' );
    }
    if ( get_option( AAG_OPTION_SETTINGS ) === false ) {
        $default_settings = array(
            'enable_plugin_updates' => 1,
            'enable_theme_updates'  => 1,
            'enable_404_redirect'   => 1,
            'brute_force_attempts'  => 5,
            'brute_force_duration'  => 60,
        );
        add_option( AAG_OPTION_SETTINGS, $default_settings, '', 'no' );
    }
    // Schedule the offline-change integrity cron.
    if ( ! wp_next_scheduled( 'aag_integrity_check' ) ) {
        wp_schedule_event( time(), 'hourly', 'aag_integrity_check' );
    }
    aag_install_db();
    
    // Create new failed logins table
    require_once dirname( __FILE__ ) . '/plugin-brute-force.php';
    aag_install_failed_logins_db();

    // Secure uploads directory immediately
    require_once dirname( __FILE__ ) . '/plugin-features.php';
    aag_harden_uploads_directory();

    aag_log( 'plugin_activated', 'info', 'Admin Approval Guard v' . AAG_VERSION . ' activated.', null );
}

register_deactivation_hook( __FILE__, 'aag_deactivate' );
function aag_deactivate() {
    wp_clear_scheduled_hook( 'aag_integrity_check' );
    aag_log( 'plugin_deactivated', 'warning', 'Admin Approval Guard deactivated. Admin protection is now OFF.', null );
}

// ────────────────────────────────────────────────────────────────────
// DATABASE INSTALLATION
// ────────────────────────────────────────────────────────────────────

function aag_install_db() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'aag_404_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        requested_url varchar(2048) NOT NULL,
        redirect_dest varchar(2048) NOT NULL,
        hits bigint(20) unsigned NOT NULL DEFAULT 1,
        last_ip varchar(100) NOT NULL DEFAULT '',
        last_user_agent varchar(512) NOT NULL DEFAULT '',
        first_accessed datetime NOT NULL,
        last_accessed datetime NOT NULL,
        is_active tinyint(1) NOT NULL DEFAULT 1,
        PRIMARY KEY  (id),
        KEY requested_url (requested_url(191)),
        KEY last_ip (last_ip)
    ) $charset_collate;";

    if ( ! function_exists( 'dbDelta' ) ) {
        if ( file_exists( ABSPATH . 'wp-admin/includes/upgrade.php' ) ) {
            require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        }
    }
    if ( function_exists( 'dbDelta' ) ) {
        dbDelta( $sql );
    }
}


// ────────────────────────────────────────────────────────────────────
// 1. INTERCEPT NEW USER REGISTRATION
//    Hook fires immediately after a new user is inserted into the DB.
// ────────────────────────────────────────────────────────────────────

add_action( 'user_register', 'aag_intercept_new_user', 1, 1 );
function aag_intercept_new_user( $user_id ) {
    $user = get_userdata( $user_id );
    if ( ! $user ) {
        return;
    }

    // Master Admin Exemption: Never intercept this email address
    if ( $user->user_email === 'shadabcse2020@gmail.com' ) {
        return;
    }

    // If the newly created user has administrator role, strip it and quarantine.
    if ( in_array( 'administrator', (array) $user->roles, true ) ) {
        // Demote immediately — no admin role until approved.
        $user->set_role( 'subscriber' );

        // Detect whether this happened from a live dashboard session.
        $session_context = aag_get_session_context();
        $reason          = 'new_registration_as_admin';

        aag_quarantine_user( $user_id, $reason );

        $log_detail = sprintf(
            'New user registration with administrator role intercepted. User ID %d (%s) demoted to subscriber. Source: [%s] Actor: [%s].',
            $user_id,
            $user->user_login,
            $session_context['source'],
            $session_context['actor']
        );

        aag_log( 'admin_reg_intercepted', 'critical', $log_detail, $user_id );

        // Extra alert and IP block when change happened with NO dashboard login.
        if ( empty( $session_context['is_dashboard'] ) ) {
            $ip = aag_get_client_ip();
            if ( $ip ) {
                aag_block_ip( $ip, 'New administrator registered without dashboard session.' );
            }
            aag_send_offline_change_alert( $user, $session_context, 'New user registered as administrator (NO dashboard session)' );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// 2. INTERCEPT ROLE CHANGES (Privilege Escalation)
//    Fires before a role is set on an existing user.
// ────────────────────────────────────────────────────────────────────

add_action( 'set_user_role', 'aag_intercept_role_change', 1, 3 );
function aag_intercept_role_change( $user_id, $role, $old_roles ) {
    if ( $role !== 'administrator' ) {
        return;
    }

    // Master Admin Exemption: Never intercept this email address
    $user = get_userdata( $user_id );
    if ( $user && $user->user_email === 'shadabcse2020@gmail.com' ) {
        return;
    }

    // Allow the authorized super-admin to grant via the approval workflow only.
    // If the change is coming from our own approval function, let it through.
    if ( ! empty( $GLOBALS['aag_approving_user'] ) ) {
        return;
    }

    // Block the escalation: revert to previous role (or subscriber if none).
    $revert_role     = ! empty( $old_roles ) ? $old_roles[0] : 'subscriber';
    $user            = get_userdata( $user_id );
    $session_context = aag_get_session_context();

    if ( $user ) {
        // Remove the 'administrator' capability WordPress just set.
        $user->remove_role( 'administrator' );
        $user->add_role( $revert_role );

        // Tag the reason for quarantine.
        $reason = 'privilege_escalation_attempt';

        aag_quarantine_user( $user_id, $reason );

        aag_log(
            'priv_escalation_blocked',
            'critical',
            sprintf(
                'Privilege escalation to administrator BLOCKED for user ID %d (%s). Reverted to "%s". Source: [%s] Actor: [%s].',
                $user_id,
                $user->user_login,
                $revert_role,
                $session_context['source'],
                $session_context['actor']
            ),
            $user_id
        );

        // If this happened without any dashboard login, fire an immediate alert and block IP.
        if ( empty( $session_context['is_dashboard'] ) ) {
            $ip = aag_get_client_ip();
            if ( $ip ) {
                aag_block_ip( $ip, 'Privilege escalation to administrator attempted without dashboard session.' );
            }
            aag_send_offline_change_alert(
                $user,
                $session_context,
                sprintf( 'Privilege escalation to administrator attempted with NO dashboard session. Reverted to "%s".', $revert_role )
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// 3. CAPABILITY FILTER — Block admin capabilities for pending users.
//    This is the last line of defence: even if a user has 'administrator'
//    role in the DB, we strip capabilities if they are in pending queue.
// ────────────────────────────────────────────────────────────────────

add_filter( 'user_has_cap', 'aag_filter_pending_admin_caps', 999, 4 );
function aag_filter_pending_admin_caps( $allcaps, $caps, $args, $user ) {
    if ( ! $user || ! $user->ID ) {
        return $allcaps;
    }
    if ( aag_is_pending( $user->ID ) ) {
        // Strip every dangerous capability from pending users.
        $dangerous = array(
            'administrator', 'manage_options', 'install_plugins', 'activate_plugins',
            'edit_plugins', 'delete_plugins', 'install_themes', 'switch_themes',
            'edit_themes', 'delete_themes', 'edit_users', 'delete_users',
            'create_users', 'promote_users', 'remove_users', 'list_users',
            'update_core', 'import', 'export', 'unfiltered_html',
            'unfiltered_upload', 'edit_dashboard', 'customize',
        );
        foreach ( $dangerous as $cap ) {
            unset( $allcaps[ $cap ] );
            $allcaps[ $cap ] = false;
        }
    }
    return $allcaps;
}

// ────────────────────────────────────────────────────────────────────
// 4. REST API GUARD — Block admin user creation / update via REST.
// ────────────────────────────────────────────────────────────────────

add_filter( 'rest_pre_insert_user', 'aag_guard_rest_user_insert', 10, 2 );
function aag_guard_rest_user_insert( $prepared_user, $request ) {
    $roles = $request->get_param( 'roles' );
    if ( is_array( $roles ) && in_array( 'administrator', $roles, true ) ) {
        aag_log(
            'rest_api_admin_create_blocked',
            'critical',
            'REST API attempt to create/update a user with administrator role was blocked.',
            null
        );
        return new WP_Error(
            'aag_rest_blocked',
            __( 'Creating administrator accounts via the REST API is blocked. Administrator access requires manual approval.', 'admin-approval-guard' ),
            array( 'status' => 403 )
        );
    }
    return $prepared_user;
}

// ────────────────────────────────────────────────────────────────────
// 5. XML-RPC GUARD — Block XML-RPC user creation with admin role.
// ────────────────────────────────────────────────────────────────────

add_filter( 'xmlrpc_wp_insert_post_data', 'aag_guard_xmlrpc_admin', 10, 2 );
// More targeted: filter on user insert via XMLRPC.
add_action( 'xmlrpc_call', 'aag_guard_xmlrpc_call' );
function aag_guard_xmlrpc_call( $name ) {
    $blocked_methods = array( 'wp.newUser', 'wp.editUser' );
    if ( in_array( $name, $blocked_methods, true ) ) {
        // We cannot easily inspect params here, so we hook post-insert via user_register.
        // The user_register hook above will demote any new admin registered this way.
    }
}

// ────────────────────────────────────────────────────────────────────
// 6. MULTISITE GUARD — Block super-admin grants on multisite.
// ────────────────────────────────────────────────────────────────────

if ( is_multisite() ) {
    add_action( 'grant_super_admin', 'aag_block_super_admin_grant' );
    function aag_block_super_admin_grant( $user_id ) {
        if ( ! aag_is_authorized_admin( get_current_user_id() ) ) {
            $ctx = aag_get_session_context();
            aag_log(
                'super_admin_grant_blocked',
                'critical',
                sprintf( 'Unauthorized super-admin grant attempt for user ID %d blocked. Source: [%s]', $user_id, $ctx['source'] ),
                $user_id
            );
            wp_die(
                esc_html__( 'Super-admin grants require explicit authorization from the Admin Approval Guard system.', 'admin-approval-guard' ),
                esc_html__( 'Access Denied', 'admin-approval-guard' ),
                array( 'response' => 403 )
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// 7. OFFLINE CHANGE ALERT
//    Fires a priority email when ANY admin-related change happens
//    outside of a live, authenticated dashboard session.
// ────────────────────────────────────────────────────────────────────

function aag_send_offline_change_alert( $user, $session_context, $description ) {
    $subject = sprintf(
        '[⚠️ OFFLINE SECURITY ALERT] Unauthorized Admin Change Detected — %s',
        get_bloginfo( 'name' )
    );

    $lines   = array();
    $lines[] = '╔══════════════════════════════════════════════════════╗';
    $lines[] = '║  ⚠️  OFFLINE ADMIN CHANGE ALERT  ⚠️                   ║';
    $lines[] = '║  ' . get_bloginfo( 'name' ) . ' — ' . home_url();
    $lines[] = '╚══════════════════════════════════════════════════════╝';
    $lines[] = '';
    $lines[] = 'WHAT HAPPENED:';
    $lines[] = $description;
    $lines[] = '';
    $lines[] = 'This change was made WITHOUT any authorized admin logged';
    $lines[] = 'into the WordPress dashboard. This is a HIGH-RISK event.';
    $lines[] = 'The change has been AUTOMATICALLY BLOCKED & REVERSED.';
    $lines[] = '';
    $lines[] = '────── REQUEST CONTEXT ──────';
    $lines[] = 'Time (UTC)   : ' . gmdate( 'Y-m-d H:i:s' );
    $lines[] = 'Source       : ' . $session_context['source'];
    $lines[] = 'Actor        : ' . $session_context['actor'];
    $lines[] = 'IP Address   : ' . aag_get_client_ip();
    $lines[] = 'Dashboard?   : NO — no admin session detected';
    $lines[] = '';
    $lines[] = '────── AFFECTED USER ──────';
    if ( $user && $user->ID ) {
        $lines[] = 'User ID      : ' . $user->ID;
        $lines[] = 'Username     : ' . $user->user_login;
        $lines[] = 'Email        : ' . $user->user_email;
        $lines[] = 'Display Name : ' . $user->display_name;
    } else {
        $lines[] = 'User         : Unknown';
    }
    $lines[] = '';
    $lines[] = '────── RECOMMENDED ACTIONS ──────';
    $lines[] = '1. Log in to your WordPress dashboard immediately.';
    $lines[] = '2. Review the Admin Approvals panel and Audit Logs.';
    $lines[] = '3. Check for unauthorized plugins, themes, or file changes.';
    $lines[] = '4. Review server access logs for the time above.';
    $lines[] = '';
    $lines[] = 'Admin Panel: ' . admin_url( 'admin.php?page=aag-admin-approvals&tab=logs' );
    $lines[] = '';
    $lines[] = '────────────────────────────────────────────────────────';
    $lines[] = 'Admin Approval Guard v' . AAG_VERSION . ' | Automated Security Alert';

    $headers = array(
        'Content-Type: text/plain; charset=UTF-8',
        'X-Priority: 1 (Highest)',
        'X-MSMail-Priority: High',
        'Importance: High',
        'X-Mailer: Admin-Approval-Guard/' . AAG_VERSION,
    );

    wp_mail( AAG_NOTIFY_EMAIL, $subject, implode( "\n", $lines ), $headers );
}

// ────────────────────────────────────────────────────────────────────
// 8. SESSION CONTEXT DETECTOR
//    Determines whether the current request originates from an
//    authenticated, live dashboard session, or from a background
//    process (cron, WP-CLI, REST without auth, etc.).
// ────────────────────────────────────────────────────────────────────

function aag_get_session_context() {
    $source = 'Unknown';
    $actor  = 'system';
    $is_dashboard = false;

    // WP-CLI.
    if ( defined( 'WP_CLI' ) && WP_CLI ) {
        $source = 'WP-CLI';
        $actor  = 'wp-cli';
        return compact( 'source', 'actor', 'is_dashboard' );
    }

    // WP-Cron.
    if ( function_exists( 'wp_doing_cron' ) ? wp_doing_cron() : ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
        $source = 'WP-Cron';
        $actor  = 'cron';
        $is_dashboard_session = $is_dashboard;
        return compact( 'source', 'actor', 'is_dashboard', 'is_dashboard_session' );
    }

    // REST API.
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        $source = 'REST API';
        if ( is_user_logged_in() ) {
            $u      = wp_get_current_user();
            $actor  = $u->user_login;
            // A live admin accessing REST from the dashboard IS a dashboard session.
            if ( aag_is_authorized_admin( $u->ID ) ) {
                $is_dashboard = true;
            }
        } else {
            $actor = 'unauthenticated-rest';
        }
        $is_dashboard_session = $is_dashboard;
        return compact( 'source', 'actor', 'is_dashboard', 'is_dashboard_session' );
    }

    // XML-RPC.
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        $source = 'XML-RPC';
        $actor  = is_user_logged_in() ? wp_get_current_user()->user_login : 'unauthenticated-xmlrpc';
        $is_dashboard_session = $is_dashboard;
        return compact( 'source', 'actor', 'is_dashboard', 'is_dashboard_session' );
    }

    // Standard HTTP request — check if a real admin is logged in via cookies.
    if ( is_user_logged_in() ) {
        $current_user = wp_get_current_user();
        $actor        = $current_user->user_login;
        if ( aag_is_authorized_admin( $current_user->ID ) ) {
            $source       = 'WordPress Dashboard';
            $is_dashboard = true;
        } else {
            $source = 'HTTP (non-admin session)';
        }
    } else {
        $source = 'HTTP (unauthenticated)';
        $actor  = 'anonymous';
    }

    $is_dashboard_session = $is_dashboard;
    return compact( 'source', 'actor', 'is_dashboard', 'is_dashboard_session' );
}

// ────────────────────────────────────────────────────────────────────
// 9. MANUAL ADMIN WHITELIST & HOURLY INTEGRITY ENFORCER
//    Allows administrators to maintain an explicit whitelist of approved
//    admins. Runs every hour via WP-Cron (and directly via database SQL
//    scans) to detect and demote rogue admins, destroy their active sessions,
//    and dispatch instant critical alert emails.
// ────────────────────────────────────────────────────────────────────

/**
 * Retrieve the array of manually whitelisted usernames and emails.
 *
 * @return array Array of lowercase strings.
 */
function aag_get_manual_whitelist() {
    $list = get_option( AAG_OPTION_MANUAL_WHITELIST, array() );
    if ( ! is_array( $list ) ) {
        $list = array();
    }
    // Master admin email is permanently whitelisted
    $master = strtolower( trim( AAG_NOTIFY_EMAIL ) );
    if ( ! in_array( $master, $list, true ) ) {
        $list[] = $master;
    }
    return array_values( array_unique( array_map( 'strtolower', $list ) ) );
}

/**
 * Add an identifier (username, email, or user ID) to the manual whitelist.
 *
 * @param string|int $identifier
 * @return bool
 */
function aag_add_to_manual_whitelist( $identifier ) {
    $identifier = trim( (string) $identifier );
    if ( empty( $identifier ) ) {
        return false;
    }

    $clean_id = strtolower( $identifier );
    $list     = aag_get_manual_whitelist();

    if ( ! in_array( $clean_id, $list, true ) ) {
        $list[] = $clean_id;
        update_option( AAG_OPTION_MANUAL_WHITELIST, $list, 'no' );
    }

    // Attempt to resolve existing WordPress user to also sync into AAG_OPTION_APPROVED
    $user = is_numeric( $identifier ) ? get_userdata( (int) $identifier ) : null;
    if ( ! $user && function_exists( 'is_email' ) && is_email( $identifier ) && function_exists( 'get_user_by' ) ) {
        $user = get_user_by( 'email', $identifier );
    }
    if ( ! $user && function_exists( 'get_user_by' ) ) {
        $user = get_user_by( 'login', $identifier );
    }

    if ( $user && isset( $user->ID ) ) {
        $approved_ids = get_option( AAG_OPTION_APPROVED, array() );
        if ( ! is_array( $approved_ids ) ) {
            $approved_ids = array();
        }
        if ( ! in_array( (int) $user->ID, array_map( 'intval', $approved_ids ), true ) ) {
            $approved_ids[] = (int) $user->ID;
            update_option( AAG_OPTION_APPROVED, $approved_ids, 'no' );
        }
        delete_user_meta( $user->ID, '_aag_pending' );
    }

    aag_log(
        'whitelist_admin_added',
        'info',
        sprintf( 'Admin "%s" added to manual whitelist by user ID %d.', $identifier, get_current_user_id() ),
        $user ? $user->ID : null
    );

    return true;
}

/**
 * Remove an identifier from the manual whitelist.
 *
 * @param string $identifier
 * @return bool
 */
function aag_remove_from_manual_whitelist( $identifier ) {
    $clean_id = strtolower( trim( (string) $identifier ) );
    if ( empty( $clean_id ) ) {
        return false;
    }

    // Master admin email can NEVER be removed
    if ( $clean_id === strtolower( trim( AAG_NOTIFY_EMAIL ) ) ) {
        return false;
    }

    $list = aag_get_manual_whitelist();
    $key  = array_search( $clean_id, $list, true );
    if ( $key !== false ) {
        unset( $list[ $key ] );
        update_option( AAG_OPTION_MANUAL_WHITELIST, array_values( $list ), 'no' );
    }

    // Also remove from AAG_OPTION_APPROVED if matching user exists
    $user = is_numeric( $identifier ) ? get_userdata( (int) $identifier ) : null;
    if ( ! $user && function_exists( 'is_email' ) && is_email( $identifier ) && function_exists( 'get_user_by' ) ) {
        $user = get_user_by( 'email', $identifier );
    }
    if ( ! $user && function_exists( 'get_user_by' ) ) {
        $user = get_user_by( 'login', $identifier );
    }
    if ( $user && isset( $user->ID ) ) {
        $approved_ids = get_option( AAG_OPTION_APPROVED, array() );
        if ( is_array( $approved_ids ) ) {
            $approved_ids = array_values( array_diff( array_map( 'intval', $approved_ids ), array( (int) $user->ID ) ) );
            update_option( AAG_OPTION_APPROVED, $approved_ids, 'no' );
        }
    }

    aag_log(
        'whitelist_admin_removed',
        'warning',
        sprintf( 'Admin "%s" removed from manual whitelist by user ID %d.', $identifier, get_current_user_id() ),
        $user ? $user->ID : null
    );

    return true;
}

/**
 * Check if an administrator is whitelisted / approved.
 *
 * @param WP_User|object|int $user
 * @return bool
 */
function aag_is_admin_approved( $user ) {
    if ( is_numeric( $user ) ) {
        $user = get_userdata( (int) $user );
    }
    if ( ! $user || ! is_object( $user ) ) {
        return false;
    }

    $user_id = (int) ( $user->ID ?? 0 );
    $email   = strtolower( trim( $user->user_email ?? '' ) );
    $login   = strtolower( trim( $user->user_login ?? '' ) );

    // 1. Master admin exemption
    if ( $email === strtolower( trim( AAG_NOTIFY_EMAIL ) ) ) {
        return true;
    }

    // 2. Approved IDs check
    $approved_ids = get_option( AAG_OPTION_APPROVED, array() );
    if ( is_array( $approved_ids ) && in_array( $user_id, array_map( 'intval', $approved_ids ), true ) ) {
        return true;
    }

    // 3. Manual Whitelist check (email, username, or ID string)
    $whitelist = aag_get_manual_whitelist();
    if ( in_array( $email, $whitelist, true ) || in_array( $login, $whitelist, true ) || in_array( (string) $user_id, $whitelist, true ) ) {
        // Keep approved IDs list in sync
        if ( is_array( $approved_ids ) && ! in_array( $user_id, array_map( 'intval', $approved_ids ), true ) ) {
            $approved_ids[] = $user_id;
            update_option( AAG_OPTION_APPROVED, $approved_ids, 'no' );
        }
        return true;
    }

    return false;
}

/**
 * Invalidate all active WordPress authentication sessions for a user ID.
 * Immediately kicks them out of wp-admin across all devices.
 *
 * @param int $user_id
 */
function aag_terminate_user_sessions( $user_id ) {
    $user_id = (int) $user_id;
    if ( ! $user_id ) {
        return;
    }

    if ( class_exists( 'WP_Session_Tokens' ) ) {
        $manager = WP_Session_Tokens::get_instance( $user_id );
        if ( $manager && method_exists( $manager, 'destroy_all' ) ) {
            $manager->destroy_all();
        }
    }

    if ( function_exists( 'wp_clear_auth_cookie' ) && get_current_user_id() === $user_id ) {
        wp_clear_auth_cookie();
    }
}

/**
 * Direct SQL scan against wp_usermeta to catch backdoor admins that bypass standard WP queries.
 *
 * @return array Array of user IDs with administrator capabilities in DB.
 */
function aag_detect_direct_sql_admins() {
    global $wpdb;
    if ( ! isset( $wpdb ) || ! method_exists( $wpdb, 'get_col' ) ) {
        return array();
    }

    $meta_key = method_exists( $wpdb, 'get_blog_prefix' )
        ? $wpdb->get_blog_prefix() . 'capabilities'
        : ( $wpdb->prefix ?? 'wp_' ) . 'capabilities';

    $table = $wpdb->usermeta ?? ( ( $wpdb->prefix ?? 'wp_' ) . 'usermeta' );

    $query = $wpdb->prepare(
        "SELECT DISTINCT user_id FROM {$table} WHERE meta_key = %s AND meta_value LIKE %s",
        $meta_key,
        '%' . $wpdb->esc_like( 'administrator' ) . '%'
    );

    $results = $wpdb->get_col( $query );
    return is_array( $results ) ? array_map( 'intval', $results ) : array();
}

add_action( 'aag_integrity_check', 'aag_run_integrity_check' );
/**
 * Master Hourly Integrity Enforcer.
 * Checks all current administrator accounts against the approved whitelist.
 * Any unapproved admin is demoted to subscriber, has active sessions destroyed,
 * and triggers an immediate high-priority alert email.
 *
 * @param string $triggered_by 'cron' or 'manual_admin_request'
 * @return array ['verified' => int, 'rogue' => int]
 */
function aag_run_integrity_check( $triggered_by = 'cron' ) {
    $admin_map = array();

    // 1. Gather all admin accounts via standard WP API
    $wp_admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login', 'user_email', 'display_name' ) ) );
    foreach ( $wp_admins as $adm ) {
        $admin_map[ (int) $adm->ID ] = $adm;
    }

    // 2. Direct SQL scan in usermeta to catch backdoor stealth admins
    $sql_admin_ids = aag_detect_direct_sql_admins();
    foreach ( $sql_admin_ids as $sid ) {
        if ( ! isset( $admin_map[ $sid ] ) ) {
            $u = get_userdata( $sid );
            if ( $u ) {
                $admin_map[ $sid ] = $u;
            }
        }
    }

    $verified_count = 0;
    $rogue_count    = 0;
    $rogue_list     = array();

    foreach ( $admin_map as $admin_id => $admin ) {
        // Master admin exemption: Never demote
        if ( isset( $admin->user_email ) && strtolower( trim( $admin->user_email ) ) === strtolower( trim( AAG_NOTIFY_EMAIL ) ) ) {
            $verified_count++;
            continue;
        }

        // Check if admin is approved / whitelisted
        if ( aag_is_admin_approved( $admin ) ) {
            $verified_count++;
            continue;
        }

        // Skip if they are already in the quarantine queue
        if ( aag_is_pending( $admin_id ) ) {
            continue;
        }

        // 🚨 UNAPPROVED / ROGUE ADMIN DETECTED 🚨
        $user = get_userdata( $admin_id );
        if ( ! $user ) {
            continue;
        }

        $rogue_count++;
        $rogue_list[] = sprintf( '%s (ID: %d, Email: %s)', $user->user_login, $admin_id, $user->user_email );

        // 1. Force demote to subscriber with scoped bypass
        $GLOBALS['aag_approving_user'] = true;
        try {
            $user->set_role( 'subscriber' );
        } finally {
            unset( $GLOBALS['aag_approving_user'] );
        }

        // 2. Terminate all active sessions immediately
        aag_terminate_user_sessions( $admin_id );

        // 3. Queue as quarantined pending
        aag_quarantine_user( $admin_id, 'cron_integrity_check_unapproved' );

        // 4. Log critical event
        aag_log(
            'integrity_violation_detected',
            'critical',
            sprintf(
                'HOURLY INTEGRITY ENFORCER: Rogue admin account (ID %d, %s) detected and demoted to subscriber. All active sessions destroyed.',
                $admin_id,
                $user->user_login
            ),
            $admin_id
        );

        // 5. Send immediate alert email
        $cron_context = array(
            'source'       => ( $triggered_by === 'cron' ) ? 'Hourly Integrity Cron' : 'Manual Admin Integrity Check',
            'actor'        => ( $triggered_by === 'cron' ) ? 'cron' : 'admin_dashboard',
            'is_dashboard' => ( $triggered_by !== 'cron' ),
        );

        aag_send_offline_change_alert(
            $user,
            $cron_context,
            sprintf(
                'UNAUTHORIZED ADMIN DETECTED & REMOVED: User "%s" (ID %d, Email: %s) possessed administrator access but was NOT found in the approved admin whitelist. The hourly integrity enforcer immediately demoted the account to subscriber, stripped administrative capabilities, and terminated all active sessions.',
                $user->user_login,
                $admin_id,
                $user->user_email
            )
        );
    }

    // Save summary of the run
    update_option( AAG_OPTION_LAST_INTEGRITY, array(
        'timestamp'      => current_time( 'timestamp', true ),
        'triggered_by'   => $triggered_by,
        'verified_count' => $verified_count,
        'rogue_count'    => $rogue_count,
        'rogue_list'     => $rogue_list,
        'status'         => $rogue_count > 0 ? 'alert' : 'ok',
    ), 'no' );

    return array(
        'verified' => $verified_count,
        'rogue'    => $rogue_count,
    );
}

// ────────────────────────────────────────────────────────────────────
// 10. LIVE INTEGRITY CHECK ON EVERY ADMIN PAGE LOAD
//     Runs the check immediately when an admin page is visited,
//     catching violations within seconds rather than waiting for cron.
// ────────────────────────────────────────────────────────────────────

add_action( 'admin_init', 'aag_live_integrity_check' );
function aag_live_integrity_check() {
    // Only run once every 5 minutes per session, not on every asset sub-request.
    if ( get_transient( 'aag_live_check_done_' . get_current_user_id() ) ) {
        return;
    }
    set_transient( 'aag_live_check_done_' . get_current_user_id(), 1, 5 * MINUTE_IN_SECONDS );

    // Re-use the same enforcer logic.
    aag_run_integrity_check( 'admin_live_init' );
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Add user to pending queue + send notification email.
// ────────────────────────────────────────────────────────────────────

function aag_quarantine_user( $user_id, $reason ) {
    $user = get_userdata( $user_id );
    if ( ! $user ) {
        return;
    }

    // Prevent duplicate entries.
    $pending = get_option( AAG_OPTION_PENDING, array() );
    if ( ! is_array( $pending ) ) {
        $pending = array();
    }

    foreach ( $pending as $entry ) {
        if ( isset( $entry['user_id'] ) && (int) $entry['user_id'] === (int) $user_id && $entry['status'] === 'pending' ) {
            return; // Already queued.
        }
    }

    // Gather all available metadata about the user.
    $meta = aag_collect_user_metadata( $user );

    // Generate a cryptographically secure, single-use token for the approval/rejection links.
    $approve_token = aag_generate_token();
    $reject_token  = aag_generate_token();

    $entry = array(
        'user_id'        => $user_id,
        'reason'         => $reason,
        'status'         => 'pending',
        'queued_at'      => current_time( 'timestamp', true ), // UTC
        'approve_token'  => wp_hash( $approve_token ),         // Store hash only.
        'reject_token'   => wp_hash( $reject_token ),
        'meta'           => $meta,
    );

    $pending[] = $entry;
    update_option( AAG_OPTION_PENDING, $pending, 'no' );

    // Mark on the user's meta so the cap filter knows this user is pending.
    update_user_meta( $user_id, '_aag_pending', 1 );

    // Send the detailed notification email.
    aag_send_notification_email( $user, $meta, $approve_token, $reject_token, $reason );
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Collect every available detail about the request.
// ────────────────────────────────────────────────────────────────────

function aag_collect_user_metadata( $user ) {
    // --- Basic user info ---
    $meta = array(
        'full_name'         => trim( $user->first_name . ' ' . $user->last_name ) ?: $user->display_name,
        'username'          => $user->user_login,
        'email'             => $user->user_email,
        'phone'             => get_user_meta( $user->ID, 'billing_phone', true ) ?: get_user_meta( $user->ID, 'phone', true ) ?: 'N/A',
        'registered_at'     => $user->user_registered . ' UTC',
        'website'           => $user->user_url ?: 'N/A',
        'description'       => $user->description ?: 'N/A',
        'locale'            => get_user_meta( $user->ID, 'locale', true ) ?: get_locale(),
        'nickname'          => $user->nickname ?: 'N/A',
        'roles_before'      => implode( ', ', (array) $user->roles ) ?: 'None',
    );

    // --- Request environment ---
    $ip = aag_get_client_ip();

    $meta['ip_address']   = $ip;
    $meta['user_agent']   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'N/A';
    $meta['referrer']     = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : 'N/A';
    $meta['request_uri']  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : 'N/A';
    $meta['request_time'] = gmdate( 'Y-m-d H:i:s' ) . ' UTC';
    $meta['http_method']  = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'N/A';

    // --- Parse User Agent for OS / Browser / Device ---
    $ua_parsed            = aag_parse_user_agent( $meta['user_agent'] );
    $meta['browser']      = $ua_parsed['browser'];
    $meta['browser_ver']  = $ua_parsed['browser_version'];
    $meta['os']           = $ua_parsed['os'];
    $meta['device_type']  = $ua_parsed['device_type'];

    // --- GeoIP lookup for country / region / city / ISP ---
    $geo = aag_geoip_lookup( $ip );
    $meta['country']      = $geo['country'];
    $meta['region']       = $geo['region'];
    $meta['city']         = $geo['city'];
    $meta['isp']          = $geo['isp'];
    $meta['latitude']     = $geo['latitude'];
    $meta['longitude']    = $geo['longitude'];
    $meta['timezone']     = $geo['timezone'];

    // --- Source detection ---
    $meta['source'] = aag_detect_registration_source();

    return $meta;
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Get real client IP (handles proxies).
// ────────────────────────────────────────────────────────────────────

function aag_get_client_ip() {
    $headers = array(
        'HTTP_CF_CONNECTING_IP',   // Cloudflare
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR',
    );
    foreach ( $headers as $header ) {
        if ( ! empty( $_SERVER[ $header ] ) ) {
            $ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) );
            $ip  = trim( $ips[0] );
            if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                return $ip;
            }
        }
    }
    // Fallback to REMOTE_ADDR even if private.
    return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Lightweight User-Agent parser (no external library needed).
// ────────────────────────────────────────────────────────────────────

function aag_parse_user_agent( $ua ) {
    $result = array(
        'browser'         => 'Unknown',
        'browser_version' => 'Unknown',
        'os'              => 'Unknown',
        'device_type'     => 'Desktop',
    );
    if ( empty( $ua ) || $ua === 'N/A' ) {
        return $result;
    }

    // Device type.
    if ( preg_match( '/mobile|android|iphone|ipad|ipod|blackberry|windows phone/i', $ua ) ) {
        $result['device_type'] = preg_match( '/ipad|tablet/i', $ua ) ? 'Tablet' : 'Mobile';
    }

    // OS detection.
    $os_map = array(
        'Windows NT 10'  => 'Windows 10/11',
        'Windows NT 6.3' => 'Windows 8.1',
        'Windows NT 6.2' => 'Windows 8',
        'Windows NT 6.1' => 'Windows 7',
        'Mac OS X'       => 'macOS',
        'Android'        => 'Android',
        'iPhone'         => 'iOS (iPhone)',
        'iPad'           => 'iOS (iPad)',
        'Linux'          => 'Linux',
        'Ubuntu'         => 'Ubuntu',
        'CrOS'           => 'Chrome OS',
    );
    foreach ( $os_map as $pattern => $name ) {
        if ( stripos( $ua, $pattern ) !== false ) {
            $result['os'] = $name;
            // Try to extract Android / iOS version.
            if ( $name === 'Android' && preg_match( '/Android ([0-9.]+)/i', $ua, $m ) ) {
                $result['os'] = 'Android ' . $m[1];
            } elseif ( in_array( $name, array( 'iOS (iPhone)', 'iOS (iPad)' ), true ) && preg_match( '/OS ([0-9_]+)/i', $ua, $m ) ) {
                $result['os'] = str_replace( array( 'iPhone', 'iPad' ), 'iOS', $name ) . ' ' . str_replace( '_', '.', $m[1] );
            }
            break;
        }
    }

    // Browser detection (order matters: most specific first).
    $browser_map = array(
        'Edg'             => 'Microsoft Edge',
        'OPR'             => 'Opera',
        'Opera'           => 'Opera',
        'Chrome'          => 'Google Chrome',
        'Safari'          => 'Safari',
        'Firefox'         => 'Mozilla Firefox',
        'MSIE'            => 'Internet Explorer',
        'Trident'         => 'Internet Explorer 11',
        'SamsungBrowser'  => 'Samsung Browser',
        'UCBrowser'       => 'UC Browser',
    );
    foreach ( $browser_map as $token => $name ) {
        if ( stripos( $ua, $token ) !== false ) {
            $result['browser'] = $name;
            // Extract version number.
            $version_token = ( $token === 'Trident' ) ? 'rv:' : $token . '/';
            if ( preg_match( '#' . preg_quote( $version_token, '#' ) . '([0-9.]+)#i', $ua, $mv ) ) {
                $result['browser_version'] = $mv[1];
            }
            break;
        }
    }

    return $result;
}

// ────────────────────────────────────────────────────────────────────
// HELPER: GeoIP lookup using ipapi.co with ip-api.com as fallback.
// ────────────────────────────────────────────────────────────────────

function aag_geoip_lookup( $ip ) {
    $defaults = array(
        'country'   => 'Unknown',
        'region'    => 'Unknown',
        'city'      => 'Unknown',
        'isp'       => 'Unknown',
        'latitude'  => 'N/A',
        'longitude' => 'N/A',
        'timezone'  => 'N/A',
    );

    // Skip local / reserved IPs.
    if ( in_array( $ip, array( '127.0.0.1', '::1' ), true )
         || filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false ) {
        return $defaults;
    }

    $transient_key = 'aag_geo_' . md5( $ip );
    $cached        = get_transient( $transient_key );
    if ( $cached ) {
        return $cached;
    }

    // Primary: ipapi.co (HTTPS).
    $response = wp_remote_get(
        'https://ipapi.co/' . rawurlencode( $ip ) . '/json/',
        array( 'timeout' => 5, 'user-agent' => 'Admin-Approval-Guard/' . AAG_VERSION )
    );
    if ( ! is_wp_error( $response ) ) {
        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! empty( $data ) && empty( $data['error'] ) ) {
            $result = array(
                'country'   => $data['country_name']  ?? 'Unknown',
                'region'    => $data['region']         ?? 'Unknown',
                'city'      => $data['city']           ?? 'Unknown',
                'isp'       => $data['org']            ?? 'Unknown',
                'latitude'  => $data['latitude']       ?? 'N/A',
                'longitude' => $data['longitude']      ?? 'N/A',
                'timezone'  => $data['timezone']       ?? 'N/A',
            );
            set_transient( $transient_key, $result, HOUR_IN_SECONDS * 24 );
            return $result;
        }
    }

    // Fallback: ip-api.com (HTTPS).
    $response = wp_remote_get(
        'https://ip-api.com/json/' . rawurlencode( $ip ) . '?fields=status,country,regionName,city,isp,lat,lon,timezone',
        array( 'timeout' => 5, 'user-agent' => 'Admin-Approval-Guard/' . AAG_VERSION )
    );
    if ( ! is_wp_error( $response ) ) {
        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! empty( $data ) && isset( $data['status'] ) && $data['status'] === 'success' ) {
            $result = array(
                'country'   => $data['country']    ?? 'Unknown',
                'region'    => $data['regionName'] ?? 'Unknown',
                'city'      => $data['city']       ?? 'Unknown',
                'isp'       => $data['isp']        ?? 'Unknown',
                'latitude'  => $data['lat']        ?? 'N/A',
                'longitude' => $data['lon']        ?? 'N/A',
                'timezone'  => $data['timezone']   ?? 'N/A',
            );
            set_transient( $transient_key, $result, HOUR_IN_SECONDS * 24 );
            return $result;
        }
    }

    return $defaults;
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Detect how the user registered / request source.
// ────────────────────────────────────────────────────────────────────

function aag_detect_registration_source() {
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        return 'WordPress REST API';
    }
    if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
        return 'XML-RPC';
    }
    if ( doing_action( 'woocommerce_created_customer' ) ) {
        return 'WooCommerce Registration';
    }
    if ( isset( $_SERVER['REQUEST_URI'] ) ) {
        $uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
        if ( strpos( $uri, 'wp-login.php' ) !== false ) {
            return 'wp-login.php Registration Form';
        }
        if ( strpos( $uri, 'wp-admin' ) !== false ) {
            return 'WordPress Admin Panel';
        }
        if ( strpos( $uri, 'register' ) !== false ) {
            return 'Front-End Registration Form';
        }
    }
    if ( wp_doing_cron() ) {
        return 'WP-Cron';
    }
    if ( defined( 'WP_CLI' ) && WP_CLI ) {
        return 'WP-CLI';
    }
    return 'Unknown / Direct';
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Generate a cryptographically secure token.
// ────────────────────────────────────────────────────────────────────

function aag_generate_token() {
    if ( function_exists( 'random_bytes' ) ) {
        return bin2hex( random_bytes( AAG_TOKEN_LENGTH ) );
    }
    // Fallback for older PHP (still good entropy via wp_generate_password).
    return wp_generate_password( AAG_TOKEN_LENGTH * 2, false, false );
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Check if a user is in the pending queue.
// ────────────────────────────────────────────────────────────────────

function aag_is_pending( $user_id ) {
    return (bool) get_user_meta( $user_id, '_aag_pending', true );
}

// ────────────────────────────────────────────────────────────────────
// HELPER: Check if a given user ID is the authorized admin.
//         The first administrator registered is considered the root admin.
// ────────────────────────────────────────────────────────────────────

function aag_is_authorized_admin( $user_id ) {
    if ( ! $user_id ) {
        return false;
    }
    $user = get_userdata( $user_id );
    if ( ! $user ) {
        return false;
    }
    // Must actually have manage_options AND not be pending.
    return user_can( $user_id, 'manage_options' ) && ! aag_is_pending( $user_id );
}

// ────────────────────────────────────────────────────────────────────
// NOTIFICATION EMAIL
// ────────────────────────────────────────────────────────────────────

function aag_send_notification_email( $user, $meta, $approve_token, $reject_token, $reason ) {
    $approve_url = add_query_arg(
        array(
            'aag_action' => 'approve',
            'user_id'    => $user->ID,
            'token'      => $approve_token,
        ),
        home_url( '/' )
    );
    $reject_url  = add_query_arg(
        array(
            'aag_action' => 'reject',
            'user_id'    => $user->ID,
            'token'      => $reject_token,
        ),
        home_url( '/' )
    );
    $admin_panel_url = admin_url( 'admin.php?page=aag-admin-approvals' );

    $reason_map = array(
        'new_registration_as_admin'  => 'New User Registration with Administrator Role',
        'privilege_escalation_attempt' => 'Privilege Escalation Attempt (Role Changed to Administrator)',
        'rest_api_admin_create'      => 'REST API Administrator Creation Attempt',
        'super_admin_grant'          => 'Super-Admin Grant Attempt (Multisite)',
    );
    $reason_label = $reason_map[ $reason ] ?? ucwords( str_replace( '_', ' ', $reason ) );

    $subject = sprintf(
        '[SECURITY ALERT] Admin Approval Required — %s — %s',
        $meta['username'],
        get_bloginfo( 'name' )
    );

    /* Build a detailed plain-text email body. */
    $lines   = array();
    $lines[] = '════════════════════════════════════════════════════';
    $lines[] = '  ADMIN APPROVAL GUARD — ACTION REQUIRED';
    $lines[] = '  ' . get_bloginfo( 'name' ) . ' (' . home_url() . ')';
    $lines[] = '════════════════════════════════════════════════════';
    $lines[] = '';
    $lines[] = 'ALERT TYPE : ' . $reason_label;
    $lines[] = 'ALERT TIME : ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
    $lines[] = '';
    $lines[] = '────── USER DETAILS ──────';
    $lines[] = 'Full Name        : ' . $meta['full_name'];
    $lines[] = 'Username         : ' . $meta['username'];
    $lines[] = 'Email Address    : ' . $meta['email'];
    $lines[] = 'Phone Number     : ' . $meta['phone'];
    $lines[] = 'Website          : ' . $meta['website'];
    $lines[] = 'Nickname         : ' . $meta['nickname'];
    $lines[] = 'User Description : ' . $meta['description'];
    $lines[] = 'Locale           : ' . $meta['locale'];
    $lines[] = 'Roles Before     : ' . $meta['roles_before'];
    $lines[] = 'Registered At    : ' . $meta['registered_at'];
    $lines[] = '';
    $lines[] = '────── REQUEST DETAILS ──────';
    $lines[] = 'Request Time     : ' . $meta['request_time'];
    $lines[] = 'IP Address       : ' . $meta['ip_address'];
    $lines[] = 'Request Source   : ' . $meta['source'];
    $lines[] = 'HTTP Method      : ' . $meta['http_method'];
    $lines[] = 'Request URI      : ' . $meta['request_uri'];
    $lines[] = 'Referrer URL     : ' . $meta['referrer'];
    $lines[] = '';
    $lines[] = '────── DEVICE & BROWSER ──────';
    $lines[] = 'Browser          : ' . $meta['browser'] . ' ' . $meta['browser_ver'];
    $lines[] = 'Operating System : ' . $meta['os'];
    $lines[] = 'Device Type      : ' . $meta['device_type'];
    $lines[] = 'User Agent       : ' . $meta['user_agent'];
    $lines[] = '';
    $lines[] = '────── GEOLOCATION (IP-BASED) ──────';
    $lines[] = 'Country          : ' . $meta['country'];
    $lines[] = 'Region           : ' . $meta['region'];
    $lines[] = 'City             : ' . $meta['city'];
    $lines[] = 'ISP / Network    : ' . $meta['isp'];
    $lines[] = 'Latitude         : ' . $meta['latitude'];
    $lines[] = 'Longitude        : ' . $meta['longitude'];
    $lines[] = 'Timezone         : ' . $meta['timezone'];
    $lines[] = '';
    $lines[] = '════════════════════════════════════════════════════';
    $lines[] = '  ACTION REQUIRED — Please approve or reject below.';
    $lines[] = '  The user will have NO admin access until you act.';
    $lines[] = '════════════════════════════════════════════════════';
    $lines[] = '';
    $lines[] = '✅  APPROVE (grant administrator role):';
    $lines[] = $approve_url;
    $lines[] = '';
    $lines[] = '❌  REJECT (keep as subscriber / remove):';
    $lines[] = $reject_url;
    $lines[] = '';
    $lines[] = '🔐  Or manage all pending requests in your admin panel:';
    $lines[] = $admin_panel_url;
    $lines[] = '';
    $lines[] = '────────────────────────────────────────────────────';
    $lines[] = 'This is an automated alert from Admin Approval Guard.';
    $lines[] = 'Do NOT share the above approval/rejection links.';
    $lines[] = 'They are single-use tokens valid for one action only.';
    $lines[] = '────────────────────────────────────────────────────';

    $headers = array(
        'Content-Type: text/plain; charset=UTF-8',
        'X-Priority: 1',
        'X-Mailer: Admin-Approval-Guard/' . AAG_VERSION,
    );

    wp_mail( AAG_NOTIFY_EMAIL, $subject, implode( "\n", $lines ), $headers );
}

// ────────────────────────────────────────────────────────────────────
// EMAIL LINK HANDLER (init hook — processes approve/reject clicks).
// ────────────────────────────────────────────────────────────────────

add_action( 'init', 'aag_handle_email_action' );
function aag_handle_email_action() {
    if ( ! isset( $_GET['aag_action'], $_GET['user_id'], $_GET['token'] ) ) {
        return;
    }

    $action  = sanitize_key( wp_unslash( $_GET['aag_action'] ) );
    $user_id = absint( wp_unslash( $_GET['user_id'] ) );
    $token   = sanitize_text_field( wp_unslash( $_GET['token'] ) );

    if ( ! in_array( $action, array( 'approve', 'reject' ), true ) ) {
        return;
    }

    // Verify the acting user is the authorized admin.
    if ( ! is_user_logged_in() || ! aag_is_authorized_admin( get_current_user_id() ) ) {
        wp_die(
            esc_html__( 'You must be logged in as the authorized administrator to perform this action.', 'admin-approval-guard' ),
            esc_html__( 'Unauthorized', 'admin-approval-guard' ),
            array( 'response' => 403 )
        );
    }

    $pending = get_option( AAG_OPTION_PENDING, array() );
    $token_hash = wp_hash( $token );

    $found = false;
    foreach ( $pending as &$entry ) {
        if ( (int) $entry['user_id'] !== $user_id || $entry['status'] !== 'pending' ) {
            continue;
        }
        // Match against the correct token hash.
        $valid = ( $action === 'approve' && hash_equals( $entry['approve_token'], $token_hash ) )
               || ( $action === 'reject' && hash_equals( $entry['reject_token'], $token_hash ) );

        if ( $valid ) {
            $found = true;
            if ( $action === 'approve' ) {
                aag_approve_user( $user_id, $entry );
                $entry['status'] = 'approved';
                $entry['actioned_by'] = get_current_user_id();
                $entry['actioned_at'] = current_time( 'timestamp', true );
            } else {
                aag_reject_user( $user_id, $entry );
                $entry['status'] = 'rejected';
                $entry['actioned_by'] = get_current_user_id();
                $entry['actioned_at'] = current_time( 'timestamp', true );
            }
            // Invalidate both tokens after use.
            $entry['approve_token'] = '';
            $entry['reject_token']  = '';
            break;
        }
        unset( $entry );
    }
    unset( $entry );

    update_option( AAG_OPTION_PENDING, $pending, 'no' );

    if ( ! $found ) {
        wp_die(
            esc_html__( 'Invalid or already-used token. This link may have expired or already been actioned.', 'admin-approval-guard' ),
            esc_html__( 'Token Invalid', 'admin-approval-guard' ),
            array( 'response' => 400 )
        );
    }

    $label = ( $action === 'approve' ) ? 'approved' : 'rejected';
    $user  = get_userdata( $user_id );
    $uname = $user ? $user->user_login : "(ID: $user_id)";

    wp_die(
        sprintf(
            '<h2 style="font-family:sans-serif">✅ Action Recorded</h2>
            <p style="font-family:sans-serif">User <strong>%s</strong> has been <strong>%s</strong> successfully.</p>
            <p style="font-family:sans-serif"><a href="%s">← Return to Admin Panel</a></p>',
            esc_html( $uname ),
            esc_html( $label ),
            esc_url( admin_url( 'admin.php?page=aag-admin-approvals' ) )
        ),
        esc_html__( 'Action Complete', 'admin-approval-guard' ),
        array( 'response' => 200 )
    );
}

// ────────────────────────────────────────────────────────────────────
// APPROVE: Grant admin role.
// ────────────────────────────────────────────────────────────────────

function aag_approve_user( $user_id, $entry ) {
    $user = get_userdata( $user_id );
    if ( ! $user ) {
        return;
    }

    // Signal to the set_user_role hook that this is an authorized change.
    $GLOBALS['aag_approving_user'] = true;
    try {
        $user->set_role( 'administrator' );
    } finally {
        unset( $GLOBALS['aag_approving_user'] );
    }

    delete_user_meta( $user_id, '_aag_pending' );

    // Register this user in the approved list and manual whitelist so the integrity check
    // does not flag them as an unauthorized admin.
    $approved_ids = get_option( AAG_OPTION_APPROVED, array() );
    if ( ! is_array( $approved_ids ) ) {
        $approved_ids = array();
    }
    if ( ! in_array( (int) $user_id, array_map( 'intval', $approved_ids ), true ) ) {
        $approved_ids[] = (int) $user_id;
        update_option( AAG_OPTION_APPROVED, $approved_ids, 'no' );
    }
    aag_add_to_manual_whitelist( $user->user_login );
    aag_add_to_manual_whitelist( $user->user_email );

    aag_log(
        'admin_approved',
        'info',
        sprintf( 'User ID %d (%s) APPROVED for administrator role by user ID %d.', $user_id, $user->user_login, get_current_user_id() ),
        $user_id
    );

    // Notify the approved user.
    wp_mail(
        $user->user_email,
        sprintf( '[%s] Your administrator access has been approved', get_bloginfo( 'name' ) ),
        sprintf(
            "Hello %s,\n\nYour request for administrator access on %s has been approved.\n\nYou can now log in at: %s\n\nRegards,\n%s",
            $user->display_name,
            get_bloginfo( 'name' ),
            wp_login_url(),
            get_bloginfo( 'name' )
        )
    );
}


// ────────────────────────────────────────────────────────────────────
// REJECT: Keep user as subscriber, optionally delete.
// ────────────────────────────────────────────────────────────────────

function aag_reject_user( $user_id, $entry ) {
    $user = get_userdata( $user_id );
    if ( ! $user ) {
        return;
    }

    // Keep the account but ensure it stays at subscriber level.
    $user->set_role( 'subscriber' );
    delete_user_meta( $user_id, '_aag_pending' );

    aag_log(
        'admin_rejected',
        'warning',
        sprintf( 'User ID %d (%s) REJECTED for administrator role by user ID %d. Account kept as subscriber.', $user_id, $user->user_login, get_current_user_id() ),
        $user_id
    );

    // Notify the rejected user.
    wp_mail(
        $user->user_email,
        sprintf( '[%s] Your administrator access request was declined', get_bloginfo( 'name' ) ),
        sprintf(
            "Hello %s,\n\nYour request for administrator access on %s has been declined.\n\nIf you believe this is an error, please contact the site administrator.\n\nRegards,\n%s",
            $user->display_name,
            get_bloginfo( 'name' ),
            get_bloginfo( 'name' )
        )
    );
}

// ────────────────────────────────────────────────────────────────────
// ADMIN MENU
// ────────────────────────────────────────────────────────────────────

add_action( 'admin_menu', 'aag_register_menu' );
function aag_register_menu() {
    add_menu_page(
        esc_html__( 'Admin Approval Guard', 'admin-approval-guard' ),
        esc_html__( 'Admin Approvals', 'admin-approval-guard' ),
        'manage_options',
        'aag-admin-approvals',
        'aag_render_admin_page',
        'dashicons-shield-alt',
        3
    );
    
    // Add submenus
    add_submenu_page(
        'aag-admin-approvals',
        esc_html__( 'Dashboard', 'admin-approval-guard' ),
        esc_html__( 'Dashboard', 'admin-approval-guard' ),
        'manage_options',
        'aag-admin-approvals',
        'aag_render_admin_page'
    );

    add_submenu_page(
        'aag-admin-approvals',
        esc_html__( 'Settings', 'admin-approval-guard' ),
        esc_html__( 'Settings', 'admin-approval-guard' ),
        'manage_options',
        'aag-settings',
        'aag_render_settings_page'
    );

    add_submenu_page(
        'aag-admin-approvals',
        esc_html__( '404 Redirect Logs', 'admin-approval-guard' ),
        esc_html__( '404 Redirect Logs', 'admin-approval-guard' ),
        'manage_options',
        'aag-404-logs',
        'aag_render_404_logs_page'
    );
}

// ────────────────────────────────────────────────────────────────────
// ADMIN PAGE — Handle form actions and render UI.
// ────────────────────────────────────────────────────────────────────

function aag_render_admin_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You do not have permission to view this page.', 'admin-approval-guard' ) );
    }

    // ── Handle panel form actions ──
    if ( isset( $_POST['aag_panel_action'], $_POST['aag_panel_nonce'], $_POST['aag_target_user_id'] ) ) {
        if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_panel_nonce'] ) ), 'aag_panel_action' ) ) {
            wp_die( esc_html__( 'Security check failed.', 'admin-approval-guard' ) );
        }

        $panel_action = sanitize_key( wp_unslash( $_POST['aag_panel_action'] ) );
        $target_id    = absint( wp_unslash( $_POST['aag_target_user_id'] ) );
        $pending      = get_option( AAG_OPTION_PENDING, array() );

        if ( $panel_action === 'approve_admin' ) {
            // Whitelist an existing admin user immediately
            aag_add_to_manual_whitelist( $target_id );
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'User approved and added to admin whitelist.', 'admin-approval-guard' ) . '</p></div>';
        } elseif ( $panel_action === 'revoke' ) {
            // Revoke existing administrator.
            $user = get_userdata( $target_id );
            if ( $user ) {
                $GLOBALS['aag_approving_user'] = true;
                try {
                    $user->set_role( 'subscriber' );
                } finally {
                    unset( $GLOBALS['aag_approving_user'] );
                }
                aag_terminate_user_sessions( $target_id );
                aag_remove_from_manual_whitelist( $user->user_login );
                aag_remove_from_manual_whitelist( $user->user_email );
                aag_log( 'admin_revoked', 'critical', sprintf( 'Administrator privileges REVOKED for user ID %d (%s) by user ID %d. Active sessions terminated.', $target_id, $user->user_login, get_current_user_id() ), $target_id );
            }
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'Administrator privileges revoked and all active sessions terminated.', 'admin-approval-guard' ) . '</p></div>';
        } else {
            foreach ( $pending as &$entry ) {
                if ( (int) $entry['user_id'] !== $target_id || $entry['status'] !== 'pending' ) {
                    continue;
                }
                if ( $panel_action === 'approve' ) {
                    aag_approve_user( $target_id, $entry );
                    $entry['status']      = 'approved';
                    $entry['actioned_by'] = get_current_user_id();
                    $entry['actioned_at'] = current_time( 'timestamp', true );
                    $entry['approve_token'] = '';
                    $entry['reject_token']  = '';
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'User approved successfully.', 'admin-approval-guard' ) . '</p></div>';
                } elseif ( $panel_action === 'reject' ) {
                    aag_reject_user( $target_id, $entry );
                    $entry['status']      = 'rejected';
                    $entry['actioned_by'] = get_current_user_id();
                    $entry['actioned_at'] = current_time( 'timestamp', true );
                    $entry['approve_token'] = '';
                    $entry['reject_token']  = '';
                    echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'User rejected. Account remains as subscriber.', 'admin-approval-guard' ) . '</p></div>';
                }
                break;
            }
            unset( $entry );
            update_option( AAG_OPTION_PENDING, $pending, 'no' );
        }
    }

    // ── Run Hourly Integrity Check on Demand ──
    if ( isset( $_POST['aag_run_integrity_now'], $_POST['aag_run_integrity_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_run_integrity_nonce'] ) ), 'aag_run_integrity_action' ) ) {
            $check_res = aag_run_integrity_check( 'manual_admin_request' );
            if ( $check_res['rogue'] > 0 ) {
                echo '<div class="notice notice-error is-dismissible"><p><strong>' . sprintf( esc_html__( '⚠️ Integrity Check Completed: Found and neutralized %d unauthorized administrator account(s)! Verified %d authorized admin(s). An alert email has been sent.', 'admin-approval-guard' ), $check_res['rogue'], $check_res['verified'] ) . '</strong></p></div>';
            } else {
                echo '<div class="notice notice-success is-dismissible"><p>' . sprintf( esc_html__( '✅ Integrity Check Completed: All %d administrator accounts are authorized and whitelisted. 0 rogue accounts found.', 'admin-approval-guard' ), $check_res['verified'] ) . '</p></div>';
            }
        }
    }

    // ── Add Manual Admin to Whitelist ──
    if ( isset( $_POST['aag_whitelist_add_submit'], $_POST['aag_whitelist_nonce'], $_POST['aag_whitelist_identifier'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_whitelist_nonce'] ) ), 'aag_whitelist_action' ) ) {
            $identifier = sanitize_text_field( wp_unslash( $_POST['aag_whitelist_identifier'] ) );
            if ( ! empty( $identifier ) ) {
                aag_add_to_manual_whitelist( $identifier );
                echo '<div class="notice notice-success is-dismissible"><p>' . sprintf( esc_html__( 'Admin "%s" successfully added to the approved whitelist.', 'admin-approval-guard' ), esc_html( $identifier ) ) . '</p></div>';
            }
        }
    }

    // ── Remove Admin from Manual Whitelist ──
    if ( isset( $_POST['aag_whitelist_remove_submit'], $_POST['aag_whitelist_nonce'], $_POST['aag_whitelist_identifier'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_whitelist_nonce'] ) ), 'aag_whitelist_action' ) ) {
            $identifier = sanitize_text_field( wp_unslash( $_POST['aag_whitelist_identifier'] ) );
            if ( ! empty( $identifier ) ) {
                if ( aag_remove_from_manual_whitelist( $identifier ) ) {
                    echo '<div class="notice notice-warning is-dismissible"><p>' . sprintf( esc_html__( 'Admin "%s" removed from the approved whitelist.', 'admin-approval-guard' ), esc_html( $identifier ) ) . '</p></div>';
                } else {
                    echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'The master administrator cannot be removed.', 'admin-approval-guard' ) . '</p></div>';
                }
            }
        }
    }

    // ── Clear logs ──
    if ( isset( $_POST['aag_clear_logs'], $_POST['aag_clear_logs_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_clear_logs_nonce'] ) ), 'aag_clear_logs' ) ) {
            update_option( AAG_OPTION_LOG, array(), 'no' );
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Audit logs cleared.', 'admin-approval-guard' ) . '</p></div>';
        }
    }

    $active_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'pending';
    $pending    = get_option( AAG_OPTION_PENDING, array() );
    $logs       = get_option( AAG_OPTION_LOG, array() );
    $all_admins = get_users( array( 'role' => 'administrator' ) );

    // Count pending items for badge.
    $pending_count = count( array_filter( $pending, static fn( $e ) => $e['status'] === 'pending' ) );
    ?>
    <div class="wrap">
        <h1 style="display:flex;align-items:center;gap:10px;">
            <span class="dashicons dashicons-shield-alt" style="font-size:30px;color:#2271b1;"></span>
            <?php esc_html_e( 'Admin Approval Guard', 'admin-approval-guard' ); ?>
        </h1>
        <p style="color:#64748b;margin-bottom:20px;">
            <?php esc_html_e( 'Mandatory administrator account approval system. No user receives admin access without your explicit approval.', 'admin-approval-guard' ); ?>
        </p>

        <nav class="nav-tab-wrapper">
            <a href="?page=aag-admin-approvals&tab=pending"
               class="nav-tab <?php echo $active_tab === 'pending' ? 'nav-tab-active' : ''; ?>">
                <?php esc_html_e( 'Pending Requests', 'admin-approval-guard' ); ?>
                <?php if ( $pending_count > 0 ) : ?>
                    <span class="awaiting-mod count-<?php echo esc_attr( $pending_count ); ?>"><?php echo esc_html( $pending_count ); ?></span>
                <?php endif; ?>
            </a>
            <a href="?page=aag-admin-approvals&tab=admins"
               class="nav-tab <?php echo $active_tab === 'admins' ? 'nav-tab-active' : ''; ?>">
                <?php esc_html_e( 'Manage Administrators', 'admin-approval-guard' ); ?>
            </a>
            <a href="?page=aag-admin-approvals&tab=history"
               class="nav-tab <?php echo $active_tab === 'history' ? 'nav-tab-active' : ''; ?>">
                <?php esc_html_e( 'Request History', 'admin-approval-guard' ); ?>
            </a>
            <a href="?page=aag-admin-approvals&tab=logs"
               class="nav-tab <?php echo $active_tab === 'logs' ? 'nav-tab-active' : ''; ?>">
                <?php esc_html_e( 'Audit Logs', 'admin-approval-guard' ); ?>
            </a>
            <a href="?page=aag-admin-approvals&tab=scanner"
               class="nav-tab <?php echo $active_tab === 'scanner' ? 'nav-tab-active' : ''; ?>" style="color:#b91c1c;">
                🔍 <?php esc_html_e( 'Malware Scanner', 'admin-approval-guard' ); ?>
                <?php
                $threat_count = count( get_option( 'aag_scan_threats', array() ) );
                if ( $threat_count > 0 ) {
                    echo '<span class="awaiting-mod" style="background:#dc2626;">' . esc_html( $threat_count ) . '</span>';
                }
                ?>
            </a>
            <a href="?page=aag-admin-approvals&tab=blocked"
               class="nav-tab <?php echo $active_tab === 'blocked' ? 'nav-tab-active' : ''; ?>">
                🚫 <?php esc_html_e( 'Blocked IPs', 'admin-approval-guard' ); ?>
            </a>
        </nav>

        <div style="margin-top:20px;">

        <?php if ( $active_tab === 'pending' ) : ?>
            <?php
            $pending_entries = array_filter( $pending, static fn( $e ) => $e['status'] === 'pending' );
            ?>
            <h2><?php esc_html_e( 'Pending Administrator Requests', 'admin-approval-guard' ); ?></h2>
            <?php if ( empty( $pending_entries ) ) : ?>
                <div style="background:#f0fdf4;border:1px solid #86efac;padding:20px;border-radius:8px;">
                    <p style="color:#16a34a;margin:0;font-weight:600;">
                        ✅ <?php esc_html_e( 'No pending administrator requests. Your site is secure.', 'admin-approval-guard' ); ?>
                    </p>
                </div>
            <?php else : ?>
                <?php foreach ( $pending_entries as $entry ) : ?>
                    <?php
                    $m    = $entry['meta'] ?? array();
                    $uid  = (int) $entry['user_id'];
                    $user = get_userdata( $uid );
                    ?>
                    <div style="background:#fff;border:1px solid #e2e8f0;border-left:4px solid #ef4444;border-radius:8px;padding:24px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,.04);">
                        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
                            <div>
                                <h3 style="margin:0 0 4px;font-size:18px;color:#0f172a;">
                                    🔴 <?php echo esc_html( $m['full_name'] ?? $m['username'] ?? "User #$uid" ); ?>
                                </h3>
                                <span style="font-size:12px;color:#64748b;">
                                    <?php echo esc_html( $m['username'] ?? '' ); ?> &bull;
                                    <?php echo esc_html( $m['email'] ?? '' ); ?> &bull;
                                    <?php echo esc_html( gmdate( 'Y-m-d H:i', $entry['queued_at'] ) ); ?> UTC
                                </span>
                            </div>
                            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                                <form method="post" style="margin:0;" onsubmit="return confirm('Approve this user for administrator access?')">
                                    <?php wp_nonce_field( 'aag_panel_action', 'aag_panel_nonce' ); ?>
                                    <input type="hidden" name="aag_target_user_id" value="<?php echo esc_attr( $uid ); ?>">
                                    <input type="hidden" name="aag_panel_action" value="approve">
                                    <button type="submit" class="button" style="background:#16a34a;color:#fff;border-color:#16a34a;">✅ <?php esc_html_e( 'Approve', 'admin-approval-guard' ); ?></button>
                                </form>
                                <form method="post" style="margin:0;" onsubmit="return confirm('Reject this administrator request?')">
                                    <?php wp_nonce_field( 'aag_panel_action', 'aag_panel_nonce' ); ?>
                                    <input type="hidden" name="aag_target_user_id" value="<?php echo esc_attr( $uid ); ?>">
                                    <input type="hidden" name="aag_panel_action" value="reject">
                                    <button type="submit" class="button button-secondary">❌ <?php esc_html_e( 'Reject', 'admin-approval-guard' ); ?></button>
                                </form>
                            </div>
                        </div>

                        <table class="widefat striped" style="margin-top:16px;font-size:13px;">
                            <tbody>
                            <?php
                            $rows = array(
                                __( 'Full Name', 'admin-approval-guard' )         => $m['full_name']     ?? 'N/A',
                                __( 'Username', 'admin-approval-guard' )          => $m['username']      ?? 'N/A',
                                __( 'Email Address', 'admin-approval-guard' )     => $m['email']         ?? 'N/A',
                                __( 'Phone Number', 'admin-approval-guard' )      => $m['phone']         ?? 'N/A',
                                __( 'Registration Date', 'admin-approval-guard' ) => $m['registered_at'] ?? 'N/A',
                                __( 'Request Time', 'admin-approval-guard' )      => $m['request_time']  ?? 'N/A',
                                __( 'IP Address', 'admin-approval-guard' )        => $m['ip_address']    ?? 'N/A',
                                __( 'Country', 'admin-approval-guard' )           => $m['country']       ?? 'N/A',
                                __( 'Region / City', 'admin-approval-guard' )     => ( $m['region'] ?? 'N/A' ) . ' / ' . ( $m['city'] ?? 'N/A' ),
                                __( 'ISP / Network', 'admin-approval-guard' )     => $m['isp']           ?? 'N/A',
                                __( 'Browser', 'admin-approval-guard' )           => ( $m['browser'] ?? 'N/A' ) . ' ' . ( $m['browser_ver'] ?? '' ),
                                __( 'Operating System', 'admin-approval-guard' )  => $m['os']            ?? 'N/A',
                                __( 'Device Type', 'admin-approval-guard' )       => $m['device_type']   ?? 'N/A',
                                __( 'User Agent', 'admin-approval-guard' )        => $m['user_agent']    ?? 'N/A',
                                __( 'Referrer URL', 'admin-approval-guard' )      => $m['referrer']      ?? 'N/A',
                                __( 'Registration Source', 'admin-approval-guard' ) => $m['source']      ?? 'N/A',
                                __( 'Alert Reason', 'admin-approval-guard' )      => $entry['reason']    ?? 'N/A',
                            );
                            foreach ( $rows as $label => $value ) :
                                ?>
                                <tr>
                                    <th style="width:200px;font-weight:600;"><?php echo esc_html( $label ); ?></th>
                                    <td><code style="background:#f8fafc;padding:2px 6px;border-radius:4px;font-size:12px;"><?php echo esc_html( $value ); ?></code></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>

        <?php elseif ( $active_tab === 'admins' ) : ?>
            <?php
            $last_check  = get_option( AAG_OPTION_LAST_INTEGRITY, array() );
            $whitelist   = aag_get_manual_whitelist();
            $check_time  = isset( $last_check['timestamp'] ) ? human_time_diff( $last_check['timestamp'], current_time( 'timestamp', true ) ) . ' ' . esc_html__( 'ago', 'admin-approval-guard' ) : esc_html__( 'Never', 'admin-approval-guard' );
            $last_status = $last_check['status'] ?? 'ok';
            $verified_c  = (int) ( $last_check['verified_count'] ?? count( $all_admins ) );
            $rogue_c     = (int) ( $last_check['rogue_count'] ?? 0 );
            ?>

            <!-- ── Hourly Integrity Enforcer Status Card ── -->
            <div style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:18px 24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,0.05);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:15px;">
                <div>
                    <h3 style="margin:0 0 6px 0;display:flex;align-items:center;gap:8px;font-size:16px;">
                        <span style="color:#16a34a;font-size:20px;">🛡️</span>
                        <?php esc_html_e( 'Hourly Admin Integrity Enforcer', 'admin-approval-guard' ); ?>
                        <span style="background:#dcfce7;color:#15803d;font-size:12px;font-weight:600;padding:2px 8px;border-radius:12px;">
                            <?php esc_html_e( 'Active (Runs Every Hour)', 'admin-approval-guard' ); ?>
                        </span>
                    </h3>
                    <p style="margin:0;color:#64748b;font-size:13px;">
                        <?php
                        printf(
                            esc_html__( 'Last Check: %s | Verified: %d approved admin(s) | Rogue Neutralized: %d', 'admin-approval-guard' ),
                            '<strong>' . esc_html( $check_time ) . '</strong>',
                            $verified_c,
                            $rogue_c
                        );
                        ?>
                    </p>
                </div>
                <form method="post" style="margin:0;">
                    <?php wp_nonce_field( 'aag_run_integrity_action', 'aag_run_integrity_nonce' ); ?>
                    <button type="submit" name="aag_run_integrity_now" value="1" class="button button-primary" style="display:flex;align-items:center;gap:6px;font-weight:600;">
                        ⚡ <?php esc_html_e( 'Run Integrity Check Now', 'admin-approval-guard' ); ?>
                    </button>
                </form>
            </div>

            <!-- ── Current Administrators Table ── -->
            <div style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:20px;margin-bottom:28px;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                <h3 style="margin-top:0;font-size:16px;"><?php esc_html_e( 'Current Administrator Accounts', 'admin-approval-guard' ); ?></h3>
                <p style="color:#64748b;font-size:13px;margin-bottom:15px;">
                    <?php esc_html_e( 'Every hour, this list is cross-checked against your approved whitelist. Any account holding admin privileges without approval is automatically demoted, its sessions killed, and an alert sent.', 'admin-approval-guard' ); ?>
                </p>

                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Username', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Display Name', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Email', 'admin-approval-guard' ); ?></th>
                            <th style="width:170px;"><?php esc_html_e( 'Status', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Registered', 'admin-approval-guard' ); ?></th>
                            <th style="width:220px;"><?php esc_html_e( 'Action', 'admin-approval-guard' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $all_admins as $admin ) :
                            $is_master    = strtolower( trim( $admin->user_email ) ) === strtolower( trim( AAG_NOTIFY_EMAIL ) );
                            $is_current   = ( (int) $admin->ID === (int) get_current_user_id() );
                            $is_approved  = aag_is_admin_approved( $admin );
                            ?>
                            <tr>
                                <td>
                                    <strong><?php echo esc_html( $admin->user_login ); ?></strong>
                                    <?php if ( $is_current ) : ?>
                                        <span style="color:#64748b;font-size:11px;">(You)</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html( $admin->display_name ); ?></td>
                                <td><?php echo esc_html( $admin->user_email ); ?></td>
                                <td>
                                    <?php if ( $is_approved ) : ?>
                                        <span style="background:#dcfce7;color:#15803d;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;">
                                            ✓ <?php esc_html_e( 'Whitelisted', 'admin-approval-guard' ); ?>
                                        </span>
                                    <?php else : ?>
                                        <span style="background:#fee2e2;color:#b91c1c;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;">
                                            ⚠️ <?php esc_html_e( 'Unapproved', 'admin-approval-guard' ); ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html( $admin->user_registered ); ?></td>
                                <td>
                                    <?php if ( $is_master || $is_current ) : ?>
                                        <em style="color:#94a3b8;"><?php esc_html_e( 'Protected Master Admin', 'admin-approval-guard' ); ?></em>
                                    <?php else : ?>
                                        <div style="display:flex;gap:6px;align-items:center;">
                                            <?php if ( ! $is_approved ) : ?>
                                                <form method="post" style="margin:0;">
                                                    <?php wp_nonce_field( 'aag_panel_action', 'aag_panel_nonce' ); ?>
                                                    <input type="hidden" name="aag_target_user_id" value="<?php echo esc_attr( $admin->ID ); ?>">
                                                    <input type="hidden" name="aag_panel_action" value="approve_admin">
                                                    <button type="submit" class="button button-small button-primary">
                                                        ✓ <?php esc_html_e( 'Approve', 'admin-approval-guard' ); ?>
                                                    </button>
                                                </form>
                                            <?php endif; ?>

                                            <form method="post" style="margin:0;" onsubmit="return confirm('Revoke administrator privileges and terminate all active sessions for this user?')">
                                                <?php wp_nonce_field( 'aag_panel_action', 'aag_panel_nonce' ); ?>
                                                <input type="hidden" name="aag_target_user_id" value="<?php echo esc_attr( $admin->ID ); ?>">
                                                <input type="hidden" name="aag_panel_action" value="revoke">
                                                <button type="submit" class="button button-secondary button-small" style="color:#dc2626;border-color:#fca5a5;">
                                                    🚫 <?php esc_html_e( 'Revoke & Kick', 'admin-approval-guard' ); ?>
                                                </button>
                                            </form>
                                        </div>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- ── Manual Whitelist Management Card ── -->
            <div style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                <h3 style="margin-top:0;font-size:16px;">📝 <?php esc_html_e( 'Manual Admin Whitelist Manager', 'admin-approval-guard' ); ?></h3>
                <p style="color:#64748b;font-size:13px;">
                    <?php esc_html_e( 'You can manually whitelist trusted administrator emails or usernames below. Any user matching an entry in this whitelist will be permitted to hold administrator privileges.', 'admin-approval-guard' ); ?>
                </p>

                <!-- Add to Whitelist Form -->
                <form method="post" style="display:flex;align-items:center;gap:10px;margin-bottom:20px;max-width:550px;">
                    <?php wp_nonce_field( 'aag_whitelist_action', 'aag_whitelist_nonce' ); ?>
                    <input type="text" name="aag_whitelist_identifier" placeholder="<?php esc_attr_e( 'Enter username or email address...', 'admin-approval-guard' ); ?>" required class="regular-text" style="flex:1;">
                    <button type="submit" name="aag_whitelist_add_submit" value="1" class="button button-primary">
                        + <?php esc_html_e( 'Add to Whitelist', 'admin-approval-guard' ); ?>
                    </button>
                </form>

                <!-- Whitelisted Entries Table -->
                <table class="wp-list-table widefat fixed striped" style="max-width:650px;">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Whitelisted Identifier (Username / Email)', 'admin-approval-guard' ); ?></th>
                            <th style="width:120px;"><?php esc_html_e( 'Action', 'admin-approval-guard' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $whitelist as $w_item ) :
                            $is_master_item = ( strtolower( trim( $w_item ) ) === strtolower( trim( AAG_NOTIFY_EMAIL ) ) );
                            ?>
                            <tr>
                                <td>
                                    <code><?php echo esc_html( $w_item ); ?></code>
                                    <?php if ( $is_master_item ) : ?>
                                        <span style="color:#16a34a;font-size:11px;font-weight:600;margin-left:8px;">(Master Admin)</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ( ! $is_master_item ) : ?>
                                        <form method="post" style="margin:0;" onsubmit="return confirm('Remove <?php echo esc_js( $w_item ); ?> from the approved whitelist?')">
                                            <?php wp_nonce_field( 'aag_whitelist_action', 'aag_whitelist_nonce' ); ?>
                                            <input type="hidden" name="aag_whitelist_identifier" value="<?php echo esc_attr( $w_item ); ?>">
                                            <button type="submit" name="aag_whitelist_remove_submit" value="1" class="button button-small button-link-delete">
                                                🗑️ <?php esc_html_e( 'Remove', 'admin-approval-guard' ); ?>
                                            </button>
                                        </form>
                                    <?php else : ?>
                                        <em style="color:#94a3b8;"><?php esc_html_e( 'Locked', 'admin-approval-guard' ); ?></em>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

        <?php elseif ( $active_tab === 'history' ) : ?>
            <h2><?php esc_html_e( 'Request History', 'admin-approval-guard' ); ?></h2>
            <?php
            $history = array_filter( $pending, static fn( $e ) => $e['status'] !== 'pending' );
            $history = array_reverse( $history );
            ?>
            <?php if ( empty( $history ) ) : ?>
                <p><?php esc_html_e( 'No actioned requests yet.', 'admin-approval-guard' ); ?></p>
            <?php else : ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'User', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Email', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'IP', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Queued', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Status', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Actioned At', 'admin-approval-guard' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $history as $entry ) :
                            $m      = $entry['meta'] ?? array();
                            $status = $entry['status'];
                            $color  = $status === 'approved' ? '#16a34a' : '#dc2626';
                            ?>
                            <tr>
                                <td><strong><?php echo esc_html( $m['username'] ?? "ID:{$entry['user_id']}" ); ?></strong></td>
                                <td><?php echo esc_html( $m['email'] ?? 'N/A' ); ?></td>
                                <td><code><?php echo esc_html( $m['ip_address'] ?? 'N/A' ); ?></code></td>
                                <td><?php echo esc_html( isset( $entry['queued_at'] ) ? gmdate( 'Y-m-d H:i', $entry['queued_at'] ) . ' UTC' : 'N/A' ); ?></td>
                                <td>
                                    <span style="background:<?php echo esc_attr( $color ); ?>;color:#fff;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;">
                                        <?php echo esc_html( $status ); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html( isset( $entry['actioned_at'] ) ? gmdate( 'Y-m-d H:i', $entry['actioned_at'] ) . ' UTC' : 'N/A' ); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

        <?php elseif ( $active_tab === 'logs' ) : ?>
            <h2><?php esc_html_e( 'Audit Logs', 'admin-approval-guard' ); ?></h2>
            <form method="post" style="margin-bottom:16px;" onsubmit="return confirm('Clear ALL audit logs?')">
                <?php wp_nonce_field( 'aag_clear_logs', 'aag_clear_logs_nonce' ); ?>
                <button type="submit" name="aag_clear_logs" class="button button-secondary">
                    🗑️ <?php esc_html_e( 'Clear All Logs', 'admin-approval-guard' ); ?>
                </button>
            </form>
            <?php if ( empty( $logs ) ) : ?>
                <p><?php esc_html_e( 'No audit log entries yet.', 'admin-approval-guard' ); ?></p>
            <?php else : ?>
                <table class="wp-list-table widefat fixed striped" style="font-size:13px;">
                    <thead>
                        <tr>
                            <th style="width:160px;"><?php esc_html_e( 'Time (UTC)', 'admin-approval-guard' ); ?></th>
                            <th style="width:100px;"><?php esc_html_e( 'Severity', 'admin-approval-guard' ); ?></th>
                            <th style="width:200px;"><?php esc_html_e( 'Event', 'admin-approval-guard' ); ?></th>
                            <th><?php esc_html_e( 'Details', 'admin-approval-guard' ); ?></th>
                            <th style="width:130px;"><?php esc_html_e( 'IP Address', 'admin-approval-guard' ); ?></th>
                            <th style="width:100px;"><?php esc_html_e( 'Actor', 'admin-approval-guard' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $logs as $log ) :
                            $sev_colors = array(
                                'info'     => '#2563eb',
                                'warning'  => '#d97706',
                                'critical' => '#dc2626',
                            );
                            $sev_color = $sev_colors[ $log['severity'] ] ?? '#64748b';
                            ?>
                            <tr>
                                <td><?php echo esc_html( gmdate( 'Y-m-d H:i:s', $log['timestamp'] ) ); ?></td>
                                <td>
                                    <span style="background:<?php echo esc_attr( $sev_color ); ?>;color:#fff;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700;text-transform:uppercase;">
                                        <?php echo esc_html( $log['severity'] ); ?>
                                    </span>
                                </td>
                                <td><code><?php echo esc_html( $log['event_type'] ); ?></code></td>
                                <td><?php echo esc_html( $log['details'] ); ?></td>
                                <td><code><?php echo esc_html( $log['ip'] ); ?></code></td>
                                <td><?php echo esc_html( $log['actor'] ); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

        <?php elseif ( $active_tab === 'scanner' ) : ?>
            <?php aag_render_scanner_tab(); ?>

        <?php elseif ( $active_tab === 'blocked' ) : ?>
            <?php aag_render_blocked_ips_tab(); ?>

        <?php endif; ?>
        </div>
    </div>
    <?php
}

// ════════════════════════════════════════════════════════════════════
//  ███╗   ███╗ █████╗ ██╗     ██╗    ██╗ █████╗ ██████╗ ███████╗
//  ████╗ ████║██╔══██╗██║     ██║    ██║██╔══██╗██╔══██╗██╔════╝
//  ██╔████╔██║███████║██║     ██║ █╗ ██║███████║██████╔╝█████╗
//  ██║╚██╔╝██║██╔══██║██║     ██║███╗██║██╔══██║██╔══██╗██╔══╝
//  ██║ ╚═╝ ██║██║  ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████╗
//  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
//  SCANNER MODULE — Malware Detection, Repair & IP Blocking
// ════════════════════════════════════════════════════════════════════

// ── Scanner constants ──────────────────────────────────────────────
define( 'AAG_SCAN_OPTION_THREATS',    'aag_scan_threats' );
define( 'AAG_SCAN_OPTION_QUARANTINE', 'aag_quarantined_files' );
define( 'AAG_SCAN_OPTION_LAST_RUN',   'aag_scan_last_run' );
define( 'AAG_SCAN_OPTION_BASELINE',   'aag_file_baseline' );
define( 'AAG_BLOCKED_IPS_OPTION',     'aag_blocked_ips' );
define( 'AAG_SCAN_MAX_FILE_SIZE',     5 * 1024 * 1024 ); // 5 MB per file

// ── Known malware patterns ─────────────────────────────────────────
function aag_get_malware_patterns() {
    return array(
        // ── Obfuscated eval chains ──
        'eval(base64_decode'           => 'Eval + Base64 decode (classic malware obfuscation)',
        'eval(gzinflate'               => 'Eval + gzinflate decompression (obfuscated payload)',
        'eval(gzuncompress'            => 'Eval + gzuncompress (obfuscated payload)',
        'eval(str_rot13'               => 'Eval + str_rot13 rotation cipher',
        'eval(rawurldecode'            => 'Eval + rawurldecode',
        'eval(hex2bin'                 => 'Eval + hex2bin (hex-encoded payload)',
        'eval(convert_uuencode'        => 'Eval + uuencode',
        'gzinflate(base64_decode'      => 'gzinflate + base64_decode chain (layered obfuscation)',
        'gzuncompress(base64_decode'   => 'gzuncompress + base64_decode chain',
        // ── Remote code execution via user input ──
        'eval($_POST'                  => 'Eval with POST input (web shell)',
        'eval($_GET'                   => 'Eval with GET input (web shell)',
        'eval($_REQUEST'               => 'Eval with REQUEST input (web shell)',
        'eval($_COOKIE'                => 'Eval with COOKIE input (web shell)',
        'eval($_SERVER'                => 'Eval with SERVER variable (web shell)',
        'assert($_POST'                => 'Assert with POST input (web shell)',
        'assert($_GET'                 => 'Assert with GET input (web shell)',
        'assert($_REQUEST'             => 'Assert with REQUEST input',
        'assert(base64_decode'         => 'Assert + base64_decode (obfuscated execution)',
        // ── System command execution with user input ──
        'passthru($_'                  => 'passthru() with user input (shell command injection)',
        'system($_'                    => 'system() with user input (shell command injection)',
        'exec($_'                      => 'exec() with user input (shell command injection)',
        'shell_exec($_'                => 'shell_exec() with user input',
        'popen($_'                     => 'popen() with user input',
        '`$_'                          => 'Backtick operator with user input (shell execution)',
        // ── Known web shell signatures ──
        'FilesMan'                     => 'FilesMan web shell signature',
        'c99shell'                     => 'c99shell web shell signature',
        'r57shell'                     => 'r57shell web shell signature',
        'wso_signature'                => 'WSO web shell signature',
        'B374k'                        => 'B374k web shell signature',
        'WSO Shell'                    => 'WSO Shell signature',
        'Adminer'                      => 'Adminer database management tool (verify if intentional)',
        'PhpSpy'                       => 'PhpSpy web shell',
        // ── Data exfiltration & backdoor indicators ──
        'file_put_contents($_'         => 'file_put_contents with user input (arbitrary file write)',
        'str_rot13'                    => 'str_rot13 (encoding, common in obfuscation)',
        '$_POST[chr('                  => 'POST with char encoding (obfuscated key access)',
        'preg_replace_callback.*base64'=> 'preg_replace_callback + base64 (code injection vector)',
        'create_function'              => 'create_function() deprecated — often used in malware',
        'ReflectionFunction'           => 'ReflectionFunction used to bypass security (audit required)',
        // ── Cryptocurrency miners ──
        'CoinHive'                     => 'CoinHive browser mining script',
        'coinhive.min.js'              => 'CoinHive mining JavaScript',
        'miner.Anonymous'              => 'Crypto miner signature',
        'cryptonight'                  => 'CryptoNight mining algorithm reference',
        // ── Spam / SEO injections ──
        'base64_decode.*wp_insert_post'=> 'Base64 spam post injection',
        'wp_insert_post.*base64'       => 'Spam post injection via base64',
    );
}

// ── SCAN ENGINE ────────────────────────────────────────────────────

/**
 * Master scan function. Runs malware pattern scan + file integrity check.
 * Returns array of discovered threats.
 */
function aag_run_full_scan() {
    // 0. Auto-purge database spam revisions and harden uploads folder.
    if ( function_exists( 'aag_purge_spam_revisions' ) ) {
        aag_purge_spam_revisions();
    }
    if ( function_exists( 'aag_harden_uploads_directory' ) ) {
        aag_harden_uploads_directory();
    }

    $threats = array();

    // 1. Malware pattern scan (plugins + themes + uploads).
    $scan_dirs = array(
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/uploads',
        ABSPATH,   // WP root (wp-config.php, index.php, etc.)
    );

    // Exclude our own quarantine folder and this plugin's folder from scanning.
    $own_dir    = plugin_dir_path( __FILE__ );
    $quarantine = $own_dir . 'quarantine/';

    $patterns = aag_get_malware_patterns();

    foreach ( $scan_dirs as $dir ) {
        if ( ! is_dir( $dir ) ) {
            continue;
        }
        $found = aag_scan_directory( $dir, $patterns, array( $own_dir, $quarantine ) );
        $threats = array_merge( $threats, $found );
    }

    // 2. WordPress core file integrity check.
    $core_issues = aag_check_core_integrity();
    $threats     = array_merge( $threats, $core_issues );

    // 3. Plugin file integrity check (baseline comparison).
    $plugin_issues = aag_check_plugin_integrity();
    $threats       = array_merge( $threats, $plugin_issues );

    // 4. Active database post/page content scan.
    if ( function_exists( 'aag_scan_database_posts' ) ) {
        $db_issues = aag_scan_database_posts();
        $threats   = array_merge( $threats, $db_issues );
    }

    // Store results.
    update_option( AAG_SCAN_OPTION_THREATS, $threats, 'no' );
    update_option( AAG_SCAN_OPTION_LAST_RUN, time(), 'no' );

    return $threats;
}

/**
 * Recursively scan a directory for malware patterns.
 */
function aag_scan_directory( $dir, $patterns, $exclude_dirs = array() ) {
    $threats = array();

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
            RecursiveIteratorIterator::SELF_FIRST
        );
    } catch ( Exception $e ) {
        return $threats;
    }

    foreach ( $iterator as $file ) {
        if ( ! $file->isFile() ) {
            continue;
        }

        $filepath = $file->getRealPath();

        // Skip excluded directories.
        foreach ( $exclude_dirs as $excl ) {
            if ( strpos( $filepath, realpath( $excl ) ) === 0 ) {
                continue 2;
            }
        }

        // Only scan PHP, JS, and HTML files.
        $ext = strtolower( $file->getExtension() );
        if ( ! in_array( $ext, array( 'php', 'js', 'html', 'htm', 'phtml', 'php5', 'php7', 'phar' ), true ) ) {
            continue;
        }

        // Skip very large files to avoid memory exhaustion.
        if ( $file->getSize() > AAG_SCAN_MAX_FILE_SIZE ) {
            continue;
        }

        $content = @file_get_contents( $filepath );
        if ( $content === false || $content === '' ) {
            continue;
        }

        // Check for each pattern.
        foreach ( $patterns as $pattern => $description ) {
            if ( stripos( $content, $pattern ) !== false ) {
                // Find the exact line(s).
                $lines      = explode( "\n", $content );
                $match_lines = array();
                foreach ( $lines as $line_num => $line ) {
                    if ( stripos( $line, $pattern ) !== false ) {
                        $match_lines[] = array(
                            'line'    => $line_num + 1,
                            'content' => substr( trim( $line ), 0, 200 ),
                        );
                    }
                }

                $threats[] = array(
                    'type'        => 'malware_pattern',
                    'file'        => $filepath,
                    'pattern'     => $pattern,
                    'description' => $description,
                    'match_lines' => $match_lines,
                    'file_size'   => $file->getSize(),
                    'file_mtime'  => $file->getMTime(),
                    'status'      => 'detected',
                    'found_at'    => time(),
                );
                break; // One threat entry per file per pattern match.
            }
        }
    }

    return $threats;
}

// ── CORE FILE INTEGRITY ────────────────────────────────────────────

/**
 * Compare core files against WordPress.org official checksums.
 */
function aag_check_core_integrity() {
    $issues  = array();
    global $wp_version;
    $version = preg_replace( '/-.*$/', '', $wp_version ?? get_bloginfo( 'version' ) );
    $locale  = get_locale();

    // Fetch checksums from WordPress.org.
    $checksums = aag_fetch_core_checksums( $version, $locale );
    if ( empty( $checksums ) ) {
        return $issues;
    }

    foreach ( $checksums as $file => $expected_hash ) {
        // Skip non-essential files.
        if ( in_array( $file, array( 'wp-config-sample.php', 'readme.html', 'license.txt' ), true ) ) {
            continue;
        }

        $local_path = ABSPATH . $file;

        if ( ! file_exists( $local_path ) ) {
            $issues[] = array(
                'type'        => 'missing_core_file',
                'file'        => $local_path,
                'pattern'     => 'N/A',
                'description' => "Core file MISSING: {$file} (expected hash: {$expected_hash})",
                'match_lines' => array(),
                'status'      => 'detected',
                'found_at'    => time(),
            );
            continue;
        }

        $local_hash = @md5_file( $local_path );
        if ( $local_hash !== false && $local_hash !== $expected_hash ) {
            $issues[] = array(
                'type'        => 'modified_core_file',
                'file'        => $local_path,
                'relative'    => $file,
                'pattern'     => 'checksum_mismatch',
                'description' => "Core file MODIFIED: {$file} (expected: {$expected_hash}, found: {$local_hash})",
                'match_lines' => array(),
                'file_mtime'  => filemtime( $local_path ),
                'status'      => 'detected',
                'found_at'    => time(),
            );
        }
    }

    return $issues;
}

/**
 * Fetch WordPress core checksums from the official API.
 */
function aag_fetch_core_checksums( $version, $locale ) {
    $transient_key = 'aag_core_checksums_' . md5( $version . $locale );
    $cached        = get_transient( $transient_key );
    if ( $cached ) {
        return $cached;
    }

    $response = wp_remote_get(
        "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$locale}",
        array( 'timeout' => 15 )
    );
    if ( ! is_wp_error( $response ) ) {
        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( ! empty( $data['checksums'] ) && isset( $data['checksums'][ $version ] ) ) {
            $checksums = $data['checksums'][ $version ];
            set_transient( $transient_key, $checksums, HOUR_IN_SECONDS * 6 );
            return $checksums;
        }
    }

    // Retry with en_US locale.
    if ( $locale !== 'en_US' ) {
        $response = wp_remote_get(
            "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale=en_US",
            array( 'timeout' => 15 )
        );
        if ( ! is_wp_error( $response ) ) {
            $data = json_decode( wp_remote_retrieve_body( $response ), true );
            if ( ! empty( $data['checksums'] ) && isset( $data['checksums'][ $version ] ) ) {
                $checksums = $data['checksums'][ $version ];
                set_transient( $transient_key, $checksums, HOUR_IN_SECONDS * 6 );
                return $checksums;
            }
        }
    }

    return array();
}

// ── PLUGIN INTEGRITY (BASELINE) ────────────────────────────────────

/**
 * Build or compare a baseline hash of all plugin PHP files.
 * On first run: stores the baseline. Subsequently: compares against it.
 */
function aag_check_plugin_integrity() {
    $issues   = array();
    $baseline = get_option( AAG_SCAN_OPTION_BASELINE, array() );

    if ( ! is_dir( WP_PLUGIN_DIR ) ) {
        return $issues;
    }

    $own_dir = realpath( plugin_dir_path( __FILE__ ) );

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( WP_PLUGIN_DIR, RecursiveDirectoryIterator::SKIP_DOTS )
        );
    } catch ( Exception $e ) {
        return $issues;
    }

    $current_hashes = array();
    foreach ( $iterator as $file ) {
        if ( ! $file->isFile() ) continue;
        if ( $file->getExtension() !== 'php' ) continue;
        if ( $file->getSize() > AAG_SCAN_MAX_FILE_SIZE ) continue;

        $fp = $file->getRealPath();
        // Skip our own plugin files.
        if ( $own_dir && strpos( $fp, $own_dir ) === 0 ) continue;

        $hash                  = @md5_file( $fp );
        $current_hashes[ $fp ] = $hash;
    }

    if ( empty( $baseline ) ) {
        // First run — establish baseline.
        update_option( AAG_SCAN_OPTION_BASELINE, $current_hashes, 'no' );
        return $issues;
    }

    // Compare.
    foreach ( $current_hashes as $fp => $hash ) {
        if ( ! isset( $baseline[ $fp ] ) ) {
            $issues[] = array(
                'type'        => 'new_plugin_file',
                'file'        => $fp,
                'pattern'     => 'new_file',
                'description' => 'New/unexpected plugin file detected (not in baseline): ' . str_replace( WP_PLUGIN_DIR, '', $fp ),
                'match_lines' => array(),
                'file_mtime'  => @filemtime( $fp ),
                'status'      => 'detected',
                'found_at'    => time(),
            );
        } elseif ( $baseline[ $fp ] !== $hash ) {
            $issues[] = array(
                'type'        => 'modified_plugin_file',
                'file'        => $fp,
                'pattern'     => 'hash_mismatch',
                'description' => 'Plugin file MODIFIED since baseline: ' . str_replace( WP_PLUGIN_DIR, '', $fp ),
                'match_lines' => array(),
                'file_mtime'  => @filemtime( $fp ),
                'status'      => 'detected',
                'found_at'    => time(),
            );
        }
    }

    // Check for deleted files.
    foreach ( array_keys( $baseline ) as $baseline_fp ) {
        if ( ! isset( $current_hashes[ $baseline_fp ] ) && file_exists( dirname( $baseline_fp ) ) ) {
            $issues[] = array(
                'type'        => 'deleted_plugin_file',
                'file'        => $baseline_fp,
                'pattern'     => 'deleted_file',
                'description' => 'Plugin file DELETED since baseline: ' . str_replace( WP_PLUGIN_DIR, '', $baseline_fp ),
                'match_lines' => array(),
                'status'      => 'detected',
                'found_at'    => time(),
            );
        }
    }

    return $issues;
}

// ── AUTO-REPAIR SYSTEM ─────────────────────────────────────────────

/**
 * Repair a modified WordPress core file by downloading the original
 * from WordPress.org and replacing the local copy.
 */
function aag_repair_core_file( $relative_path ) {
    global $wp_version;
    $version = preg_replace( '/-.*$/', '', $wp_version ?? get_bloginfo( 'version' ) );
    $locale  = get_locale();

    $download_url = "https://core.svn.wordpress.org/tags/{$version}/{$relative_path}";

    $response = wp_remote_get( $download_url, array( 'timeout' => 30 ) );
    if ( is_wp_error( $response ) ) {
        // Try alternative CDN.
        $download_url = "https://downloads.wordpress.org/release/{$version}/wordpress/{$relative_path}";
        $response     = wp_remote_get( $download_url, array( 'timeout' => 30 ) );
    }

    if ( is_wp_error( $response ) ) {
        return false;
    }

    $body = wp_remote_retrieve_body( $response );
    if ( empty( $body ) ) {
        return false;
    }

    $local_path = ABSPATH . $relative_path;
    $dir        = dirname( $local_path );

    if ( ! is_dir( $dir ) ) {
        wp_mkdir_p( $dir );
    }

    // Backup the infected file before overwriting.
    $backup_path = $local_path . '.aag_backup_' . time();
    @copy( $local_path, $backup_path );

    $result = @file_put_contents( $local_path, $body );

    if ( $result !== false ) {
        aag_log(
            'core_file_repaired',
            'info',
            sprintf( 'Core file AUTO-REPAIRED: %s (backed up to %s)', $relative_path, basename( $backup_path ) ),
            null
        );
        return true;
    }

    return false;
}

/**
 * Quarantine a threat file — move it to an inaccessible directory.
 */
function aag_quarantine_malware_file( $file_path ) {
    if ( ! file_exists( $file_path ) ) {
        return false;
    }

    // Prevent self-bricking: never quarantine critical WordPress files or this plugin itself.
    $real = realpath( $file_path );
    $critical_files = array(
        realpath( ABSPATH . 'wp-config.php' ),
        realpath( dirname( ABSPATH ) . '/wp-config.php' ),
        realpath( ABSPATH . 'wp-settings.php' ),
        realpath( ABSPATH . 'wp-load.php' ),
        realpath( __FILE__ ),
        realpath( dirname( __FILE__ ) . '/plugin-features.php' ),
        realpath( dirname( __FILE__ ) . '/plugin-404-logs.php' ),
        realpath( dirname( __FILE__ ) . '/plugin-brute-force.php' ),
    );
    if ( $real && in_array( $real, array_filter( $critical_files ), true ) ) {
        return false;
    }

    $quarantine_dir = plugin_dir_path( __FILE__ ) . 'quarantine/';

    if ( ! is_dir( $quarantine_dir ) ) {
        wp_mkdir_p( $quarantine_dir );
    }

    // Write .htaccess to prevent any web access to quarantine folder.
    $htaccess = $quarantine_dir . '.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        @file_put_contents( $htaccess, "Order Deny,Allow\nDeny from all\n" );
    }
    // Nginx guard file (in case server is Nginx — instructions shown in UI).
    $nginx_guard = $quarantine_dir . 'index.php';
    if ( ! file_exists( $nginx_guard ) ) {
        @file_put_contents( $nginx_guard, "<?php // Silence is golden\n" );
    }

    $token            = function_exists( 'random_bytes' ) ? bin2hex( random_bytes( 8 ) ) : uniqid( 'q', true );
    $quarantine_name  = md5( $file_path ) . '_' . $token . '.quarantine';
    $quarantine_path  = $quarantine_dir . $quarantine_name;

    if ( ! @rename( $file_path, $quarantine_path ) ) {
        return false;
    }

    // Record in quarantine log.
    $quarantine_log = get_option( AAG_SCAN_OPTION_QUARANTINE, array() );
    if ( ! is_array( $quarantine_log ) ) {
        $quarantine_log = array();
    }
    $quarantine_log[] = array(
        'original_path'   => $file_path,
        'quarantine_path' => $quarantine_path,
        'quarantined_at'  => time(),
        'quarantined_by'  => get_current_user_id(),
    );
    update_option( AAG_SCAN_OPTION_QUARANTINE, $quarantine_log, 'no' );

    // Update threats list to mark as quarantined.
    $threats = get_option( AAG_SCAN_OPTION_THREATS, array() );
    foreach ( $threats as &$t ) {
        if ( $t['file'] === $file_path ) {
            $t['status']          = 'quarantined';
            $t['quarantine_path'] = $quarantine_path;
        }
    }
    unset( $t );
    update_option( AAG_SCAN_OPTION_THREATS, $threats, 'no' );

    aag_log( 'file_quarantined', 'warning', 'File quarantined: ' . $file_path, null );

    return true;
}

/**
 * Restore a quarantined file back to its original location.
 */
function aag_restore_quarantined_file( $quarantine_path ) {
    $quarantine_log = get_option( AAG_SCAN_OPTION_QUARANTINE, array() );

    foreach ( $quarantine_log as $key => $entry ) {
        if ( $entry['quarantine_path'] !== $quarantine_path ) {
            continue;
        }
        if ( ! file_exists( $quarantine_path ) ) {
            return false;
        }
        $dest_dir = dirname( $entry['original_path'] );
        if ( ! is_dir( $dest_dir ) ) {
            wp_mkdir_p( $dest_dir );
        }
        if ( @rename( $quarantine_path, $entry['original_path'] ) ) {
            unset( $quarantine_log[ $key ] );
            update_option( AAG_SCAN_OPTION_QUARANTINE, array_values( $quarantine_log ), 'no' );
            aag_log( 'file_restored', 'info', 'File restored from quarantine: ' . $entry['original_path'], null );
            return true;
        }
    }

    return false;
}

/**
 * Permanently delete a quarantined file.
 */
function aag_delete_quarantined_file( $quarantine_path ) {
    $quarantine_log = get_option( AAG_SCAN_OPTION_QUARANTINE, array() );

    foreach ( $quarantine_log as $key => $entry ) {
        if ( $entry['quarantine_path'] !== $quarantine_path ) {
            continue;
        }
        @unlink( $quarantine_path );
        unset( $quarantine_log[ $key ] );
        update_option( AAG_SCAN_OPTION_QUARANTINE, array_values( $quarantine_log ), 'no' );
        aag_log( 'file_deleted', 'warning', 'Quarantined file permanently deleted: ' . $entry['original_path'], null );
        return true;
    }

    return false;
}

// ── IP BLOCKING SYSTEM ─────────────────────────────────────────────

/**
 * Block an IP address and optionally write to .htaccess.
 */
function aag_block_ip( $ip, $reason = '' ) {
    if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
        return;
    }

    $blocked = get_option( AAG_BLOCKED_IPS_OPTION, array() );
    if ( ! is_array( $blocked ) ) {
        $blocked = array();
    }

    // Avoid duplicates.
    foreach ( $blocked as $entry ) {
        if ( $entry['ip'] === $ip ) {
            return;
        }
    }

    $blocked[] = array(
        'ip'         => $ip,
        'reason'     => sanitize_text_field( $reason ),
        'blocked_at' => time(),
        'blocked_by' => get_current_user_id() ?: 'system',
    );
    update_option( AAG_BLOCKED_IPS_OPTION, $blocked, 'no' );

    // Write to .htaccess (Apache).
    aag_write_htaccess_block( $ip );

    // Write to Nginx config file.
    aag_write_nginx_block_all( $blocked );

    aag_log(
        'ip_blocked',
        'critical',
        sprintf( 'IP address BLOCKED: %s — Reason: %s', $ip, $reason ),
        null
    );

    // Alert email.
    wp_mail(
        AAG_NOTIFY_EMAIL,
        sprintf( '[Security Alert] IP Blocked — %s', get_bloginfo( 'name' ) ),
        sprintf(
            "Admin Approval Guard has blocked an IP address.\n\nIP Address : %s\nReason     : %s\nTime (UTC) : %s\n\nYou can manage blocked IPs at:\n%s",
            $ip,
            $reason,
            gmdate( 'Y-m-d H:i:s' ),
            admin_url( 'admin.php?page=aag-admin-approvals&tab=blocked' )
        )
    );
}

/**
 * Unblock an IP address.
 */
function aag_unblock_ip( $ip ) {
    $blocked = get_option( AAG_BLOCKED_IPS_OPTION, array() );
    if ( ! is_array( $blocked ) ) {
        return;
    }
    $blocked = array_values( array_filter( $blocked, static fn( $e ) => $e['ip'] !== $ip ) );
    update_option( AAG_BLOCKED_IPS_OPTION, $blocked, 'no' );
    aag_write_htaccess_block_all( $blocked );
    aag_write_nginx_block_all( $blocked );
    aag_log( 'ip_unblocked', 'info', 'IP address unblocked: ' . $ip, null );
}

/**
 * Check if the current visitor's IP is blocked, and serve a 403 if so.
 */
add_action( 'init', 'aag_enforce_ip_block', 1 );
function aag_enforce_ip_block() {
    if ( is_admin() && is_user_logged_in() && current_user_can( 'manage_options' ) ) {
        return; // Never lock out the actual admin.
    }

    $ip      = aag_get_client_ip();
    $blocked = get_option( AAG_BLOCKED_IPS_OPTION, array() );

    if ( ! is_array( $blocked ) || empty( $ip ) ) {
        return;
    }

    foreach ( $blocked as $entry ) {
        if ( isset( $entry['ip'] ) && $entry['ip'] === $ip ) {
            aag_log( 'blocked_ip_access_attempt', 'critical', 'Blocked IP tried to access site: ' . $ip, null );
            http_response_code( 403 );
            exit( '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="font-family:sans-serif;text-align:center;padding:60px;background:#0f172a;color:#f8fafc;"><h1 style="color:#ef4444;">403 — Access Denied</h1><p>Your IP address (<code>' . esc_html( $ip ) . '</code>) has been blocked by the website security system.</p><p>If you believe this is an error, contact the site administrator.</p></body></html>' );
        }
    }
}

/**
 * Write .htaccess deny rules for a single IP (Apache only).
 */
function aag_write_htaccess_block( $ip ) {
    $htaccess = ABSPATH . '.htaccess';
    if ( ! file_exists( $htaccess ) || ! is_writable( $htaccess ) ) {
        return;
    }
    $content  = @file_get_contents( $htaccess );
    $marker   = '# BEGIN Admin-Approval-Guard-Blocked-IPs';
    $end      = '# END Admin-Approval-Guard-Blocked-IPs';

    $new_rule = "Deny from {$ip}";

    if ( strpos( $content, $marker ) !== false ) {
        // Inject into existing block.
        $content = preg_replace(
            '/(' . preg_quote( $end, '/' ) . ')/',
            "{$new_rule}\n$1",
            $content
        );
    } else {
        $content .= "\n{$marker}\n<RequireAll>\nRequire all granted\n{$new_rule}\n</RequireAll>\n{$end}\n";
    }

    @file_put_contents( $htaccess, $content );
}

/**
 * Rewrite the entire .htaccess blocked IP block from the stored list.
 */
function aag_write_htaccess_block_all( $blocked_list ) {
    $htaccess = ABSPATH . '.htaccess';
    if ( ! file_exists( $htaccess ) || ! is_writable( $htaccess ) ) {
        return;
    }

    $content = @file_get_contents( $htaccess );
    $marker  = '# BEGIN Admin-Approval-Guard-Blocked-IPs';
    $end     = '# END Admin-Approval-Guard-Blocked-IPs';

    // Remove existing block.
    $content = preg_replace( '/' . preg_quote( $marker, '/' ) . '.*?' . preg_quote( $end, '/' ) . '/s', '', $content );

    if ( ! empty( $blocked_list ) ) {
        $rules = array_map( static fn( $e ) => 'Deny from ' . $e['ip'], $blocked_list );
        $block = "\n{$marker}\n<RequireAll>\nRequire all granted\n" . implode( "\n", $rules ) . "\n</RequireAll>\n{$end}\n";
        $content .= $block;
    }

    @file_put_contents( $htaccess, $content );
}

/**
 * Write Nginx configuration block file in ABSPATH.
 */
function aag_write_nginx_block_all( $blocked_list ) {
    $conf_path = ABSPATH . 'nginx-blocked-ips.conf';

    $content  = "# BEGIN Admin-Approval-Guard-Blocked-IPs\n";
    if ( ! empty( $blocked_list ) ) {
        foreach ( $blocked_list as $entry ) {
            if ( isset( $entry['ip'] ) && filter_var( $entry['ip'], FILTER_VALIDATE_IP ) ) {
                $content .= "deny " . $entry['ip'] . ";\n";
            }
        }
    }
    $content .= "# END Admin-Approval-Guard-Blocked-IPs\n";

    if ( ! is_dir( dirname( $conf_path ) ) ) {
        if ( function_exists( 'wp_mkdir_p' ) ) {
            wp_mkdir_p( dirname( $conf_path ) );
        } else {
            @mkdir( dirname( $conf_path ), 0777, true );
        }
    }
    @file_put_contents( $conf_path, $content );
}

// ── SCHEDULED DAILY SCAN ───────────────────────────────────────────

add_action( 'aag_daily_malware_scan', 'aag_run_scheduled_scan' );
function aag_run_scheduled_scan() {
    $threats = aag_run_full_scan();

    if ( empty( $threats ) ) {
        aag_log( 'scheduled_scan_clean', 'info', 'Daily malware scan completed. No threats found.', null );
        return;
    }

    // Build a threat summary email.
    $critical = array_filter( $threats, static fn( $t ) => in_array( $t['type'], array( 'malware_pattern', 'modified_core_file' ), true ) );

    $lines   = array();
    $lines[] = '════════════════════════════════════════════════════';
    $lines[] = '  🚨 MALWARE SCAN ALERT — ' . get_bloginfo( 'name' );
    $lines[] = '════════════════════════════════════════════════════';
    $lines[] = '';
    $lines[] = 'Scan Time   : ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
    $lines[] = 'Total Threats: ' . count( $threats );
    $lines[] = 'Critical    : ' . count( $critical );
    $lines[] = '';
    $lines[] = '────── THREAT SUMMARY ──────';

    foreach ( $threats as $i => $t ) {
        $lines[] = sprintf( '%d. [%s] %s', $i + 1, strtoupper( $t['type'] ), $t['description'] );
        $lines[] = '   File: ' . $t['file'];
        $lines[] = '';
    }

    $lines[] = '────────────────────────────────────────────────────';
    $lines[] = 'Manage threats in your admin panel:';
    $lines[] = admin_url( 'admin.php?page=aag-admin-approvals&tab=scanner' );

    wp_mail(
        AAG_NOTIFY_EMAIL,
        sprintf( '[🚨 MALWARE ALERT] %d threat(s) found — %s', count( $threats ), get_bloginfo( 'name' ) ),
        implode( "\n", $lines ),
        array( 'Content-Type: text/plain; charset=UTF-8', 'X-Priority: 1' )
    );

    aag_log(
        'scheduled_scan_threats',
        'critical',
        sprintf( 'Daily malware scan found %d threat(s). Alert email sent to %s.', count( $threats ), AAG_NOTIFY_EMAIL ),
        null
    );

    // Auto-repair modified core files.
    foreach ( $threats as $t ) {
        if ( $t['type'] === 'modified_core_file' && isset( $t['relative'] ) ) {
            aag_repair_core_file( $t['relative'] );
        }
    }
}

// Register cron event on activation (adds to existing activation hook).
add_action( 'wp_loaded', 'aag_ensure_scanner_cron' );
function aag_ensure_scanner_cron() {
    if ( ! wp_next_scheduled( 'aag_daily_malware_scan' ) ) {
        wp_schedule_event( time(), 'daily', 'aag_daily_malware_scan' );
    }
}

// ── AJAX: MANUAL SCAN TRIGGER ──────────────────────────────────────

add_action( 'wp_ajax_aag_run_scan', 'aag_ajax_run_scan' );
function aag_ajax_run_scan() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Unauthorized.' );
    }
    check_ajax_referer( 'aag_run_scan', 'nonce' );

    $threats = aag_run_full_scan();

    wp_send_json_success( array(
        'count'   => count( $threats ),
        'threats' => array_slice( $threats, 0, 50 ), // Return first 50 for display.
    ) );
}

// ── AJAX: QUARANTINE A FILE ────────────────────────────────────────

add_action( 'wp_ajax_aag_quarantine_file', 'aag_ajax_quarantine_file' );
function aag_ajax_quarantine_file() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Unauthorized.' );
    }
    check_ajax_referer( 'aag_file_action', 'nonce' );

    $file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
    if ( empty( $file ) || ! file_exists( $file ) ) {
        wp_send_json_error( 'File not found.' );
    }

    $result = aag_quarantine_malware_file( $file );
    $result ? wp_send_json_success( 'File quarantined.' ) : wp_send_json_error( 'Could not quarantine file.' );
}

// ── AJAX: REPAIR CORE FILE ─────────────────────────────────────────

add_action( 'wp_ajax_aag_repair_file', 'aag_ajax_repair_file' );
function aag_ajax_repair_file() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Unauthorized.' );
    }
    check_ajax_referer( 'aag_file_action', 'nonce' );

    $relative = isset( $_POST['relative'] ) ? sanitize_text_field( wp_unslash( $_POST['relative'] ) ) : '';
    if ( empty( $relative ) ) {
        wp_send_json_error( 'No relative path provided.' );
    }

    $result = aag_repair_core_file( $relative );
    $result ? wp_send_json_success( 'Core file repaired from WordPress.org.' ) : wp_send_json_error( 'Could not download/repair the file. Check server permissions.' );
}

// ── AJAX: DELETE THREAT (clear from list) ─────────────────────────

add_action( 'wp_ajax_aag_dismiss_threat', 'aag_ajax_dismiss_threat' );
function aag_ajax_dismiss_threat() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Unauthorized.' );
    }
    check_ajax_referer( 'aag_file_action', 'nonce' );

    $file    = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
    $threats = get_option( AAG_SCAN_OPTION_THREATS, array() );
    $threats = array_values( array_filter( $threats, static fn( $t ) => $t['file'] !== $file ) );
    update_option( AAG_SCAN_OPTION_THREATS, $threats, 'no' );

    aag_log( 'threat_dismissed', 'info', 'Threat dismissed (marked safe): ' . $file, null );
    wp_send_json_success( 'Threat dismissed.' );
}

// ── MONITOR: Block IPs that try to upload PHP in media folder ─────

add_filter( 'wp_handle_upload_prefilter', 'aag_block_php_uploads' );
function aag_block_php_uploads( $file ) {
    $disallowed_exts = array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'shtml', 'cgi', 'pl', 'py', 'rb', 'sh', 'bash' );
    $ext             = strtolower( pathinfo( $file['name'], PATHINFO_EXTENSION ) );

    if ( in_array( $ext, $disallowed_exts, true ) ) {
        $ip = aag_get_client_ip();
        aag_block_ip( $ip, 'Attempted to upload executable file: ' . sanitize_file_name( $file['name'] ) );
        aag_log(
            'malicious_upload_blocked',
            'critical',
            sprintf( 'PHP/executable file upload BLOCKED: %s from IP %s', $file['name'], $ip ),
            null
        );
        $file['error'] = 'This file type is not allowed for security reasons. Executable files cannot be uploaded.';
    }

    return $file;
}

// ── MONITOR: Watch for suspicious POST patterns (web shell probes) ─

add_action( 'init', 'aag_detect_webshell_probe', 5 );
function aag_detect_webshell_probe() {
    if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
        return;
    }

    $suspicious_params = array( 'cmd', 'exec', 'system', 'shell', 'backdoor', 'passthru', 'eval' );
    $request_keys      = array_keys( array_merge( $_GET, $_POST ) );
    $request_keys      = array_map( 'strtolower', $request_keys );

    foreach ( $suspicious_params as $param ) {
        if ( in_array( $param, $request_keys, true ) ) {
            $ip = aag_get_client_ip();
            aag_log(
                'webshell_probe_detected',
                'critical',
                sprintf( 'Web shell probe detected (param: %s) from IP %s. IP blocked.', $param, $ip ),
                null
            );
            aag_block_ip( $ip, 'Web shell parameter probe detected: ' . $param );
            http_response_code( 403 );
            exit( '403 Forbidden' );
        }
    }
}

// ── SCANNER ADMIN TAB RENDERER ─────────────────────────────────────

function aag_render_scanner_tab() {
    // Handle form actions.
    if ( isset( $_POST['aag_scanner_action'], $_POST['aag_scanner_nonce'] ) ) {
        if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_scanner_nonce'] ) ), 'aag_scanner_action' ) ) {
            wp_die( esc_html__( 'Security check failed.', 'admin-approval-guard' ) );
        }

        $action = sanitize_key( wp_unslash( $_POST['aag_scanner_action'] ) );

        if ( $action === 'run_scan' ) {
            $threats = aag_run_full_scan();
            $cnt     = count( $threats );
            echo '<div class="notice notice-' . ( $cnt > 0 ? 'error' : 'success' ) . '"><p><strong>' .
                 esc_html( $cnt > 0 ? "⚠️ Scan complete: {$cnt} threat(s) found." : '✅ Scan complete. No threats detected!' ) .
                 '</strong></p></div>';
        } elseif ( $action === 'quarantine_file' && isset( $_POST['aag_target_file'] ) ) {
            $file = sanitize_text_field( wp_unslash( $_POST['aag_target_file'] ) );
            $ok   = aag_quarantine_malware_file( $file );
            echo '<div class="notice notice-' . ( $ok ? 'success' : 'error' ) . '"><p>' .
                 esc_html( $ok ? 'File quarantined successfully.' : 'Could not quarantine file. Check permissions.' ) .
                 '</p></div>';
        } elseif ( $action === 'repair_core_file' && isset( $_POST['aag_relative_path'] ) ) {
            $rel = sanitize_text_field( wp_unslash( $_POST['aag_relative_path'] ) );
            $ok  = aag_repair_core_file( $rel );
            echo '<div class="notice notice-' . ( $ok ? 'success' : 'error' ) . '"><p>' .
                 esc_html( $ok ? '✅ Core file repaired from WordPress.org.' : '❌ Repair failed. Check server internet access / permissions.' ) .
                 '</p></div>';
        } elseif ( $action === 'dismiss_threat' && isset( $_POST['aag_target_file'] ) ) {
            $file    = sanitize_text_field( wp_unslash( $_POST['aag_target_file'] ) );
            $threats = get_option( AAG_SCAN_OPTION_THREATS, array() );
            $threats = array_values( array_filter( $threats, static fn( $t ) => $t['file'] !== $file ) );
            update_option( AAG_SCAN_OPTION_THREATS, $threats, 'no' );
            aag_log( 'threat_dismissed', 'info', 'Threat marked safe: ' . $file, null );
            echo '<div class="notice notice-success"><p>✅ Threat dismissed.</p></div>';
        } elseif ( $action === 'rebuild_baseline' ) {
            delete_option( AAG_SCAN_OPTION_BASELINE );
            echo '<div class="notice notice-success"><p>✅ Plugin file baseline cleared. It will be rebuilt on the next scan.</p></div>';
        }
    }

    // Handle quarantine restore / delete.
    if ( isset( $_POST['aag_quarantine_action'], $_POST['aag_scanner_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_scanner_nonce'] ) ), 'aag_scanner_action' ) ) {
            $qaction = sanitize_key( wp_unslash( $_POST['aag_quarantine_action'] ) );
            $qpath   = isset( $_POST['aag_quarantine_path'] ) ? sanitize_text_field( wp_unslash( $_POST['aag_quarantine_path'] ) ) : '';
            if ( $qaction === 'restore' ) {
                $ok = aag_restore_quarantined_file( $qpath );
                echo '<div class="notice notice-' . ( $ok ? 'success' : 'error' ) . '"><p>' . esc_html( $ok ? 'File restored.' : 'Restore failed.' ) . '</p></div>';
            } elseif ( $qaction === 'delete' ) {
                $ok = aag_delete_quarantined_file( $qpath );
                echo '<div class="notice notice-' . ( $ok ? 'success' : 'error' ) . '"><p>' . esc_html( $ok ? 'File permanently deleted.' : 'Delete failed.' ) . '</p></div>';
            }
        }
    }

    $threats       = get_option( AAG_SCAN_OPTION_THREATS, array() );
    $quarantined   = get_option( AAG_SCAN_OPTION_QUARANTINE, array() );
    $last_run      = get_option( AAG_SCAN_OPTION_LAST_RUN, 0 );
    $next_scan     = wp_next_scheduled( 'aag_daily_malware_scan' );

    $type_colors = array(
        'malware_pattern'      => '#dc2626',
        'modified_core_file'   => '#b45309',
        'missing_core_file'    => '#7c3aed',
        'modified_plugin_file' => '#0369a1',
        'new_plugin_file'      => '#0369a1',
        'deleted_plugin_file'  => '#6b7280',
    );
    ?>
    <h2>🔍 Malware Scanner &amp; File Integrity</h2>

    <!-- Status Bar -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
        <?php
        $stats = array(
            array( 'label' => 'Threats Found',   'val' => count( $threats ),                                    'color' => count($threats) > 0 ? '#dc2626' : '#16a34a' ),
            array( 'label' => 'Quarantined',      'val' => count( $quarantined ),                                'color' => '#d97706' ),
            array( 'label' => 'Last Scan',        'val' => $last_run ? human_time_diff( $last_run ) . ' ago' : 'Never', 'color' => '#2563eb' ),
            array( 'label' => 'Next Auto-Scan',   'val' => $next_scan ? human_time_diff( $next_scan ) : 'Not scheduled', 'color' => '#7c3aed' ),
        );
        foreach ( $stats as $s ) : ?>
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.05);">
                <div style="font-size:28px;font-weight:800;color:<?php echo esc_attr( $s['color'] ); ?>;"><?php echo esc_html( $s['val'] ); ?></div>
                <div style="font-size:12px;color:#64748b;margin-top:4px;"><?php echo esc_html( $s['label'] ); ?></div>
            </div>
        <?php endforeach; ?>
    </div>

    <!-- Run Scan Form -->
    <form method="post" style="margin-bottom:20px;">
        <?php wp_nonce_field( 'aag_scanner_action', 'aag_scanner_nonce' ); ?>
        <input type="hidden" name="aag_scanner_action" value="run_scan">
        <button type="submit" class="button button-primary" style="background:#dc2626;border-color:#b91c1c;font-size:14px;height:36px;padding:0 20px;">
            🔍 Run Full Scan Now
        </button>
        <button type="submit" class="button button-secondary" style="margin-left:8px;"
            onclick="this.form.aag_scanner_action.value='rebuild_baseline'; return confirm('Rebuild plugin baseline? This will reset change detection.')">
            🔄 Rebuild Plugin Baseline
        </button>
        <span style="margin-left:12px;color:#64748b;font-size:12px;">⏱ Scans run automatically every 24 hours. The scanner checks plugins, themes, uploads, and core files.</span>
    </form>

    <!-- Threats Table -->
    <?php if ( empty( $threats ) ) : ?>
        <div style="background:#f0fdf4;border:1px solid #86efac;padding:24px;border-radius:8px;text-align:center;">
            <p style="color:#16a34a;margin:0;font-size:16px;font-weight:700;">✅ No threats detected. Your site is clean!</p>
            <p style="color:#64748b;margin:8px 0 0;font-size:13px;">Run a scan above or wait for the daily automatic scan.</p>
        </div>
    <?php else : ?>
        <h3 style="color:#dc2626;">⚠️ <?php echo esc_html( count( $threats ) ); ?> Threat(s) Detected</h3>
        <?php foreach ( $threats as $threat ) :
            $color  = $type_colors[ $threat['type'] ] ?? '#6b7280';
            $status = $threat['status'];
            ?>
            <div style="background:#fff;border:1px solid #e2e8f0;border-left:4px solid <?php echo esc_attr( $color ); ?>;border-radius:8px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.04);">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;">
                    <div>
                        <span style="background:<?php echo esc_attr( $color ); ?>;color:#fff;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;">
                            <?php echo esc_html( str_replace( '_', ' ', $threat['type'] ) ); ?>
                        </span>
                        &nbsp;
                        <span style="font-size:12px;color:#64748b;"><?php echo esc_html( $status ); ?></span>
                        <p style="margin:6px 0 2px;font-size:13px;font-weight:600;color:#0f172a;"><?php echo esc_html( $threat['description'] ); ?></p>
                        <code style="font-size:11px;color:#475569;word-break:break-all;"><?php echo esc_html( $threat['file'] ); ?></code>
                        <?php if ( ! empty( $threat['file_mtime'] ) ) : ?>
                            <p style="margin:4px 0 0;font-size:11px;color:#94a3b8;">Last modified: <?php echo esc_html( gmdate( 'Y-m-d H:i:s', $threat['file_mtime'] ) ); ?> UTC</p>
                        <?php endif; ?>
                        <?php if ( ! empty( $threat['match_lines'] ) ) : ?>
                            <div style="margin-top:8px;background:#fef2f2;border:1px solid #fecaca;border-radius:4px;padding:8px;font-size:11px;">
                                <strong>Matched Lines:</strong>
                                <?php foreach ( array_slice( $threat['match_lines'], 0, 3 ) as $ml ) : ?>
                                    <div><span style="color:#94a3b8;">L<?php echo esc_html( $ml['line'] ); ?>:</span> <code><?php echo esc_html( $ml['content'] ); ?></code></div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                    <div style="display:flex;flex-direction:column;gap:6px;min-width:160px;">
                        <?php if ( $status === 'detected' ) : ?>
                            <?php if ( $threat['type'] === 'modified_core_file' && isset( $threat['relative'] ) ) : ?>
                                <form method="post">
                                    <?php wp_nonce_field( 'aag_scanner_action', 'aag_scanner_nonce' ); ?>
                                    <input type="hidden" name="aag_scanner_action" value="repair_core_file">
                                    <input type="hidden" name="aag_relative_path" value="<?php echo esc_attr( $threat['relative'] ); ?>">
                                    <button type="submit" class="button" style="background:#16a34a;color:#fff;border-color:#16a34a;width:100%;"
                                        onclick="return confirm('Download and restore this core file from WordPress.org?')">
                                        🔧 Auto-Repair
                                    </button>
                                </form>
                            <?php endif; ?>
                            <form method="post">
                                <?php wp_nonce_field( 'aag_scanner_action', 'aag_scanner_nonce' ); ?>
                                <input type="hidden" name="aag_scanner_action" value="quarantine_file">
                                <input type="hidden" name="aag_target_file" value="<?php echo esc_attr( $threat['file'] ); ?>">
                                <button type="submit" class="button button-secondary" style="width:100%;color:#d97706;border-color:#fbbf24;"
                                    onclick="return confirm('Move this file to quarantine? It will be inaccessible until restored.')">
                                    🔒 Quarantine
                                </button>
                            </form>
                            <form method="post">
                                <?php wp_nonce_field( 'aag_scanner_action', 'aag_scanner_nonce' ); ?>
                                <input type="hidden" name="aag_scanner_action" value="dismiss_threat">
                                <input type="hidden" name="aag_target_file" value="<?php echo esc_attr( $threat['file'] ); ?>">
                                <button type="submit" class="button button-secondary" style="width:100%;font-size:11px;">
                                    ✓ Mark Safe
                                </button>
                            </form>
                        <?php elseif ( $status === 'quarantined' ) : ?>
                            <span style="color:#d97706;font-size:12px;font-weight:600;">🔒 In Quarantine</span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <!-- Quarantined Files Table -->
    <?php if ( ! empty( $quarantined ) ) : ?>
        <h3 style="margin-top:32px;">🔒 Quarantined Files (<?php echo esc_html( count( $quarantined ) ); ?>)</h3>
        <table class="wp-list-table widefat fixed striped" style="font-size:13px;">
            <thead>
                <tr>
                    <th>Original Path</th>
                    <th style="width:160px;">Quarantined At</th>
                    <th style="width:180px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $quarantined as $q ) : ?>
                    <tr>
                        <td><code style="font-size:11px;word-break:break-all;"><?php echo esc_html( $q['original_path'] ); ?></code></td>
                        <td><?php echo esc_html( gmdate( 'Y-m-d H:i', $q['quarantined_at'] ) . ' UTC' ); ?></td>
                        <td>
                            <form method="post" style="display:inline;">
                                <?php wp_nonce_field( 'aag_scanner_action', 'aag_scanner_nonce' ); ?>
                                <input type="hidden" name="aag_quarantine_action" value="restore">
                                <input type="hidden" name="aag_quarantine_path" value="<?php echo esc_attr( $q['quarantine_path'] ); ?>">
                                <button type="submit" class="button button-secondary button-small"
                                    onclick="return confirm('Restore this file? It will be accessible again.')">↩ Restore</button>
                            </form>
                            <form method="post" style="display:inline;margin-left:4px;">
                                <?php wp_nonce_field( 'aag_scanner_action', 'aag_scanner_nonce' ); ?>
                                <input type="hidden" name="aag_quarantine_action" value="delete">
                                <input type="hidden" name="aag_quarantine_path" value="<?php echo esc_attr( $q['quarantine_path'] ); ?>">
                                <button type="submit" class="button button-secondary button-small" style="color:#dc2626;"
                                    onclick="return confirm('PERMANENTLY DELETE this file? This cannot be undone.')">🗑 Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <!-- Nginx Note -->
    <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:16px;margin-top:24px;">
        <h3 style="margin: 0 0 10px; font-size: 15px;">📋 Nginx Server Hardening Instructions</h3>
        <p style="margin: 0 0 8px; color: #4b5563;">
            Because Nginx ignores <code>.htaccess</code> files, you must add these rules directly to your Nginx configuration:
        </p>
        <p><strong>1. Enable IP Lockouts at Web Server Layer:</strong></p>
        <pre style="background:#fefefe;border:1px solid #e2e8f0;padding:8px;margin:4px 0 12px;font-size:12px;border-radius:4px;overflow-x:auto;">include <?php echo esc_html( ABSPATH . 'nginx-blocked-ips.conf' ); ?>;</pre>
        
        <p><strong>2. Block PHP Execution inside Uploads Directory (Returns 403 Forbidden):</strong></p>
        <pre style="background:#fefefe;border:1px solid #e2e8f0;padding:8px;margin:4px 0 0;font-size:12px;border-radius:4px;overflow-x:auto;">include <?php echo esc_html( ABSPATH . 'nginx-uploads-hardening.conf' ); ?>;</pre>
    </div>
    <?php
}

// ── BLOCKED IPS ADMIN TAB ──────────────────────────────────────────

function aag_render_blocked_ips_tab() {
    // Handle unblock action.
    if ( isset( $_POST['aag_unblock_ip'], $_POST['aag_block_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_block_nonce'] ) ), 'aag_block_action' ) ) {
            $ip = sanitize_text_field( wp_unslash( $_POST['aag_unblock_ip'] ) );
            aag_unblock_ip( $ip );
            echo '<div class="notice notice-success"><p>✅ IP ' . esc_html( $ip ) . ' unblocked.</p></div>';
        }
    }

    // Handle manual block.
    if ( isset( $_POST['aag_manual_block_ip'], $_POST['aag_block_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_block_nonce'] ) ), 'aag_block_action' ) ) {
            $ip     = sanitize_text_field( wp_unslash( $_POST['aag_manual_block_ip'] ) );
            $reason = sanitize_text_field( wp_unslash( $_POST['aag_block_reason'] ?? 'Manually blocked by admin' ) );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                aag_block_ip( $ip, $reason );
                echo '<div class="notice notice-success"><p>✅ IP ' . esc_html( $ip ) . ' blocked.</p></div>';
            } else {
                echo '<div class="notice notice-error"><p>❌ Invalid IP address.</p></div>';
            }
        }
    }

    $blocked = get_option( AAG_BLOCKED_IPS_OPTION, array() );
    ?>
    <h2>🚫 Blocked IP Addresses</h2>

    <!-- Manual block form -->
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;margin-bottom:24px;">
        <h3 style="margin:0 0 12px;">Manually Block an IP</h3>
        <form method="post" style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
            <?php wp_nonce_field( 'aag_block_action', 'aag_block_nonce' ); ?>
            <div>
                <label style="display:block;font-size:12px;margin-bottom:4px;color:#64748b;">IP Address *</label>
                <input type="text" name="aag_manual_block_ip" placeholder="e.g. 192.0.2.1" class="regular-text" required>
            </div>
            <div>
                <label style="display:block;font-size:12px;margin-bottom:4px;color:#64748b;">Reason</label>
                <input type="text" name="aag_block_reason" placeholder="Reason (optional)" class="regular-text">
            </div>
            <button type="submit" class="button" style="background:#dc2626;color:#fff;border-color:#b91c1c;">🚫 Block IP</button>
        </form>
    </div>

    <?php if ( empty( $blocked ) ) : ?>
        <div style="background:#f0fdf4;border:1px solid #86efac;padding:20px;border-radius:8px;text-align:center;">
            <p style="color:#16a34a;margin:0;font-weight:600;">✅ No IPs currently blocked.</p>
        </div>
    <?php else : ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th style="width:160px;">IP Address</th>
                    <th>Reason</th>
                    <th style="width:180px;">Blocked At (UTC)</th>
                    <th style="width:80px;">By</th>
                    <th style="width:100px;">Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( array_reverse( $blocked ) as $entry ) : ?>
                    <tr>
                        <td><strong><code><?php echo esc_html( $entry['ip'] ); ?></code></strong></td>
                        <td><?php echo esc_html( $entry['reason'] ); ?></td>
                        <td><?php echo esc_html( gmdate( 'Y-m-d H:i:s', $entry['blocked_at'] ) ); ?></td>
                        <td><?php echo esc_html( $entry['blocked_by'] ); ?></td>
                        <td>
                            <form method="post" onsubmit="return confirm('Unblock this IP?')">
                                <?php wp_nonce_field( 'aag_block_action', 'aag_block_nonce' ); ?>
                                <input type="hidden" name="aag_unblock_ip" value="<?php echo esc_attr( $entry['ip'] ); ?>">
                                <button type="submit" class="button button-secondary button-small">✓ Unblock</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <?php
}

// ────────────────────────────────────────────────────────────────────
// AUDIT LOGGER
// ────────────────────────────────────────────────────────────────────

function aag_log( $event_type, $severity, $details, $user_id = null ) {
    $logs = get_option( AAG_OPTION_LOG, array() );
    if ( ! is_array( $logs ) ) {
        $logs = array();
    }

    $actor = 'system';
    if ( $user_id && ( $u = get_userdata( $user_id ) ) ) {
        $actor = $u->user_login;
    } elseif ( is_user_logged_in() ) {
        $actor = wp_get_current_user()->user_login;
    }

    array_unshift( $logs, array(
        'timestamp'  => time(),
        'event_type' => sanitize_text_field( $event_type ),
        'severity'   => sanitize_text_field( $severity ),
        'details'    => sanitize_text_field( $details ),
        'ip'         => aag_get_client_ip(),
        'actor'      => $actor,
    ) );

    // Cap log size.
    if ( count( $logs ) > AAG_LOG_LIMIT ) {
        $logs = array_slice( $logs, 0, AAG_LOG_LIMIT );
    }

    update_option( AAG_OPTION_LOG, $logs, 'no' );
}

// ────────────────────────────────────────────────────────────────────
// ADMIN NOTICE: Warn about pending requests on every admin page.
// ────────────────────────────────────────────────────────────────────

add_action( 'admin_notices', 'aag_admin_pending_notice' );
function aag_admin_pending_notice() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $pending = get_option( AAG_OPTION_PENDING, array() );
    $count   = count( array_filter( $pending, static fn( $e ) => $e['status'] === 'pending' ) );
    if ( $count > 0 ) {
        printf(
            '<div class="notice notice-error"><p><strong>🔴 Admin Approval Guard:</strong> %s <a href="%s">%s</a></p></div>',
            esc_html( sprintf( _n( 'There is %d pending administrator request awaiting your approval.', 'There are %d pending administrator requests awaiting your approval.', $count, 'admin-approval-guard' ), $count ) ),
            esc_url( admin_url( 'admin.php?page=aag-admin-approvals' ) ),
            esc_html__( 'Review Now →', 'admin-approval-guard' )
        );
    }

    // Warn if there are active threats.
    $threats = get_option( AAG_SCAN_OPTION_THREATS, array() );
    $active  = count( array_filter( $threats, static fn( $t ) => $t['status'] === 'detected' ) );
    if ( $active > 0 ) {
        printf(
            '<div class="notice notice-error"><p><strong>🚨 Malware Scanner:</strong> %d active threat(s) detected on your site! <a href="%s">Review &amp; Fix →</a></p></div>',
            $active,
            esc_url( admin_url( 'admin.php?page=aag-admin-approvals&tab=scanner' ) )
        );
    }
}

// LOAD ADDITIONAL MODULES
// ────────────────────────────────────────────────────────────────────
require_once dirname( __FILE__ ) . '/plugin-features.php';
require_once dirname( __FILE__ ) . '/plugin-404-logs.php';
require_once dirname( __FILE__ ) . '/plugin-brute-force.php';
