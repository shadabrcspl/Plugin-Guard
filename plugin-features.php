<?php
defined( 'ABSPATH' ) || exit;

// ────────────────────────────────────────────────────────────────────
// SETTINGS PAGE
// ────────────────────────────────────────────────────────────────────
function aag_render_settings_page() {
    if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Access Denied' ); }
    if ( isset( $_POST['aag_save_settings'], $_POST['aag_settings_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_settings_nonce'] ) ), 'aag_save_settings' ) ) {
        $disable_file_mods = isset( $_POST['disable_file_mods'] ) ? 1 : 0;
        aag_write_wp_config_file_mods( $disable_file_mods );

        $settings = array(
            'enable_plugin_updates'      => isset( $_POST['enable_plugin_updates'] ) ? 1 : 0,
            'enable_theme_updates'       => isset( $_POST['enable_theme_updates'] ) ? 1 : 0,
            'enable_404_redirect'        => isset( $_POST['enable_404_redirect'] ) ? intval( $_POST['enable_404_redirect'] ) : 0,
            'brute_force_attempts'       => isset( $_POST['brute_force_attempts'] ) ? absint( $_POST['brute_force_attempts'] ) : 5,
            'brute_force_duration'       => isset( $_POST['brute_force_duration'] ) ? absint( $_POST['brute_force_duration'] ) : 60,
            'disable_xmlrpc'             => isset( $_POST['disable_xmlrpc'] ) ? 1 : 0,
            'disable_rest_api_guests'    => isset( $_POST['disable_rest_api_guests'] ) ? 1 : 0,
            'enable_security_headers'    => isset( $_POST['enable_security_headers'] ) ? 1 : 0,
            'disable_author_scanning'    => isset( $_POST['disable_author_scanning'] ) ? 1 : 0,
            'enable_registration_antispam'=> isset( $_POST['enable_registration_antispam'] ) ? 1 : 0,
        );
        update_option( AAG_OPTION_SETTINGS, $settings, 'no' );
        echo '<div class="notice notice-success"><p>Settings saved successfully.</p></div>';
    }

    // Handle manual purge revisions trigger
    if ( isset( $_POST['aag_purge_revisions_btn'], $_POST['aag_purge_revisions_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_purge_revisions_nonce'] ) ), 'aag_purge_revisions_action' ) ) {
            $purged_count = aag_purge_spam_revisions();
            echo '<div class="notice notice-success"><p>✅ Database Scan Complete: ' . esc_html( sprintf( _n( 'Removed %d spam revision from the database.', 'Removed %d spam revisions from the database.', $purged_count, 'admin-approval-guard' ), $purged_count ) ) . '</p></div>';
        }
    }

    // Handle database password change trigger
    if ( isset( $_POST['aag_change_db_password_btn'], $_POST['aag_change_db_password_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_change_db_password_nonce'] ) ), 'aag_change_db_password_action' ) ) {
            $new_pass = sanitize_text_field( $_POST['aag_new_db_password'] );
            if ( strlen( $new_pass ) < 8 ) {
                echo '<div class="notice notice-error"><p>❌ Database password must be at least 8 characters long.</p></div>';
            } else {
                $result = aag_change_database_password( $new_pass );
                if ( is_wp_error( $result ) ) {
                    echo '<div class="notice notice-error"><p>❌ ' . esc_html( $result->get_error_message() ) . '</p></div>';
                } else {
                    echo '<div class="notice notice-success"><p>✅ Database password changed successfully in both database and wp-config.php.</p></div>';
                }
            }
        }
    }

    // Handle manual wp-config.php write toggle
    if ( isset( $_POST['aag_toggle_wp_config_writable_btn'], $_POST['aag_wp_config_perms_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_wp_config_perms_nonce'] ) ), 'aag_wp_config_perms_action' ) ) {
            $wp_config_path = '';
            if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
                $wp_config_path = ABSPATH . 'wp-config.php';
            } elseif ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
                $wp_config_path = dirname( ABSPATH ) . '/wp-config.php';
            }

            if ( $wp_config_path ) {
                if ( is_writable( $wp_config_path ) ) {
                    if ( @chmod( $wp_config_path, 0444 ) ) {
                        echo '<div class="notice notice-success"><p>🔒 wp-config.php has been successfully locked (made Read-Only).</p></div>';
                    } else {
                        echo '<div class="notice notice-error"><p>❌ Failed to lock wp-config.php. Check your VPS file ownership permissions.</p></div>';
                    }
                } else {
                    if ( @chmod( $wp_config_path, 0644 ) ) {
                        echo '<div class="notice notice-success"><p>🔓 wp-config.php has been successfully unlocked (made Writable).</p></div>';
                    } else {
                        echo '<div class="notice notice-error"><p>❌ Failed to unlock wp-config.php. Check your VPS file ownership permissions.</p></div>';
                    }
                }
            } else {
                echo '<div class="notice notice-error"><p>❌ wp-config.php file could not be located.</p></div>';
            }
        }
    }

    $settings = get_option( AAG_OPTION_SETTINGS, array( 'enable_plugin_updates' => 1, 'enable_theme_updates' => 1, 'enable_404_redirect' => 1 ) );
    ?>
    <div class="wrap">
        <h1>Admin Approval Guard - Settings</h1>
        <form method="post" action="">
            <?php wp_nonce_field( 'aag_save_settings', 'aag_settings_nonce' ); ?>
            <table class="form-table">
                <tr>
                    <th scope="row">Enable Plugin Updates</th>
                    <td><label><input type="checkbox" name="enable_plugin_updates" value="1" <?php checked( $settings['enable_plugin_updates'], 1 ); ?>> Allow WordPress to check for and install plugin updates.</label></td>
                </tr>
                <tr>
                    <th scope="row">Enable Theme Updates</th>
                    <td><label><input type="checkbox" name="enable_theme_updates" value="1" <?php checked( $settings['enable_theme_updates'], 1 ); ?>> Allow WordPress to check for and install theme updates.</label></td>
                </tr>
                <tr>
                    <th scope="row">404 (Not Found) Action</th>
                    <td>
                        <select name="enable_404_redirect">
                            <option value="0" <?php selected( isset( $settings['enable_404_redirect'] ) ? intval( $settings['enable_404_redirect'] ) : 1, 0 ); ?>>Show Standard WordPress 404 Page</option>
                            <option value="1" <?php selected( isset( $settings['enable_404_redirect'] ) ? intval( $settings['enable_404_redirect'] ) : 1, 1 ); ?>>301 Redirect to Homepage (Best for active links)</option>
                            <option value="2" <?php selected( isset( $settings['enable_404_redirect'] ) ? intval( $settings['enable_404_redirect'] ) : 1, 2 ); ?>>410 Gone Page (Recommended to remove deleted spam pages from Google Index)</option>
                        </select>
                        <p class="description" style="margin-top: 4px; color:#64748b;">
                            If your site was hacked and spam pages were created, using <strong>410 Gone</strong> signals to Googlebot that those pages are permanently deleted, helping clean your search index much faster.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Brute Force Limit</th>
                    <td>
                        <input type="number" name="brute_force_attempts" value="<?php echo isset( $settings['brute_force_attempts'] ) ? absint( $settings['brute_force_attempts'] ) : 5; ?>" min="1" max="20" style="width: 70px;"> failed attempts within 15 minutes before IP lockout.
                    </td>
                </tr>
                <tr>
                    <th scope="row">Hardened Write Protection (wp-config.php)</th>
                    <td>
                        <label>
                            <input type="checkbox" name="disable_file_mods" value="1" <?php checked( defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS, true ); ?>> 
                            <strong>Disable dashboard installation/modification of plugins and themes.</strong>
                        </label>
                        <p class="description" style="margin-top: 4px; color:#64748b;">
                            This writes a security lock to your <code>wp-config.php</code> file. It completely prevents anyone (even administrators or exploits) from installing new plugins/themes or modifying files from the dashboard. Turn this off temporarily when you need to run updates.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Disable XML-RPC</th>
                    <td>
                        <label>
                            <input type="checkbox" name="disable_xmlrpc" value="1" <?php checked( isset( $settings['disable_xmlrpc'] ) ? $settings['disable_xmlrpc'] : 0, 1 ); ?>> 
                            <strong>Block all XML-RPC incoming requests.</strong>
                        </label>
                        <p class="description" style="margin-top: 4px; color:#64748b;">
                            Blocks remote calls to <code>xmlrpc.php</code>. This stops brute force attacks targeting XML-RPC endpoints (highly recommended unless you use Jetpack or the WP Mobile App).
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Restrict REST API for Guests</th>
                    <td>
                        <label>
                            <input type="checkbox" name="disable_rest_api_guests" value="1" <?php checked( isset( $settings['disable_rest_api_guests'] ) ? $settings['disable_rest_api_guests'] : 0, 1 ); ?>> 
                            <strong>Block REST API access for unauthenticated visitors.</strong>
                        </label>
                        <p class="description" style="margin-top: 4px; color:#64748b;">
                            Prevents anonymous guest users from grabbing listings of your WordPress users or posts via public API queries (e.g. <code>/wp-json/wp/v2/users</code>).
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">HTTP Security Headers</th>
                    <td>
                        <label>
                            <input type="checkbox" name="enable_security_headers" value="1" <?php checked( isset( $settings['enable_security_headers'] ) ? $settings['enable_security_headers'] : 0, 1 ); ?>> 
                            <strong>Enable standard HTTP Security Headers.</strong>
                        </label>
                        <p class="description" style="margin-top: 4px; color:#64748b;">
                            Enforces browser protection policies (<code>X-Frame-Options</code>, <code>X-Content-Type-Options</code>, <code>X-XSS-Protection</code>, <code>Referrer-Policy</code>) to safeguard visitors from clickjacking and mime-type sniffing attacks.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Block Author Page Scanning</th>
                    <td>
                        <label>
                            <input type="checkbox" name="disable_author_scanning" value="1" <?php checked( isset( $settings['disable_author_scanning'] ) ? $settings['disable_author_scanning'] : 0, 1 ); ?>> 
                            <strong>Disable public author archive pages and query scans.</strong>
                        </label>
                        <p class="description" style="margin-top: 4px; color:#64748b;">
                            Blocks access to frontend author archive pages and redirects query requests like <code>/?author=1</code> to the homepage. This keeps your admin usernames hidden from malicious scanner bots.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">WooCommerce Anti-Spam Guard</th>
                    <td>
                        <label>
                            <input type="checkbox" name="enable_registration_antispam" value="1" <?php checked( isset( $settings['enable_registration_antispam'] ) ? $settings['enable_registration_antispam'] : 0, 1 ); ?>> 
                            <strong>Block bot registrations using a Honeypot & spam email domain blocker.</strong>
                        </label>
                        <p class="description" style="margin-top: 4px; color:#64748b;">
                            Injects a hidden field to trap spam bots, and blocks account registration from highly abused disposable or spam domains (like <code>.xyz</code>, <code>.top</code>, <code>.click</code>).
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Lockout Action</th>
                    <td>
                        The IP address will be automatically blacklisted and blocked at the application/Nginx layer.
                    </td>
                </tr>
            </table>
            <?php submit_button( 'Save Settings', 'primary', 'aag_save_settings' ); ?>
        </form>

        <hr style="margin: 30px 0;">

        <h2>🛠️ Security Tools & Maintenance</h2>
        <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;max-width: 800px;box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
            <h3 style="margin-top:0;">Database Revision Spam Purger</h3>
            <p style="color:#64748b;">
                WordPress stores post drafts and historical revisions in the database. Hackers often inject spam links into these hidden revision drafts (marked as <code>post_type = 'revision'</code> and <code>post_status = 'inherit'</code>) to gain search engine SEO ranking while keeping them invisible on the normal dashboard.
            </p>
            <p>
                <strong>System Action:</strong> The scanner automatically runs every 24 hours to scrub the database. You can also run the scan manually using the button below.
            </p>
            <form method="post" action="">
                <?php wp_nonce_field( 'aag_purge_revisions_action', 'aag_purge_revisions_nonce' ); ?>
                <button type="submit" name="aag_purge_revisions_btn" class="button button-secondary">🧹 Scan & Purge Spam Revisions Now</button>
            </form>
        </div>

        <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;max-width: 800px;box-shadow: 0 1px 3px rgba(0,0,0,0.05);margin-top: 20px;">
            <h3 style="margin-top:0;">Secure Database Password Changer</h3>
            <p style="color:#64748b;">
                Changes the MySQL password for the current database connection user and automatically updates your <code>wp-config.php</code> file.
            </p>
            <form method="post" action="">
                <?php wp_nonce_field( 'aag_change_db_password_action', 'aag_change_db_password_nonce' ); ?>
                <table class="form-table" style="margin-top: 0;">
                    <tr>
                        <th scope="row" style="padding: 10px 0; width: 200px;"><label for="aag_new_db_password">New DB Password</label></th>
                        <td style="padding: 10px 0;">
                            <div style="display:flex; gap:10px; align-items:center; max-width: 450px;">
                                <input type="password" name="aag_new_db_password" id="aag_new_db_password" class="regular-text" required minlength="8" placeholder="Enter secure password" style="flex:1;">
                                <button type="button" class="button" onclick="aag_toggle_password_visibility()">👁️</button>
                            </div>
                            <div style="margin-top: 8px;">
                                <button type="button" class="button button-secondary" onclick="aag_suggest_strong_password()">🪄 Suggest Strong Password</button>
                            </div>
                        </td>
                    </tr>
                </table>
                <script>
                    function aag_toggle_password_visibility() {
                        const input = document.getElementById('aag_new_db_password');
                        if (input.type === 'password') {
                            input.type = 'text';
                        } else {
                            input.type = 'password';
                        }
                    }
                    function aag_suggest_strong_password() {
                        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
                        let password = '';
                        const length = 20;
                        const array = new Uint32Array(length);
                        window.crypto.getRandomValues(array);
                        for (let i = 0; i < length; i++) {
                            password += chars[array[i] % chars.length];
                        }
                        const input = document.getElementById('aag_new_db_password');
                        input.value = password;
                        input.type = 'text';
                    }
                </script>
                <button type="submit" name="aag_change_db_password_btn" class="button button-secondary" onclick="return confirm('WARNING: This will alter the database user password on your MySQL server and update wp-config.php. Are you sure you want to continue?');">🔑 Update Database Password</button>
            </form>
        </div>

        <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;max-width: 800px;box-shadow: 0 1px 3px rgba(0,0,0,0.05);margin-top: 20px;">
            <h3 style="margin-top:0;">wp-config.php Permissions Manager</h3>
            <p style="color:#64748b;">
                Toggles the write permissions of your site's main configuration file (<code>wp-config.php</code>) to prevent unauthorized server write modifications.
            </p>
            <?php
            $wp_config_path = '';
            if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
                $wp_config_path = ABSPATH . 'wp-config.php';
            } elseif ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
                $wp_config_path = dirname( ABSPATH ) . '/wp-config.php';
            }
            
            if ( $wp_config_path ) :
                $is_config_writable = is_writable( $wp_config_path );
                $perms               = substr( sprintf( '%o', @fileperms( $wp_config_path ) ), -4 );
                ?>
                <p>
                    <strong>Current Status:</strong> 
                    <?php if ( $is_config_writable ) : ?>
                        <span style="color:#dc3545; font-weight:bold;">🔓 Unlocked (Writable)</span> <code>[Permissions: <?php echo esc_html( $perms ); ?>]</code>
                    <?php else : ?>
                        <span style="color:#28a745; font-weight:bold;">🔒 Locked (Read-Only)</span> <code>[Permissions: <?php echo esc_html( $perms ); ?>]</code>
                    <?php endif; ?>
                </p>
                <form method="post" action="">
                    <?php wp_nonce_field( 'aag_wp_config_perms_action', 'aag_wp_config_perms_nonce' ); ?>
                    <?php if ( $is_config_writable ) : ?>
                        <button type="submit" name="aag_toggle_wp_config_writable_btn" class="button button-primary" style="background:#28a745; border-color:#28a745;">🔒 Lock wp-config.php (Make Read-Only)</button>
                    <?php else : ?>
                        <button type="submit" name="aag_toggle_wp_config_writable_btn" class="button button-primary" style="background:#dc3545; border-color:#dc3545;">🔓 Unlock wp-config.php (Make Writable)</button>
                    <?php endif; ?>
                </form>
            <?php else : ?>
                <p style="color:#dc3545;">⚠️ wp-config.php file could not be located.</p>
            <?php endif; ?>
        </div>
    </div>
    <?php
}

// ────────────────────────────────────────────────────────────────────
// UPDATE CONTROLS
// ────────────────────────────────────────────────────────────────────
add_filter( 'site_transient_update_plugins', 'aag_filter_plugin_updates' );
add_filter( 'auto_update_plugin', 'aag_filter_auto_plugin_updates', 10, 2 );
function aag_filter_plugin_updates( $value ) {
    $settings = get_option( AAG_OPTION_SETTINGS, array( 'enable_plugin_updates' => 1 ) );
    if ( empty( $settings['enable_plugin_updates'] ) ) {
        if ( isset( $value->response ) ) { $value->response = array(); }
    }
    return $value;
}
function aag_filter_auto_plugin_updates( $update, $item ) {
    $settings = get_option( AAG_OPTION_SETTINGS, array( 'enable_plugin_updates' => 1 ) );
    return empty( $settings['enable_plugin_updates'] ) ? false : $update;
}

add_filter( 'site_transient_update_themes', 'aag_filter_theme_updates' );
add_filter( 'auto_update_theme', 'aag_filter_auto_theme_updates', 10, 2 );
function aag_filter_theme_updates( $value ) {
    $settings = get_option( AAG_OPTION_SETTINGS, array( 'enable_theme_updates' => 1 ) );
    if ( empty( $settings['enable_theme_updates'] ) ) {
        if ( isset( $value->response ) ) { $value->response = array(); }
    }
    return $value;
}
function aag_filter_auto_theme_updates( $update, $item ) {
    $settings = get_option( AAG_OPTION_SETTINGS, array( 'enable_theme_updates' => 1 ) );
    return empty( $settings['enable_theme_updates'] ) ? false : $update;
}

// ────────────────────────────────────────────────────────────────────
// 404 REDIRECT ENGINE
// ────────────────────────────────────────────────────────────────────
add_action( 'template_redirect', 'aag_handle_404_redirect', 1 );
function aag_handle_404_redirect() {
    if ( is_404() ) {
        $settings = get_option( AAG_OPTION_SETTINGS, array( 'enable_404_redirect' => 1 ) );
        $behavior = isset( $settings['enable_404_redirect'] ) ? intval( $settings['enable_404_redirect'] ) : 1;

        if ( $behavior > 0 ) {
            global $wpdb;
            $table_name = $wpdb->prefix . 'aag_404_logs';
            $url        = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) );
            $dest       = ( $behavior === 1 ) ? home_url() : '410 Gone Page';
            $ip         = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
            $ua         = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) );
            $now        = current_time( 'mysql' );

            // Check if table exists (in case it wasn't created yet)
            if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) === $table_name ) {
                $row = $wpdb->get_row( $wpdb->prepare( "SELECT id FROM $table_name WHERE requested_url = %s", $url ) );
                if ( $row ) {
                    $wpdb->query( $wpdb->prepare(
                        "UPDATE $table_name SET hits = hits + 1, last_accessed = %s, last_ip = %s, last_user_agent = %s WHERE id = %d",
                        $now, $ip, $ua, $row->id
                    ) );
                } else {
                    $wpdb->insert( $table_name, array(
                        'requested_url'   => $url,
                        'redirect_dest'   => $dest,
                        'hits'            => 1,
                        'last_ip'         => $ip,
                        'last_user_agent' => $ua,
                        'first_accessed'  => $now,
                        'last_accessed'   => $now,
                        'is_active'       => 1,
                    ), array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%d' ) );
                }
            }

            if ( $behavior === 1 ) {
                wp_redirect( home_url(), 301 );
                exit;
            } else {
                status_header( 410 );
                nocache_headers();
                header( $_SERVER['SERVER_PROTOCOL'] . ' 410 Gone' );
                echo '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>410 Gone - Page Permanently Removed</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; text-align: center; padding: 150px 20px; background: #f7fafc; color: #4a5568; }
        h1 { font-size: 50px; margin: 0 0 10px; color: #2d3748; }
        p { font-size: 18px; margin: 0 0 20px; }
        a { color: #3182ce; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>410</h1>
    <p>This page has been permanently removed and is no longer available.</p>
    <p><a href="' . esc_url( home_url( '/' ) ) . '">&#8592; Go to Homepage</a></p>
</body>
</html>';
                exit;
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// LOGIN ALERTS
// ────────────────────────────────────────────────────────────────────
add_action( 'wp_login', 'aag_send_login_alert', 10, 2 );
function aag_send_login_alert( $user_login, $user ) {
    $admin_email = 'shadabcse2020@gmail.com';
    
    // Do not spam alerts if the master admin logs in (optional, but requested for "someone")
    // If you want alerts for yourself as well, comment this out.
    // if ( $user->user_email === $admin_email ) return;

    $ip_address = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? 'Unknown' ) );
    $time       = current_time( 'mysql' );
    $user_agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown' ) );

    $subject = sprintf( '[%s] 🔐 User Login Alert: %s', get_bloginfo( 'name' ), $user_login );
    
    $message  = "A user has successfully logged into your WordPress dashboard.\n\n";
    $message .= "--- Login Details ---\n";
    $message .= "Username: {$user_login}\n";
    $message .= "Email: {$user->user_email}\n";
    $message .= "Roles: " . implode( ', ', $user->roles ) . "\n";
    $message .= "Time: {$time}\n";
    $message .= "IP Address: {$ip_address}\n";
    $message .= "User Agent: {$user_agent}\n\n";
    $message .= "If this login is suspicious, you should immediately revoke their access or ban their IP address.";

    wp_mail( $admin_email, $subject, $message );
}

// ────────────────────────────────────────────────────────────────────
// DATABASE REVISION SPAM PURGER
// ────────────────────────────────────────────────────────────────────
function aag_purge_spam_revisions() {
    global $wpdb;
    $count = 0;
    
    // Find all revisions
    $revisions = $wpdb->get_results(
        "SELECT ID, post_content, post_title FROM {$wpdb->posts} WHERE post_type = 'revision' AND post_status = 'inherit'"
    );
    
    if ( empty( $revisions ) ) {
        return 0;
    }
    
    $spam_keywords = array(
        'casino', 'poker', 'blackjack', 'slots', 'payday', 'viagra', 'cialis', 
        'levitra', 'porn', 'adult', 'replica', 'valium', 'xanax', 'vardenafil',
        'sildenafil', 'tadalafil', 'outlet', 'cheap', 'discount', 'free shipping'
    );
    
    $home_url = home_url();
    $home_host = parse_url( $home_url, PHP_URL_HOST );
    
    foreach ( $revisions as $rev ) {
        $is_spam = false;
        $content = strtolower( $rev->post_content );
        $title   = strtolower( $rev->post_title );
        
        // 1. Check for spam keywords
        foreach ( $spam_keywords as $keyword ) {
            if ( strpos( $content, $keyword ) !== false || strpos( $title, $keyword ) !== false ) {
                $is_spam = true;
                break;
            }
        }
        
        // 2. Check for external links (highly common in cloaking/spam inserts)
        if ( ! $is_spam && strpos( $content, '<a ' ) !== false ) {
            preg_match_all( '/href=["\'](https?:\/\/[^"\']+)["\']/i', $rev->post_content, $matches );
            if ( ! empty( $matches[1] ) ) {
                $ext_link_count = 0;
                foreach ( $matches[1] as $url ) {
                    $host = parse_url( $url, PHP_URL_HOST );
                    if ( $host && $host !== $home_host ) {
                        $ext_link_count++;
                    }
                }
                if ( $ext_link_count >= 2 ) {
                    $is_spam = true;
                }
            }
        }
        
        if ( $is_spam ) {
            // Delete post permanently along with revision metadata
            wp_delete_post( $rev->ID, true );
            $count++;
        }
    }
    
    if ( $count > 0 ) {
        aag_log(
            'spam_revisions_purged',
            'warning',
            sprintf( 'Successfully detected and auto-purged %d spam revisions from the database.', $count )
        );
        
        // Send email alert to master admin
        wp_mail(
            'shadabcse2020@gmail.com',
            sprintf( '[Security Alert] Spam Revisions Purged — %s', get_bloginfo( 'name' ) ),
            sprintf(
                "Admin Approval Guard has scanned your database and detected spam draft/revision history injections.\n\nPurged Revisions count: %d\nTime (UTC): %s\n\nNo action is required from your side. The database has been cleaned.",
                $count,
                gmdate( 'Y-m-d H:i:s' )
            )
        );
    }
    
    return $count;
}

// ────────────────────────────────────────────────────────────────────
// UPLOADS DIRECTORY HARDENING & AUTO-CLEANUP
// ────────────────────────────────────────────────────────────────────
function aag_harden_uploads_directory() {
    $uploads_dir = WP_CONTENT_DIR . '/uploads';
    if ( ! is_dir( $uploads_dir ) ) {
        return array();
    }

    // 1. Maintain the security .htaccess file in the uploads directory
    $htaccess_path = $uploads_dir . '/.htaccess';
    $htaccess_content = "# Disable PHP execution inside WordPress Uploads Directory\n" .
                        "<Files *.php>\n" .
                        "deny from all\n" .
                        "</Files>\n" .
                        "<Files *.php3>\n" .
                        "deny from all\n" .
                        "</Files>\n" .
                        "<Files *.php4>\n" .
                        "deny from all\n" .
                        "</Files>\n" .
                        "<Files *.php5>\n" .
                        "deny from all\n" .
                        "</Files>\n" .
                        "<Files *.php7>\n" .
                        "deny from all\n" .
                        "</Files>\n" .
                        "<Files *.phtml>\n" .
                        "deny from all\n" .
                        "</Files>\n" .
                        "<Files *.phar>\n" .
                        "deny from all\n" .
                        "</Files>";

    if ( ! file_exists( $htaccess_path ) || file_get_contents( $htaccess_path ) !== $htaccess_content ) {
        @file_put_contents( $htaccess_path, $htaccess_content );
    }

    // 1b. Maintain the Nginx uploads hardening block file in ABSPATH
    $nginx_conf_path = ABSPATH . 'nginx-uploads-hardening.conf';
    $nginx_conf_content = "# Nginx Uploads Hardening: Block PHP execution in wp-content/uploads/\n" .
                          "location ~* ^/wp-content/uploads/.*\\.php\$ {\n" .
                          "    deny all;\n" .
                          "}\n";
    if ( ! file_exists( $nginx_conf_path ) || file_get_contents( $nginx_conf_path ) !== $nginx_conf_content ) {
        @file_put_contents( $nginx_conf_path, $nginx_conf_content );
        @chmod( $nginx_conf_path, 0644 );
    }

    // 2. Scan and auto-delete any executable files
    $disallowed_exts = array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'shtml', 'cgi', 'pl', 'py', 'rb', 'sh', 'bash' );
    $deleted_files = array();

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ( $iterator as $file ) {
            if ( $file->isFile() ) {
                $ext = strtolower( $file->getExtension() );
                if ( in_array( $ext, $disallowed_exts, true ) ) {
                    $filepath = $file->getRealPath();
                    if ( basename( $filepath ) === '.htaccess' ) {
                        continue;
                    }
                    if ( @unlink( $filepath ) ) {
                        $deleted_files[] = $filepath;
                        aag_log(
                            'malicious_file_deleted',
                            'critical',
                            sprintf( 'Auto-deleted executable file found in uploads: %s', basename( $filepath ) )
                        );
                    }
                }
            }
        }
    } catch ( Exception $e ) {
        // Fail silently
    }

    if ( ! empty( $deleted_files ) ) {
        // Send email alert to master admin
        wp_mail(
            'shadabcse2020@gmail.com',
            sprintf( '[Security Alert] Executable Files Deleted from Uploads — %s', get_bloginfo( 'name' ) ),
            sprintf(
                "Admin Approval Guard has detected and deleted executable files from your uploads folder.\n\nDeleted Files:\n%s\n\nTime (UTC): %s\n\nYour site has blocked and neutralized this upload.",
                implode( "\n", $deleted_files ),
                gmdate( 'Y-m-d H:i:s' )
            )
        );
    }

    return $deleted_files;
}

// ────────────────────────────────────────────────────────────────────
// BASELINE MANAGEMENT (PREVENTS FALSE POSITIVES ON PLUGIN UPDATES)
// ────────────────────────────────────────────────────────────────────
function aag_rebuild_baseline() {
    if ( ! is_dir( WP_PLUGIN_DIR ) ) {
        return;
    }
    
    $own_dir = realpath( plugin_dir_path( __FILE__ ) );
    
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( WP_PLUGIN_DIR, RecursiveDirectoryIterator::SKIP_DOTS )
        );
    } catch ( Exception $e ) {
        return;
    }
    
    $current_hashes = array();
    foreach ( $iterator as $file ) {
        if ( ! $file->isFile() ) continue;
        if ( $file->getExtension() !== 'php' ) continue;
        
        $fp = $file->getRealPath();
        // Skip our own plugin files
        if ( $own_dir && strpos( $fp, $own_dir ) === 0 ) continue;
        
        $hash                  = @md5_file( $fp );
        $current_hashes[ $fp ] = $hash;
    }
    
    update_option( AAG_SCAN_OPTION_BASELINE, $current_hashes, 'no' );
    
    aag_log(
        'baseline_rebuilt',
        'info',
        'Security baseline rebuilt automatically due to plugin update or activation.'
    );
}

// Hook into WordPress upgrade system for plugins
add_action( 'upgrader_process_complete', 'aag_handle_upgrader_process_complete', 10, 2 );
function aag_handle_upgrader_process_complete( $upgrader_object, $options ) {
    if ( isset( $options['type'] ) && $options['type'] === 'plugin' ) {
        aag_rebuild_baseline();
    }
}

// Hook into plugin status transitions
add_action( 'activated_plugin', 'aag_rebuild_baseline' );
add_action( 'deactivated_plugin', 'aag_rebuild_baseline' );
add_action( 'deleted_plugin', 'aag_rebuild_baseline' );

// ────────────────────────────────────────────────────────────────────
// WP-CONFIG HARDENED LOCKOUT WRITER
// ────────────────────────────────────────────────────────────────────
function aag_write_wp_config_file_mods( $enable ) {
    $wp_config_path = '';
    if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
        $wp_config_path = ABSPATH . 'wp-config.php';
    } elseif ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
        $wp_config_path = dirname( ABSPATH ) . '/wp-config.php';
    }

    if ( empty( $wp_config_path ) || ! is_writable( $wp_config_path ) ) {
        return false;
    }

    $content = file_get_contents( $wp_config_path );
    if ( $content === false ) {
        return false;
    }

    // Remove any existing definition of DISALLOW_FILE_MODS or DISALLOW_FILE_EDIT to avoid duplicates/conflicts
    $content = preg_replace( '/define\(\s*[\'"](DISALLOW_FILE_MODS|DISALLOW_FILE_EDIT)[\'"]\s*,\s*[^;]+\s*\);?\r?\n?/i', '', $content );

    if ( $enable ) {
        // Insert the definition right after the opening <?php tag
        $insert = "\ndefine( 'DISALLOW_FILE_MODS', true ); // Added by Admin Approval Guard\n";
        $pos = strpos( $content, '<?php' );
        if ( $pos !== false ) {
            $content = substr_replace( $content, '<?php' . $insert, $pos, 5 );
        } else {
            $content = $insert . $content;
        }
    }

    return file_put_contents( $wp_config_path, $content ) !== false;
}

// ────────────────────────────────────────────────────────────────────
// DISABLE XML-RPC
// ────────────────────────────────────────────────────────────────────
add_filter( 'xmlrpc_enabled', 'aag_disable_xmlrpc_handler' );
function aag_disable_xmlrpc_handler( $enabled ) {
    $settings = get_option( AAG_OPTION_SETTINGS, array() );
    if ( ! empty( $settings['disable_xmlrpc'] ) ) {
        return false;
    }
    return $enabled;
}

// ────────────────────────────────────────────────────────────────────
// RESTRICT REST API FOR GUESTS
// ────────────────────────────────────────────────────────────────────
add_filter( 'rest_authentication_errors', 'aag_restrict_rest_api_handler' );
function aag_restrict_rest_api_handler( $result ) {
    if ( true === $result || is_wp_error( $result ) ) {
        return $result;
    }

    $settings = get_option( AAG_OPTION_SETTINGS, array() );
    if ( ! empty( $settings['disable_rest_api_guests'] ) ) {
        if ( ! is_user_logged_in() ) {
            return new WP_Error(
                'rest_forbidden_guest',
                __( 'REST API access is restricted to logged-in users.', 'admin-approval-guard' ),
                array( 'status' => rest_authorization_required_code() )
            );
        }
    }
    return $result;
}

// ────────────────────────────────────────────────────────────────────
// HTTP SECURITY HEADERS
// ────────────────────────────────────────────────────────────────────
add_action( 'send_headers', 'aag_send_security_headers' );
function aag_send_security_headers() {
    $settings = get_option( AAG_OPTION_SETTINGS, array() );
    if ( ! empty( $settings['enable_security_headers'] ) ) {
        header( 'X-Frame-Options: SAMEORIGIN' );
        header( 'X-Content-Type-Options: nosniff' );
        header( 'X-XSS-Protection: 1; mode=block' );
        header( 'Referrer-Policy: strict-origin-when-cross-origin' );
    }
}

// ────────────────────────────────────────────────────────────────────
// ACTIVE DATABASE POST/PAGE MALWARE CONTENT SCANNER
// ────────────────────────────────────────────────────────────────────
function aag_scan_database_posts() {
    global $wpdb;
    $threats = array();
    
    // Query published posts, pages, and custom post types
    $posts = $wpdb->get_results(
        "SELECT ID, post_title, post_content, post_type FROM {$wpdb->posts} WHERE post_status = 'publish' AND post_type IN ('post', 'page')"
    );
    
    if ( empty( $posts ) ) {
        return $threats;
    }
    
    $suspicious_patterns = array(
        '/<script[^>]*src=["\']https?:\/\/(?![^"\']*(google|yahoo|bing|facebook|instagram|twitter|pinterest|wp\.com|wordpress\.org|googleapis\.com|jquery\.com|cloudflare))[^\'"]+["\'][^>]*>/i' => 'External script from unverified domain',
        '/eval\s*\(\s*base64_decode/i' => 'Obfuscated JavaScript payload (eval/base64)',
        '/<iframe[^>]*src=["\']https?:\/\/(?![^"\']*(youtube|vimeo|google|maps\.google|facebook|wp\.com|wordpress\.org|cloudflare))[^\'"]+["\'][^>]*>/i' => 'Suspicious external iframe injection',
        '/display\s*:\s*none\s*;[^>]*<a/i' => 'Hidden SEO backlink (display:none)',
        '/position\s*:\s*absolute\s*;[^;]*left\s*:\s*-\d+px/i' => 'Hidden SEO link positioned off-screen'
    );
    
    foreach ( $posts as $p ) {
        $content = $p->post_content;
        foreach ( $suspicious_patterns as $pattern => $description ) {
            if ( preg_match( $pattern, $content ) ) {
                $threats[] = array(
                    'type'        => 'database_malware',
                    'file'        => sprintf( 'Database: Post ID %d (%s)', $p->ID, $p->post_type ),
                    'pattern'     => $description,
                    'description' => sprintf( 'Suspicious code found in published %s: "%s". Description: %s', $p->post_type, esc_html($p->post_title), $description ),
                    'match_lines' => array(),
                    'status'      => 'detected',
                    'found_at'    => time()
                );
            }
        }
    }
    
    return $threats;
}

// ────────────────────────────────────────────────────────────────────
// BLOCK AUTHOR SCANNING & USERNAME HARVESTING
// ────────────────────────────────────────────────────────────────────
add_action( 'template_redirect', 'aag_disable_author_scanning_handler' );
function aag_disable_author_scanning_handler() {
    $settings = get_option( AAG_OPTION_SETTINGS, array() );
    if ( ! empty( $settings['disable_author_scanning'] ) ) {
        if ( is_author() || isset( $_GET['author'] ) ) {
            wp_redirect( home_url(), 301 );
            exit;
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// WOOCOMMERCE & WP ANTI-SPAM REGISTRATION GUARD (HONEYPOT & DOMAIN BLOCK)
// ────────────────────────────────────────────────────────────────────

// Render honeypot field
add_action( 'register_form', 'aag_add_registration_honeypot' );
add_action( 'woocommerce_register_form', 'aag_add_registration_honeypot' );
function aag_add_registration_honeypot() {
    $settings = get_option( AAG_OPTION_SETTINGS, array() );
    if ( ! empty( $settings['enable_registration_antispam'] ) ) {
        echo '
        <p class="form-row" style="display:none !important; visibility:hidden !important; height:0 !important; overflow:hidden !important;">
            <label for="aag_honeypot_email">Confirm Primary Email (Leave Blank)</label>
            <input type="text" name="aag_honeypot_email" id="aag_honeypot_email" value="" autocomplete="off" tabindex="-1" />
        </p>';
    }
}

// Validate honeypot and email domain
add_filter( 'registration_errors', 'aag_validate_wp_registration', 10, 3 );
function aag_validate_wp_registration( $errors, $sanitized_user_login, $user_email ) {
    $error_msg = aag_check_registration_spam( $user_email );
    if ( $error_msg ) {
        $errors->add( 'spam_registration_blocked', $error_msg );
    }
    return $errors;
}

add_action( 'woocommerce_register_post', 'aag_validate_woo_registration', 10, 3 );
function aag_validate_woo_registration( $username, $email, $validation_errors ) {
    $error_msg = aag_check_registration_spam( $email );
    if ( $error_msg ) {
        $validation_errors->add( 'spam_registration_blocked', $error_msg );
    }
}

// Centralized validation logic
function aag_check_registration_spam( $email ) {
    $settings = get_option( AAG_OPTION_SETTINGS, array() );
    if ( empty( $settings['enable_registration_antispam'] ) ) {
        return false;
    }

    // 1. Check Honeypot Field
    if ( ! empty( $_POST['aag_honeypot_email'] ) ) {
        $ip = aag_get_client_ip();
        aag_log(
            'registration_spam_blocked',
            'warning',
            sprintf( 'Spam registration blocked via Honeypot. Email tried: %s. IP: %s', sanitize_email( $email ), $ip )
        );
        return __( '<strong>Security Error</strong>: Bot registration detected.', 'admin-approval-guard' );
    }

    // 2. Check Spam Email Domain/TLD
    $email  = strtolower( trim( $email ) );
    $domain = substr( strrchr( $email, "@" ), 1 );
    if ( ! $domain ) {
        return false;
    }

    // Known high-abuse spam TLDs
    $spam_tlds = array( 'xyz', 'top', 'click', 'link', 'club', 'work', 'date', 'space', 'live', 'online', 'download', 'bid', 'loan', 'win', 'gq', 'cf', 'ml', 'tk', 'ga' );
    $ext       = pathinfo( $domain, PATHINFO_EXTENSION );

    // Known temporary/burner email providers
    $burner_providers = array( 'tempmail', '10minutemail', 'yopmail', 'guerrillamail', 'mailinator', 'dispostable', 'getairmail', 'sharklasers', 'burnermail', 'trashmail', 'bestvpsfor' );

    $is_spam = false;
    if ( in_array( $ext, $spam_tlds, true ) ) {
        $is_spam = true;
    } else {
        foreach ( $burner_providers as $provider ) {
            if ( strpos( $domain, $provider ) !== false ) {
                $is_spam = true;
                break;
            }
        }
    }

    if ( $is_spam ) {
        $ip = aag_get_client_ip();
        aag_log(
            'registration_spam_blocked',
            'warning',
            sprintf( 'Spam registration blocked due to suspicious email domain (%s). IP: %s', esc_html( $domain ), $ip )
        );
        return __( '<strong>Security Error</strong>: Registration is restricted from this email domain.', 'admin-approval-guard' );
    }

    return false;
}

// ────────────────────────────────────────────────────────────────────
// DATABASE PASSWORD CHANGER
// ────────────────────────────────────────────────────────────────────
function aag_change_database_password( $new_password ) {
    $wp_config_path = '';
    if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
        $wp_config_path = ABSPATH . 'wp-config.php';
    } elseif ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
        $wp_config_path = dirname( ABSPATH ) . '/wp-config.php';
    }

    if ( empty( $wp_config_path ) ) {
        return new WP_Error( 'config_not_found', 'Your wp-config.php file could not be located.' );
    }

    $original_perms = @fileperms( $wp_config_path );
    $made_writable = false;

    // Check if writable, and if not, try to make it writable
    if ( ! is_writable( $wp_config_path ) ) {
        if ( @chmod( $wp_config_path, 0644 ) ) {
            $made_writable = true;
        } else {
            // Try 0666 as a last resort
            if ( @chmod( $wp_config_path, 0666 ) ) {
                $made_writable = true;
            }
        }
    }

    // Double check writability before running queries
    if ( ! is_writable( $wp_config_path ) ) {
        return new WP_Error( 'config_not_writable', 'Your wp-config.php file is not writable, and the plugin was unable to change its permissions automatically.' );
    }

    global $wpdb;

    // MySQL permits users to change their own password using ALTER USER USER()
    $query = $wpdb->prepare( "ALTER USER USER() IDENTIFIED BY %s", $new_password );
    $db_success = $wpdb->query( $query );

    if ( $db_success === false ) {
        // Fallback for older MySQL / MariaDB versions
        $query_legacy = $wpdb->prepare( "SET PASSWORD = PASSWORD(%s)", $new_password );
        $db_success = $wpdb->query( $query_legacy );
    }

    if ( $db_success === false ) {
        // Restore permissions if we changed them before returning error
        if ( $made_writable && $original_perms !== false ) {
            @chmod( $wp_config_path, $original_perms & 0777 );
        }
        return new WP_Error( 'db_error', 'Failed to change password in database. Verify your database user privileges.' );
    }

    // Now write to wp-config.php
    $content = file_get_contents( $wp_config_path );
    if ( $content === false ) {
        if ( $made_writable && $original_perms !== false ) {
            @chmod( $wp_config_path, $original_perms & 0777 );
        }
        return new WP_Error( 'config_read_error', 'Failed to read wp-config.php.' );
    }

    $escaped_pw = addcslashes( $new_password, "'\\" );
    $new_content = preg_replace_callback(
        '/define\(\s*[\'"]DB_PASSWORD[\'"]\s*,\s*[\'"].*?[\'"]\s*\);/i',
        function() use ( $escaped_pw ) {
            return "define( 'DB_PASSWORD', '" . $escaped_pw . "' );";
        },
        $content
    );

    $write_success = ( file_put_contents( $wp_config_path, $new_content ) !== false );

    // Restore original file permissions
    if ( $made_writable && $original_perms !== false ) {
        @chmod( $wp_config_path, $original_perms & 0777 );
    }

    if ( ! $write_success ) {
        return new WP_Error( 'config_write_error', 'Failed to write new password to wp-config.php.' );
    }

    return true;
}









