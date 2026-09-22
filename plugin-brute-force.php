<?php
defined( 'ABSPATH' ) || exit;

// ────────────────────────────────────────────────────────────────────
// BRUTE FORCE PROTECTION & FAILED LOGIN LOGGER
// ────────────────────────────────────────────────────────────────────

if ( ! class_exists( 'WP_List_Table' ) ) {
    if ( file_exists( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' ) ) {
        require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
    }
}

// ── Hook into WordPress Admin Menu for Submenu ───────────────────────
add_action( 'admin_menu', 'aag_register_login_logs_submenu', 11 );
function aag_register_login_logs_submenu() {
    add_submenu_page(
        'aag-admin-approvals',
        esc_html__( 'Failed Login Logs', 'admin-approval-guard' ),
        esc_html__( 'Failed Logins', 'admin-approval-guard' ),
        'manage_options',
        'aag-failed-logins',
        'aag_render_failed_logins_page'
    );
}

// ── Database Installation for Failed Logins Table ───────────────────
function aag_install_failed_logins_db() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'aag_failed_logins';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        username varchar(255) NOT NULL,
        ip_address varchar(100) NOT NULL,
        user_agent varchar(512) NOT NULL DEFAULT '',
        failed_at datetime NOT NULL,
        PRIMARY KEY  (id),
        KEY ip_address (ip_address),
        KEY failed_at (failed_at)
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

// ── Brute Force Lockout & Logging Logic ──────────────────────────────
add_action( 'wp_login_failed', 'aag_log_failed_login' );
function aag_log_failed_login( $username ) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'aag_failed_logins';

    $ip = function_exists( 'aag_get_client_ip' ) ? aag_get_client_ip() : sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
    $ua = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) );
    $now = current_time( 'mysql' );

    // Check if table exists
    if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) === $table_name ) {
        $wpdb->insert( $table_name, array(
            'username'   => sanitize_user( $username ),
            'ip_address' => $ip,
            'user_agent' => $ua,
            'failed_at'  => $now,
        ), array( '%s', '%s', '%s', '%s' ) );
    }

    // ── Brute Force Checks ──
    $settings = get_option( AAG_OPTION_SETTINGS, array() );
    $max_attempts = isset( $settings['brute_force_attempts'] ) ? absint( $settings['brute_force_attempts'] ) : 5;
    $lockout_duration = isset( $settings['brute_force_duration'] ) ? absint( $settings['brute_force_duration'] ) : 60; // in minutes
    $time_window = 15; // check last 15 minutes for attempts

    if ( $max_attempts > 0 && ! empty( $ip ) ) {
        $window_start = gmdate( 'Y-m-d H:i:s', time() - ( $time_window * MINUTE_IN_SECONDS ) );
        $attempts = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(id) FROM $table_name WHERE ip_address = %s AND failed_at >= %s",
            $ip, $window_start
        ) );

        if ( $attempts >= $max_attempts ) {
            // Auto-block the IP!
            $reason = sprintf( 'Brute force protection: %d failed login attempts within %d minutes', $attempts, $time_window );
            aag_block_ip( $ip, $reason );
        }
    }
}

// ── Hook to block access during login process ─────────────────────────
add_filter( 'authenticate', 'aag_check_ip_before_login', 1, 3 );
function aag_check_ip_before_login( $user, $username, $password ) {
    $ip = function_exists( 'aag_get_client_ip' ) ? aag_get_client_ip() : sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) );
    $blocked = get_option( AAG_BLOCKED_IPS_OPTION, array() );

    if ( is_array( $blocked ) && ! empty( $ip ) ) {
        foreach ( $blocked as $entry ) {
            if ( isset( $entry['ip'] ) && $entry['ip'] === $ip ) {
                return new WP_Error( 'blocked_ip', __( '<strong>ERROR</strong>: Your IP address is blocked due to security reasons.', 'admin-approval-guard' ) );
            }
        }
    }
    return $user;
}

// ── WP_List_Table for Failed Logins logs ─────────────────────────────
class AAG_Failed_Logins_Table extends WP_List_Table {

    public function __construct() {
        parent::__construct( array(
            'singular' => 'failed_login',
            'plural'   => 'failed_logins',
            'ajax'     => false,
        ) );
    }

    public function get_columns() {
        return array(
            'username'   => 'Attempted Username',
            'ip_address' => 'IP Address',
            'user_agent' => 'Browser / User Agent',
            'failed_at'  => 'Date & Time',
            'actions'    => 'Quick Action',
        );
    }

    public function get_sortable_columns() {
        return array(
            'username'  => array( 'username', false ),
            'ip_address'=> array( 'ip_address', false ),
            'failed_at' => array( 'failed_at', true ),
        );
    }

    public function column_default( $item, $column_name ) {
        switch ( $column_name ) {
            case 'username':
                return '<strong style="color:#d32f2f;">' . esc_html( $item['username'] ) . '</strong>';
            case 'ip_address':
                return '<code>' . esc_html( $item['ip_address'] ) . '</code>'
                    . '<br><a href="https://ipinfo.io/' . esc_attr( $item['ip_address'] ) . '" target="_blank" style="font-size:11px;">Lookup IP &#8594;</a>';
            case 'user_agent':
                $ua = esc_html( $item['user_agent'] );
                $short = strlen( $ua ) > 60 ? substr( $ua, 0, 60 ) . '&hellip;' : $ua;
                return '<span title="' . $ua . '" style="cursor:help;font-size:11px;">' . $short . '</span>';
            case 'failed_at':
                return esc_html( $item['failed_at'] );
            case 'actions':
                // Check if already blocked
                $ip = $item['ip_address'];
                $blocked_ips = get_option( AAG_BLOCKED_IPS_OPTION, array() );
                $is_blocked = false;
                if ( is_array( $blocked_ips ) ) {
                    foreach ( $blocked_ips as $entry ) {
                        if ( $entry['ip'] === $ip ) {
                            $is_blocked = true;
                            break;
                        }
                    }
                }
                
                if ( $is_blocked ) {
                    return '<span style="color:#2e7d32;font-weight:bold;">Already Blocked</span>';
                } else {
                    $block_url = wp_nonce_url(
                        admin_url( 'admin.php?page=aag-failed-logins&action=block_ip&ip=' . urlencode( $ip ) ),
                        'aag_quick_block_' . $ip
                    );
                    return '<a href="' . esc_url( $block_url ) . '" class="button button-small" style="background:#d32f2f;color:#fff;border-color:#c62828;">🚫 Block IP</a>';
                }
            default:
                return '';
        }
    }

    public function prepare_items() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'aag_failed_logins';

        $per_page = 25;
        $columns  = $this->get_columns();
        $hidden   = array();
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = array( $columns, $hidden, $sortable );

        $where = 'WHERE 1=1';

        // Search
        if ( ! empty( $_REQUEST['s'] ) ) {
            $search  = '%' . $wpdb->esc_like( sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) ) . '%';
            $where  .= $wpdb->prepare( ' AND (username LIKE %s OR ip_address LIKE %s)', $search, $search );
        }

        // Sorting
        $allowed_orderby = array_keys( $this->get_sortable_columns() );
        $orderby = ( ! empty( $_REQUEST['orderby'] ) && in_array( $_REQUEST['orderby'], $allowed_orderby, true ) )
            ? sanitize_key( $_REQUEST['orderby'] ) : 'failed_at';
        $order   = ( ! empty( $_REQUEST['order'] ) && $_REQUEST['order'] === 'asc' ) ? 'ASC' : 'DESC';

        $total_items = (int) $wpdb->get_var( "SELECT COUNT(id) FROM $table_name $where" );

        $current_page = $this->get_pagenum();
        $offset       = ( $current_page - 1 ) * $per_page;

        $this->items = $wpdb->get_results(
            "SELECT * FROM $table_name $where ORDER BY $orderby $order LIMIT $per_page OFFSET $offset",
            ARRAY_A
        );

        $this->set_pagination_args( array(
            'total_items' => $total_items,
            'per_page'    => $per_page,
            'total_pages' => ceil( $total_items / $per_page ),
        ) );
    }
}

// ── Rendering function ───────────────────────────────────────────────
function aag_render_failed_logins_page() {
    if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Access Denied' ); }

    global $wpdb;
    $table_name = $wpdb->prefix . 'aag_failed_logins';

    // Handle Quick Action IP Block
    if ( isset( $_GET['action'] ) && $_GET['action'] === 'block_ip' && isset( $_GET['ip'] ) ) {
        $ip = sanitize_text_field( wp_unslash( $_GET['ip'] ) );
        if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            check_admin_referer( 'aag_quick_block_' . $ip );
            aag_block_ip( $ip, 'Manually blocked from failed logins logs' );
            echo '<div class="notice notice-success"><p>✅ IP ' . esc_html( $ip ) . ' has been successfully blocked.</p></div>';
        }
    }

    // Handle clear failed logins action
    if ( isset( $_POST['aag_clear_failed_logins'], $_POST['aag_clear_failed_nonce'] ) ) {
        if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['aag_clear_failed_nonce'] ) ), 'aag_clear_failed_action' ) ) {
            $wpdb->query( "TRUNCATE TABLE $table_name" );
            echo '<div class="notice notice-success"><p>✅ Failed login logs cleared.</p></div>';
        }
    }

    // Get statistics
    $total_failed = (int) ( $wpdb->get_var( "SELECT COUNT(id) FROM $table_name" ) ?? 0 );
    $unique_ips   = (int) ( $wpdb->get_var( "SELECT COUNT(DISTINCT ip_address) FROM $table_name WHERE ip_address != ''" ) ?? 0 );
    $last_failed  = $wpdb->get_var( "SELECT MAX(failed_at) FROM $table_name" ) ?: 'Never';

    // Top 5 targeted usernames
    $top_targets = $wpdb->get_results(
        "SELECT username, COUNT(id) as attempts FROM $table_name GROUP BY username ORDER BY attempts DESC LIMIT 5",
        ARRAY_A
    );
    ?>
    <style>
        .aag-stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:28px; }
        .aag-stat-card { background:#fff; padding:20px 16px; border-radius:10px; box-shadow:0 1px 4px rgba(0,0,0,.08); text-align:center; border-top:4px solid #dc3545; }
        .aag-stat-card h3 { margin:0 0 8px; font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:#888; }
        .aag-stat-card .aag-val { font-size:30px; font-weight:700; color:#dc3545; line-height:1; }
        .aag-top-table { width:100%; border-collapse:collapse; margin-bottom:24px; }
        .aag-top-table th { background:#f8f9fa; padding:8px 12px; text-align:left; font-size:12px; text-transform:uppercase; color:#666; border-bottom:2px solid #dee2e6; }
        .aag-top-table td { padding:8px 12px; border-bottom:1px solid #dee2e6; font-size:13px; }
        .aag-top-table tr:hover td { background:#f8f9fa; }
        .aag-section-title { font-size:15px; font-weight:600; color:#23282d; margin:24px 0 12px; }
    </style>

    <div class="wrap">
        <h1 style="display:flex;align-items:center;gap:10px;">
            &#128274; Failed Login Monitor & Brute Force Protection
        </h1>

        <!-- Stats Grid -->
        <div class="aag-stats-grid">
            <div class="aag-stat-card">
                <h3>Total Failed Logins</h3>
                <div class="aag-val"><?php echo number_format_i18n( $total_failed ); ?></div>
            </div>
            <div class="aag-stat-card" style="border-top-color:#fd7e14;">
                <h3>Suspicious IPs</h3>
                <div class="aag-val" style="color:#fd7e14;"><?php echo number_format_i18n( $unique_ips ); ?></div>
            </div>
            <div class="aag-stat-card" style="border-top-color:#6f42c1;">
                <h3>Last Failure At</h3>
                <div style="font-size:13px;color:#6f42c1;font-weight:600;margin-top:6px;"><?php echo esc_html( $last_failed ); ?></div>
            </div>
        </div>

        <!-- Top 5 Targeted Usernames -->
        <?php if ( ! empty( $top_targets ) ) : ?>
        <p class="aag-section-title">&#127919; Top 5 Most Targeted Usernames</p>
        <table class="aag-top-table">
            <thead><tr><th>#</th><th>Targeted Username</th><th>Failed Attempts</th></tr></thead>
            <tbody>
            <?php foreach ( $top_targets as $i => $row ) : ?>
                <tr>
                    <td><?php echo absint( $i + 1 ); ?></td>
                    <td><strong><code><?php echo esc_html( $row['username'] ); ?></code></strong></td>
                    <td><strong><?php echo number_format_i18n( $row['attempts'] ); ?></strong></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>

        <hr style="margin:20px 0;">

        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <p class="aag-section-title" style="margin:0;">📋 Failed Login Log</p>
            
            <form method="post" onsubmit="return confirm('Are you sure you want to delete all failed login history?');" style="margin:0;">
                <?php wp_nonce_field( 'aag_clear_failed_action', 'aag_clear_failed_nonce' ); ?>
                <button type="submit" name="aag_clear_failed_logins" class="button button-link-delete" style="color:#d32f2f;">Clear Failed Logins Log</button>
            </form>
        </div>

        <form method="get">
            <input type="hidden" name="page" value="<?php echo esc_attr( $_REQUEST['page'] ?? 'aag-failed-logins' ); ?>" />
            <?php
            $list_table = new AAG_Failed_Logins_Table();
            $list_table->prepare_items();
            $list_table->search_box( 'Search Username or IP', 'search_logins' );
            $list_table->display();
            ?>
        </form>
    </div>
    <?php
}
