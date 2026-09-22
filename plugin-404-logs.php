<?php
defined( 'ABSPATH' ) || exit;

// ────────────────────────────────────────────────────────────────────
// 404 LOGS DASHBOARD
// ────────────────────────────────────────────────────────────────────

if ( ! class_exists( 'WP_List_Table' ) ) {
    if ( file_exists( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' ) ) {
        require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
    }
}

class AAG_404_Logs_Table extends WP_List_Table {

    public function __construct() {
        parent::__construct( array(
            'singular' => '404_log',
            'plural'   => '404_logs',
            'ajax'     => false,
        ) );
    }

    public function get_columns() {
        return array(
            'requested_url'   => 'Requested URL',
            'hits'            => 'Hits',
            'last_ip'         => 'Last Visitor IP',
            'last_user_agent' => 'Browser / Device',
            'first_accessed'  => 'First Seen',
            'last_accessed'   => 'Last Seen',
            'status'          => 'Status',
            'action'          => 'Quick Action',
        );
    }

    public function get_sortable_columns() {
        return array(
            'requested_url'  => array( 'requested_url', false ),
            'hits'           => array( 'hits', false ),
            'last_ip'        => array( 'last_ip', false ),
            'first_accessed' => array( 'first_accessed', false ),
            'last_accessed'  => array( 'last_accessed', true ),
        );
    }

    public function column_default( $item, $column_name ) {
        switch ( $column_name ) {
            case 'requested_url':
                return '<strong style="word-break:break-all;">' . esc_html( $item['requested_url'] ) . '</strong>'
                    . '<div style="color:#999;font-size:11px;">&#8594; ' . esc_html( $item['redirect_dest'] ) . ' (301)</div>';
            case 'hits':
                return '<span style="font-size:18px;font-weight:bold;color:#0073aa;">' . number_format_i18n( $item['hits'] ) . '</span>';
            case 'last_ip':
                if ( empty( $item['last_ip'] ) ) { return '<em style="color:#aaa;">Unknown</em>'; }
                return '<code>' . esc_html( $item['last_ip'] ) . '</code>'
                    . '<br><a href="https://ipinfo.io/' . esc_attr( $item['last_ip'] ) . '" target="_blank" style="font-size:11px;">Lookup IP &#8594;</a>';
            case 'last_user_agent':
                if ( empty( $item['last_user_agent'] ) ) { return '<em style="color:#aaa;">Unknown</em>'; }
                $ua    = esc_html( $item['last_user_agent'] );
                $short = strlen( $ua ) > 60 ? substr( $ua, 0, 60 ) . '&hellip;' : $ua;
                return '<span title="' . $ua . '" style="cursor:help;font-size:11px;">' . $short . '</span>';
            case 'first_accessed':
            case 'last_accessed':
                return '<span style="font-size:12px;">' . esc_html( $item[ $column_name ] ) . '</span>';
            case 'status':
                return $item['is_active']
                    ? '<span style="background:#d4edda;color:#155724;padding:3px 8px;border-radius:12px;font-size:11px;font-weight:bold;">Active</span>'
                    : '<span style="background:#e2e3e5;color:#383d41;padding:3px 8px;border-radius:12px;font-size:11px;">Disabled</span>';
            case 'action':
                $ip = $item['last_ip'];
                if ( empty( $ip ) ) {
                    return '';
                }
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
                    return '<span style="color:#2e7d32;font-weight:bold;">Blocked</span>';
                } else {
                    $block_url = wp_nonce_url(
                        admin_url( 'admin.php?page=aag-404-logs&action=block_ip&ip=' . urlencode( $ip ) ),
                        'aag_quick_block_' . $ip
                    );
                    return '<a href="' . esc_url( $block_url ) . '" class="button button-small" style="background:#d32f2f;color:#fff;border-color:#c62828;">🚫 Block IP</a>';
                }
            default:
                return esc_html( $item[ $column_name ] ?? '' );
        }
    }

    public function prepare_items() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'aag_404_logs';

        $per_page = 25;
        $columns  = $this->get_columns();
        $hidden   = array();
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = array( $columns, $hidden, $sortable );

        $where = 'WHERE 1=1';

        // Search by URL or IP - fully parameterized
        if ( ! empty( $_REQUEST['s'] ) ) {
            $search  = '%' . $wpdb->esc_like( sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) ) . '%';
            $where  .= $wpdb->prepare( ' AND (requested_url LIKE %s OR last_ip LIKE %s)', $search, $search );
        }

        // Sorting - strictly allow-listed
        $allowed_orderby = array_keys( $this->get_sortable_columns() );
        $orderby = ( ! empty( $_REQUEST['orderby'] ) && in_array( $_REQUEST['orderby'], $allowed_orderby, true ) )
            ? sanitize_key( $_REQUEST['orderby'] ) : 'last_accessed';
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

function aag_render_404_logs_page() {
    if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Access Denied' ); }

    global $wpdb;
    $table_name = $wpdb->prefix . 'aag_404_logs';

    // Handle Quick Action IP Block
    if ( isset( $_GET['action'] ) && $_GET['action'] === 'block_ip' && isset( $_GET['ip'] ) ) {
        $ip = sanitize_text_field( wp_unslash( $_GET['ip'] ) );
        if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            check_admin_referer( 'aag_quick_block_' . $ip );
            aag_block_ip( $ip, 'Manually blocked from 404 logs dashboard' );
            echo '<div class="notice notice-success"><p>✅ IP ' . esc_html( $ip ) . ' has been successfully blocked.</p></div>';
        }
    }

    // Statistics
    $total_urls = (int) ( $wpdb->get_var( "SELECT COUNT(id) FROM $table_name" ) ?? 0 );
    $total_hits = (int) ( $wpdb->get_var( "SELECT SUM(hits) FROM $table_name" ) ?? 0 );
    $today_hits = (int) ( $wpdb->get_var( $wpdb->prepare(
        "SELECT SUM(hits) FROM $table_name WHERE DATE(last_accessed) = %s", current_time( 'Y-m-d' )
    ) ) ?? 0 );
    $unique_ips = (int) ( $wpdb->get_var( "SELECT COUNT(DISTINCT last_ip) FROM $table_name WHERE last_ip != ''" ) ?? 0 );
    $last_time  = $wpdb->get_var( "SELECT MAX(last_accessed) FROM $table_name" ) ?: 'Never';

    // Top 5 most-hit 404 URLs
    $top_urls = $wpdb->get_results(
        "SELECT requested_url, hits, last_ip FROM $table_name ORDER BY hits DESC LIMIT 5",
        ARRAY_A
    );
    ?>
    <style>
        .aag-stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:28px; }
        .aag-stat-card { background:#fff; padding:20px 16px; border-radius:10px; box-shadow:0 1px 4px rgba(0,0,0,.08); text-align:center; border-top:4px solid #0073aa; }
        .aag-stat-card h3 { margin:0 0 8px; font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:#888; }
        .aag-stat-card .aag-val { font-size:30px; font-weight:700; color:#0073aa; line-height:1; }
        .aag-stat-card.green { border-top-color:#28a745; } .aag-stat-card.green .aag-val { color:#28a745; }
        .aag-stat-card.orange { border-top-color:#fd7e14; } .aag-stat-card.orange .aag-val { color:#fd7e14; }
        .aag-stat-card.red { border-top-color:#dc3545; } .aag-stat-card.red .aag-val { color:#dc3545; }
        .aag-top-table { width:100%; border-collapse:collapse; margin-bottom:24px; }
        .aag-top-table th { background:#f8f9fa; padding:8px 12px; text-align:left; font-size:12px; text-transform:uppercase; color:#666; border-bottom:2px solid #dee2e6; }
        .aag-top-table td { padding:8px 12px; border-bottom:1px solid #dee2e6; font-size:13px; word-break:break-all; }
        .aag-top-table tr:hover td { background:#f8f9fa; }
        .aag-section-title { font-size:15px; font-weight:600; color:#23282d; margin:24px 0 12px; }
    </style>

    <div class="wrap">
        <h1 style="display:flex;align-items:center;gap:10px;">
            &#128269; 404 Redirect Monitor
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=aag-settings' ) ); ?>" style="font-size:13px;font-weight:normal;">Settings &#8594;</a>
        </h1>

        <!-- Stats Grid -->
        <div class="aag-stats-grid">
            <div class="aag-stat-card">
                <h3>Unique 404 URLs</h3>
                <div class="aag-val"><?php echo number_format_i18n( $total_urls ); ?></div>
            </div>
            <div class="aag-stat-card green">
                <h3>Total Redirect Hits</h3>
                <div class="aag-val"><?php echo number_format_i18n( $total_hits ); ?></div>
            </div>
            <div class="aag-stat-card orange">
                <h3>Today's Hits</h3>
                <div class="aag-val"><?php echo number_format_i18n( $today_hits ); ?></div>
            </div>
            <div class="aag-stat-card red">
                <h3>Unique Visitor IPs</h3>
                <div class="aag-val"><?php echo number_format_i18n( $unique_ips ); ?></div>
            </div>
            <div class="aag-stat-card" style="border-top-color:#6f42c1;">
                <h3>Last Hit At</h3>
                <div style="font-size:13px;color:#6f42c1;font-weight:600;margin-top:6px;"><?php echo esc_html( $last_time ); ?></div>
            </div>
        </div>

        <!-- Top 5 Hit URLs -->
        <?php if ( ! empty( $top_urls ) ) : ?>
        <p class="aag-section-title">&#128293; Top 5 Most Hit 404 URLs</p>
        <table class="aag-top-table">
            <thead><tr><th>#</th><th>Requested URL</th><th>Hits</th><th>Last Visitor IP</th></tr></thead>
            <tbody>
            <?php foreach ( $top_urls as $i => $row ) : ?>
                <tr>
                    <td><?php echo absint( $i + 1 ); ?></td>
                    <td><?php echo esc_html( $row['requested_url'] ); ?></td>
                    <td><strong><?php echo number_format_i18n( $row['hits'] ); ?></strong></td>
                    <td>
                        <?php if ( ! empty( $row['last_ip'] ) ) : ?>
                            <code><?php echo esc_html( $row['last_ip'] ); ?></code>
                            <a href="<?php echo esc_url( 'https://ipinfo.io/' . $row['last_ip'] ); ?>" target="_blank" style="font-size:11px;"> Lookup &#8594;</a>
                        <?php else : ?>
                            <em style="color:#aaa;">Unknown</em>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>

        <hr>

        <!-- Full Log Table -->
        <p class="aag-section-title">&#128203; Full Redirect Log</p>
        <form method="get">
            <input type="hidden" name="page" value="<?php echo esc_attr( $_REQUEST['page'] ?? 'aag-404-logs' ); ?>" />
            <?php
            $list_table = new AAG_404_Logs_Table();
            $list_table->prepare_items();
            $list_table->search_box( 'Search URL or IP', 'search_404' );
            $list_table->display();
            ?>
        </form>
    </div>
    <?php
}
