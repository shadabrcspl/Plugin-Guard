<?php
/**
 * Test bootstrap for Admin Approval Guard plugin.
 * Provides minimal WordPress function stubs so tests run without a full WP install.
 */

// ── Constants ──────────────────────────────────────────────────────
if ( ! defined( 'ABSPATH' ) )           define( 'ABSPATH', sys_get_temp_dir() . '/wordpress/' );
if ( ! defined( 'WP_CONTENT_DIR' ) )    define( 'WP_CONTENT_DIR', ABSPATH . 'wp-content' );
if ( ! defined( 'WP_PLUGIN_DIR' ) )     define( 'WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins' );
if ( ! defined( 'HOUR_IN_SECONDS' ) )   define( 'HOUR_IN_SECONDS', 3600 );
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) define( 'MINUTE_IN_SECONDS', 60 );
if ( ! defined( 'DAY_IN_SECONDS' ) )    define( 'DAY_IN_SECONDS', 86400 );


// ── Global state ───────────────────────────────────────────────────
$GLOBALS['wp_options']  = [];
$GLOBALS['wp_usermeta'] = [];   // [ user_id => [ key => value ] ]
$GLOBALS['wp_users']    = [];   // [ user_id => WP_User_Mock ]
$GLOBALS['wp_mail_log'] = [];   // captured wp_mail calls

class WPDB_Mock {
    public string $prefix = 'wp_';
    public string $usermeta = 'wp_usermeta';
    public function get_charset_collate(): string { return 'DEFAULT CHARSET=utf8mb4'; }
    public function get_blog_prefix( $blog_id = 0 ): string { return $this->prefix; }
    public function get_var( $query = null, $x = 0, $y = 0 ) { return null; }
    public function get_row( $query = null, $output = 'OBJECT', $y = 0 ) { return null; }
    public function get_results( $query = null, $output = 'OBJECT' ) { return []; }
    public function get_col( $query = null, $x = 0 ) { return $GLOBALS['wpdb_mock_cols'] ?? []; }
    public function query( $query ) { return true; }
    public function prepare( $query, ...$args ) {
        if ( empty( $args ) ) return $query;
        if ( is_array( $args[0] ?? null ) ) $args = $args[0];
        $escaped = array_map( function( $a ) { return "'" . addslashes( (string)$a ) . "'"; }, $args );
        return vsprintf( str_replace( [ '%s', '%d', '%f' ], [ '%s', '%s', '%s' ], $query ), $escaped );
    }
    public function insert( $table, $data, $format = null ) { return true; }
    public function update( $table, $data, $where, $format = null, $where_format = null ) { return true; }
    public function esc_like( $text ) { return addcslashes( $text, '_%\\' ); }
}
$GLOBALS['wpdb'] = new WPDB_Mock();
global $wpdb;
$wpdb = $GLOBALS['wpdb'];

function dbDelta( $queries = '' ) { return []; }

// ── Options API ────────────────────────────────────────────────────
function get_option( $option, $default = false ) {
    return array_key_exists( $option, $GLOBALS['wp_options'] )
        ? $GLOBALS['wp_options'][ $option ]
        : $default;
}
function update_option( $option, $value, $autoload = null ) {
    $GLOBALS['wp_options'][ $option ] = $value;
    return true;
}
function add_option( $option, $value = '', $deprecated = '', $autoload = 'yes' ) {
    if ( ! array_key_exists( $option, $GLOBALS['wp_options'] ) ) {
        $GLOBALS['wp_options'][ $option ] = $value;
    }
    return true;
}
function delete_option( $option ) {
    unset( $GLOBALS['wp_options'][ $option ] );
    return true;
}

// ── User Meta API ──────────────────────────────────────────────────
function get_user_meta( $user_id, $key = '', $single = false ) {
    $val = $GLOBALS['wp_usermeta'][ $user_id ][ $key ] ?? '';
    return $single ? $val : ( $val !== '' ? [ $val ] : [] );
}
function update_user_meta( $user_id, $key, $value, $prev = '' ) {
    $GLOBALS['wp_usermeta'][ $user_id ][ $key ] = $value;
    return true;
}
function delete_user_meta( $user_id, $key, $value = '' ) {
    unset( $GLOBALS['wp_usermeta'][ $user_id ][ $key ] );
    return true;
}

// ── Minimal WP_User mock ───────────────────────────────────────────
class WP_User_Mock {
    public int    $ID           = 0;
    public string $user_login   = '';
    public string $user_email   = '';
    public string $display_name = '';
    public string $user_registered = '2024-01-01 00:00:00';
    public string $user_url     = '';
    public string $description  = '';
    public string $nickname     = '';
    public string $first_name   = '';
    public string $last_name    = '';
    public array  $roles        = [];

    public function __construct( array $data = [] ) {
        foreach ( $data as $k => $v ) {
            if ( property_exists( $this, $k ) ) $this->$k = $v;
        }
    }

    public function set_role( string $role ) {
        $this->roles = [ $role ];
        $GLOBALS['wp_usermeta'][ $this->ID ]['wp_capabilities'] = [ $role => true ];
    }

    public function remove_role( string $role ) {
        $this->roles = array_values( array_filter( $this->roles, fn( $r ) => $r !== $role ) );
    }

    public function add_role( string $role ) {
        if ( ! in_array( $role, $this->roles, true ) ) {
            $this->roles[] = $role;
        }
    }
}

function get_userdata( $id ) {
    return $GLOBALS['wp_users'][ (int) $id ] ?? false;
}

function get_user_by( $field, $value ) {
    foreach ( $GLOBALS['wp_users'] as $u ) {
        if ( $field === 'id' && (int) $u->ID === (int) $value ) return $u;
        if ( $field === 'login' && strtolower( $u->user_login ) === strtolower( (string) $value ) ) return $u;
        if ( $field === 'email' && strtolower( $u->user_email ) === strtolower( (string) $value ) ) return $u;
    }
    return false;
}

function is_email( $email ) {
    return filter_var( $email, FILTER_VALIDATE_EMAIL ) ? (string) $email : false;
}

if ( ! class_exists( 'WP_Session_Tokens' ) ) {
    class WP_Session_Tokens {
        public static array $destroyed_users = [];
        public int $user_id;
        public function __construct( int $user_id ) {
            $this->user_id = $user_id;
        }
        public static function get_instance( int $user_id ) {
            return new self( $user_id );
        }
        public function destroy_all() {
            self::$destroyed_users[] = $this->user_id;
        }
    }
}

function get_users( array $args = [] ) {
    $role = $args['role'] ?? '';
    return array_filter(
        array_values( $GLOBALS['wp_users'] ),
        fn( $u ) => empty( $role ) || in_array( $role, $u->roles, true )
    );
}

// Helper: register a test user in the global store.
function aag_test_create_user( int $id, string $login, string $email, array $roles = [] ): WP_User_Mock {
    $u               = new WP_User_Mock();
    $u->ID           = $id;
    $u->user_login   = $login;
    $u->user_email   = $email;
    $u->display_name = $login;
    $u->first_name   = $login;
    $u->roles        = $roles;
    $GLOBALS['wp_users'][ $id ] = $u;
    return $u;
}

// ── WP Error ───────────────────────────────────────────────────────
class WP_Error {
    public string $code;
    public string $message;
    public function __construct( string $code = '', string $message = '', $data = '' ) {
        $this->code    = $code;
        $this->message = $message;
    }
    public function get_error_message() { return $this->message; }
}
function is_wp_error( $thing ) { return $thing instanceof WP_Error; }

// ── WordPress hooks (no-ops for unit tests) ────────────────────────
function add_action()    {}
function add_filter()    {}
function remove_action() {}
function register_activation_hook()   {}
function register_deactivation_hook() {}

// ── Utility stubs ──────────────────────────────────────────────────
function sanitize_text_field( $str ) { return strip_tags( trim( (string) $str ) ); }
function sanitize_key( $key )        { return strtolower( preg_replace( '/[^a-z0-9_\-]/i', '', (string) $key ) ); }
function esc_html( $text )           { return htmlspecialchars( (string) $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); }
function esc_attr( $text )           { return htmlspecialchars( (string) $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); }
function esc_url_raw( $url )         { return filter_var( (string) $url, FILTER_SANITIZE_URL ) ?: ''; }
function absint( $v )                { return abs( (int) $v ); }
function wp_unslash( $v )            { return is_array( $v ) ? array_map( 'wp_unslash', $v ) : stripslashes( (string) $v ); }
function wp_kses( $str, $allowed )   { return strip_tags( (string) $str ); }
function current_time( $type, $gmt = false ) { return $gmt ? time() : time() + get_option('gmt_offset', 0) * 3600; }
function home_url( $path = '' )      { return 'https://example.com' . $path; }
function admin_url( $path = '' )     { return 'https://example.com/wp-admin/' . ltrim( $path, '/' ); }
function wp_login_url( $redirect = '' ) { return 'https://example.com/wp-login.php'; }
function get_bloginfo( $show = '' )  { return $show === 'name' ? 'Test Site' : 'Test Site'; }
function get_locale()                { return 'en_US'; }
function is_multisite()              { return false; }
function is_user_logged_in() {
    return ! empty( $GLOBALS['aag_current_user_id'] );
}
function wp_doing_cron() {
    return ! empty( $GLOBALS['wp_doing_cron'] );
}

function __( $text, $domain = 'default' ) { return $text; }
function esc_html__( $text, $domain = 'default' ) { return $text; }
function esc_attr__( $text, $domain = 'default' ) { return $text; }
function _n( $single, $plural, $number, $domain = 'default' ) { return $number === 1 ? $single : $plural; }
function sanitize_file_name( $filename ) { return preg_replace( '/[^A-Za-z0-9._-]/', '', (string)$filename ); }
function trailingslashit( $string ) { return rtrim( (string)$string, '/\\' ) . '/'; }
function plugin_dir_path( $file ) { return trailingslashit( dirname( $file ) ); }

function current_user_can( $cap ) {
    $uid = $GLOBALS['aag_current_user_id'] ?? 0;
    if ( ! $uid ) return false;
    $u = get_userdata( $uid );
    if ( ! $u ) return false;
    return in_array( 'administrator', $u->roles, true );
}
function get_current_user_id() { return $GLOBALS['aag_current_user_id'] ?? 0; }
function wp_get_current_user() {
    $uid = get_current_user_id();
    return $uid ? get_userdata( $uid ) : (object) [ 'user_login' => 'anonymous', 'ID' => 0 ];
}
function user_can( $user_id, $cap ) {
    $u = get_userdata( is_object( $user_id ) ? $user_id->ID : (int) $user_id );
    return $u && in_array( 'administrator', $u->roles, true );
}

function wp_hash( $data )                     { return hash( 'sha256', 'salt' . $data ); }
if ( ! function_exists( 'hash_equals' ) ) {
    function hash_equals( $known, $user )     { return $known === $user; }
}
function add_query_arg( $args, $url )         { return $url . '?' . http_build_query( $args ); }
function wp_generate_password( $len = 12, $sc = true, $esc = false ) {
    return substr( str_repeat( 'abcdefghijklmnopqrstuvwxyz0123456789', 4 ), 0, $len );
}
function wp_nonce_field() {}
function wp_verify_nonce( $nonce, $action ) { return true; }
function wp_die( $msg = '', $title = '', $args = [] ) { throw new RuntimeException( strip_tags( (string) $msg ) ); }

function wp_mail( $to, $subject, $message, $headers = [], $attachments = [] ) {
    $GLOBALS['wp_mail_log'][] = compact( 'to', 'subject', 'message' );
    return true;
}

function get_transient( $key )            { return $GLOBALS['wp_transients'][ $key ] ?? false; }
function set_transient( $key, $val, $exp = 0 ) { $GLOBALS['wp_transients'][ $key ] = $val; return true; }
function wp_remote_get( $url, $args = [] ) {
    // Always simulate a failed / empty response so GeoIP falls back to defaults.
    return new WP_Error( 'http_request_failed', 'Mocked: no real HTTP in tests.' );
}

function wp_remote_retrieve_body( $response ) {
    return is_array( $response ) && isset( $response['body'] ) ? $response['body'] : '';
}

function wp_mkdir_p( $target ) {
    return is_dir( $target ) || mkdir( $target, 0777, true );
}

function wp_next_scheduled( $hook, $args = [] ) { return false; }
function wp_schedule_event( $timestamp, $recurrence, $hook, $args = [] ) { return true; }
function wp_clear_scheduled_hook( $hook, $args = [] ) { return true; }
function human_time_diff( $from, $to = '' ) { return '1 hour'; }
function wp_send_json_success( $data = null ) { echo json_encode( [ 'success' => true, 'data' => $data ] ); exit; }
function wp_send_json_error( $data = null ) { echo json_encode( [ 'success' => false, 'data' => $data ] ); exit; }

function doing_action( $hook = '' ) { return false; }

if ( ! class_exists( 'WP_List_Table' ) ) {
    class WP_List_Table {
        public function __construct( $args = [] ) {}
        public function get_columns() { return []; }
        public function prepare_items() {}
        public function display() {}
    }
}

// ── Load the plugin ────────────────────────────────────────────────
require_once dirname( __DIR__ ) . '/plugin-security-check.php';
