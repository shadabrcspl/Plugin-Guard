<?php

if (!function_exists('wp_get_current_user')) {
    function wp_get_current_user() {
        global $mock_current_user_is_admin;
        if (!class_exists('Mock_WP_User2')) {
            class Mock_WP_User2 {
                public $roles = [];
                public function exists() { return true; }
            }
        }
        $user = new Mock_WP_User2();
        $user->roles = !empty($mock_current_user_is_admin) ? ['administrator'] : ['author'];
        return $user;
    }
}

// Mock WordPress functions
if (!function_exists('get_option')) {
    function get_option($option, $default = false) {
        return isset($GLOBALS['wp_options'][$option]) ? $GLOBALS['wp_options'][$option] : $default;
    }
}
if (!function_exists('update_option')) {
    function update_option($option, $value, $autoload = null) {
        $GLOBALS['wp_options'][$option] = $value;
    }
}
if (!function_exists('delete_option')) {
    function delete_option($option) {
        unset($GLOBALS['wp_options'][$option]);
    }
}
if (!function_exists('deactivate_plugins')) {
    function deactivate_plugins($plugins) {
        // Mock deactivation
    }
}
if (!function_exists('delete_plugins')) {
    function delete_plugins($plugins) {
        // Mock deletion
        foreach ($plugins as $plugin) {
            $path = WP_PLUGIN_DIR . '/' . $plugin;
            if (file_exists($path)) {
                unlink($path);
            }
        }
    }
}
if (!function_exists('register_activation_hook')) {
    function register_activation_hook($file, $function) {}
}
if (!function_exists('add_action')) {
    function add_action($hook, $function_to_add, $priority = 10, $accepted_args = 1) {}
}
if (!function_exists('add_filter')) {
    function add_filter($hook, $function_to_add, $priority = 10, $accepted_args = 1) {}
}
if (!function_exists('plugin_basename')) {
    function plugin_basename($file) {
        return basename($file);
    }
}
if (!function_exists('register_deactivation_hook')) {
    function register_deactivation_hook($file, $function) {}
}
if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir() {
        return ['basedir' => sys_get_temp_dir() . '/wp-content/uploads'];
    }
}
if (!function_exists('insert_with_markers')) {
    function insert_with_markers($filename, $marker, $insertion) {
        return true;
    }
}
if (!function_exists('get_home_path')) {
    function get_home_path() {
        return sys_get_temp_dir() . '/';
    }
}
if (!function_exists('is_author')) {
    function is_author() {
        return false;
    }
}
if (!function_exists('wp_redirect')) {
    function wp_redirect($location, $status = 302, $x_redirect_by = 'WordPress') {}
}
if (!function_exists('home_url')) {
    function home_url($path = '', $scheme = null) {
        return 'http://example.com' . $path;
    }
}
if (!function_exists('add_menu_page')) {
    function add_menu_page() {}
}
if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str) {
        return strip_tags(trim($str));
    }
}
if (!function_exists('wp_die')) {
    function wp_die($message = '', $title = '', $args = array()) {
        die($message);
    }
}
if (!function_exists('current_user_can')) {
    function current_user_can($capability, ...$args) {
        return true;
    }
}
if (!function_exists('esc_html')) {
    function esc_html($text) {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}
if (!function_exists('esc_attr')) {
    function esc_attr($text) {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('is_user_logged_in')) {
    function is_user_logged_in() {
        return false;
    }
}
if (!class_exists('WP_Error')) {
    class WP_Error {
        public function __construct($code = '', $message = '', $data = '') {}
    }
}

if (!function_exists('get_theme_root')) {
    function get_theme_root() {
        return sys_get_temp_dir() . '/wp-content/themes';
    }
}
if (!function_exists('get_userdata')) {
    function get_userdata($id) {
        $user = new stdClass();
        $user->user_login = 'testadmin';
        $user->user_email = 'test@example.com';
        $user->roles = ['administrator'];
        return $user;
    }
}
if (!function_exists('wp_mail')) {
    function wp_mail() {
        return true;
    }
}
if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled($hook) {
        return false;
    }
}
if (!function_exists('wp_schedule_event')) {
    function wp_schedule_event($timestamp, $recurrence, $hook, $args = array()) {
        return true;
    }
}
if (!function_exists('remove_query_arg')) {
    function remove_query_arg($key, $query) {
        return str_replace('?ver=1.0', '', $query);
    }
}
global $table_prefix;
$table_prefix = 'wp_';




// Include the plugin file to be tested

require_once dirname(__DIR__) . '/plugin-security-check.php';if (!function_exists('_get_cron_array')) {
    function _get_cron_array() { return array(); }
}
if (!function_exists('get_users')) {
    function get_users($args = array()) {
        $user = new stdClass();
        $user->ID = 1;
        $user->user_login = 'admin';
        return array($user);
    }
}
if (!class_exists('WP_User')) {
    class WP_User {
        public function __construct($id) {}
        public function remove_role($role) {}
        public function add_role($role) {}
    }
}
if (!function_exists('update_user_meta')) {
    function update_user_meta($user_id, $meta_key, $meta_value, $prev_value = '') { return true; }
}
if (!class_exists('Mock_WPDB')) {
    class Mock_WPDB {
        public $options = 'wp_options';
        public function get_results($query) {
            return array();
        }
    }
}
global $wpdb;
$wpdb = new Mock_WPDB();

$_SERVER['REMOTE_ADDR'] = '192.168.1.1';
if (!function_exists('current_time')) {
    function current_time($type) { return '2023-01-01 12:00:00'; }
}

if (!function_exists('get_posts')) {
    function get_posts($args = array()) {
        $post = new stdClass();
        $post->ID = 123;
        $post->post_title = 'Test Pending Post';
        $post->post_author = 1;
        return array($post);
    }
}

if (!function_exists('wp_update_post')) {
    function wp_update_post($postarr = array(), $wp_error = false, $fire_after_hooks = true) {
        return 123;
    }
}

if (!function_exists('wp_trash_post')) {
    function wp_trash_post($post_id) {
        return true;
    }
}

// Transient Mocks
global $mock_transients;
$mock_transients = array();

if (!function_exists('get_transient')) {
    function get_transient($transient) {
        global $mock_transients;
        return isset($mock_transients[$transient]) ? $mock_transients[$transient] : false;
    }
}
if (!function_exists('set_transient')) {
    function set_transient($transient, $value, $expiration = 0) {
        global $mock_transients;
        $mock_transients[$transient] = $value;
        return true;
    }
}
if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}

if (!function_exists('psc_get_client_ip')) {
    // Provide a mocked get_client_ip if tests run before plugin load
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
}
