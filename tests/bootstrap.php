<?php
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
// Include the plugin file to be tested
require_once dirname(__DIR__) . '/plugin-security-check.php';
if (!function_exists('get_bloginfo')) {
    function get_bloginfo($show, $filter = 'raw') {
        if ($show === 'version') return '6.0';
        return '';
    }
}
if (!function_exists('get_locale')) {
    function get_locale() {
        return 'en_US';
    }
}
if (!function_exists('wp_remote_get')) {
    function wp_remote_get($url, $args = array()) {
        return array('response' => array('code' => 200), 'body' => '{"checksums":{"6.0":{"wp-settings.php":"fake_hash"}}}');
    }
}
if (!function_exists('wp_remote_post')) {
    function wp_remote_post($url, $args = array()) {
         return array('response' => array('code' => 200), 'body' => '');
    }
}
if (!function_exists('wp_remote_retrieve_response_code')) {
    function wp_remote_retrieve_response_code($response) {
        return 200;
    }
}
if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body($response) {
        return $response['body'];
    }
}
if (!function_exists('is_wp_error')) {
    function is_wp_error($thing) {
        return false;
    }
}
if (!function_exists('wp_nonce_url')) {
    function wp_nonce_url($actionurl, $action = -1, $name = '_wpnonce') {
        return $actionurl;
    }
}
if (!function_exists('admin_url')) {
    function admin_url($path = '', $scheme = 'admin') {
        return 'http://example.com/wp-admin/' . $path;
    }
}
// Add ABSPATH if not defined
if (!defined('ABSPATH')) {
    define('ABSPATH', sys_get_temp_dir() . '/');
}
if (!function_exists('wp_version_check')) {
    function wp_version_check() {}
}
if (!function_exists('get_site_transient')) {
    function get_site_transient($transient) {
        if ($transient === 'update_core') {
            $obj = new stdClass();
            $offer = new stdClass();
            $offer->response = 'reinstall';
            $obj->updates = [$offer];
            return $obj;
        }
        return false;
    }
}
if (!class_exists('WP_Upgrader_Skin')) {
    class WP_Upgrader_Skin {
        public function feedback($string, ...$args) {}
        public function header() {}
        public function footer() {}
    }
}
if (!class_exists('Core_Upgrader')) {
    class Core_Upgrader {
        public function __construct($skin) {}
        public function upgrade($update, $args) { return true; }
    }
}
