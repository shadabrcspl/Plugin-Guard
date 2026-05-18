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
// Include the plugin file to be tested
require_once dirname(__DIR__) . '/plugin-security-check.php';
