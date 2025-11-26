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
    }
}
// Include the plugin file to be tested
require_once dirname(__DIR__) . '/plugin-security-check.php';
