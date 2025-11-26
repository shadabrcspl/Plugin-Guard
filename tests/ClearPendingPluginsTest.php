<?php
use PHPUnit\Framework\TestCase;

class ClearPendingPluginsTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        // Set up a dummy WordPress environment
        define('WP_PLUGIN_DIR', sys_get_temp_dir() . '/wp-content/plugins');
        if (!is_dir(WP_PLUGIN_DIR)) {
            mkdir(WP_PLUGIN_DIR, 0777, true);
        }
    }

    protected function setUp(): void
    {
        // Mock WordPress functions and globals
        global $wp_options;
        $wp_options = [];

        // Include the plugin file to be tested
        require_once dirname(__DIR__) . '/plugin-security-check.php';
    }

    public function testClearPendingPlugins()
    {
        // Create a dummy plugin file
        $plugin_slug = 'dummy-plugin/dummy-plugin.php';
        $plugin_dir = WP_PLUGIN_DIR . '/dummy-plugin';
        if (!is_dir($plugin_dir)) {
            mkdir($plugin_dir, 0777, true);
        }
        touch(WP_PLUGIN_DIR . '/' . $plugin_slug);

        // Add the dummy plugin to the pending approval list
        update_option('pending_approval_plugins', [$plugin_slug]);

        // Call the function to clear pending plugins
        clear_pending_plugins();

        // Assert that the pending plugins list is empty
        $this->assertEmpty(get_option('pending_approval_plugins'));

        // Assert that the dummy plugin file has been deleted
        $this->assertFileDoesNotExist(WP_PLUGIN_DIR . '/' . $plugin_slug);
    }
}
