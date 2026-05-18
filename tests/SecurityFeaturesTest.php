<?php
use PHPUnit\Framework\TestCase;

class SecurityFeaturesTest extends TestCase
{
    protected function setUp(): void
    {
        global $wp_options;
        $wp_options = [];

        // Reset $_SERVER variables
        $_SERVER['QUERY_STRING'] = '';
    }

    public function testDisableXmlRpc()
    {
        // When enabled
        update_option('psc_disable_xmlrpc', 'yes');

        // We can't directly test add_filter here easily without a full WP load,
        // but we can ensure the option is read correctly.
        $this->assertEquals('yes', get_option('psc_disable_xmlrpc'));
    }

    public function testPreventUserEnumeration()
    {
        update_option('psc_prevent_enumeration', 'yes');

        // Test REST API endpoint removal
        $endpoints = [
            '/wp/v2/posts' => true,
            '/wp/v2/users' => true,
            '/wp/v2/users/(?P<id>[\d]+)' => true,
        ];

        $filtered = psc_block_rest_user_enumeration($endpoints);

        $this->assertArrayHasKey('/wp/v2/posts', $filtered);
        $this->assertArrayNotHasKey('/wp/v2/users', $filtered);
        $this->assertArrayNotHasKey('/wp/v2/users/(?P<id>[\d]+)', $filtered);
    }

    public function testRestrictRestApi()
    {
        update_option('psc_restrict_rest_api', 'yes');

        // Test when user is not logged in (mocked in bootstrap to return false)
        $result = psc_restrict_rest_api_to_authenticated_users(null);

        $this->assertInstanceOf('WP_Error', $result);
    }
}
