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

    public function testRequirePostApproval()
    {
        global $mock_current_user_is_admin;

        $data = [
            'post_type' => 'post',
            'post_status' => 'publish'
        ];

        // Test 1: User is NOT admin
        $mock_current_user_is_admin = false;
        $result = psc_require_admin_approval_for_posts($data, []);
        $this->assertEquals('pending', $result['post_status'], 'Post status should be forced to pending for non-admins');

        // Test 2: User IS admin
        $mock_current_user_is_admin = true;
        $result = psc_require_admin_approval_for_posts($data, []);
        $this->assertEquals('publish', $result['post_status'], 'Post status should remain publish for admins');

        // Test 3: Not a post
        $data['post_type'] = 'page';
        $mock_current_user_is_admin = false;
        $result = psc_require_admin_approval_for_posts($data, []);
        $this->assertEquals('publish', $result['post_status'], 'Non-post types should not be affected');
    }
}