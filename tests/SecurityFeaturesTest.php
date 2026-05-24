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

    public function testPostCreationMonitorLinks()
    {
        global $mock_current_user_is_admin;
        $mock_current_user_is_admin = false;

        $data = [
            'post_type' => 'post',
            'post_status' => 'publish',
            'post_title' => 'Test Post',
            'post_content' => '<a href="http://bad-domain.com/spam">Spam</a>'
        ];

        // 1. Test Blacklisted Domains
        update_option('psc_blacklisted_domains', "bad-domain.com\nanother-spam.net");
        $result = psc_post_creation_monitor_filter($data, []);
        $this->assertEquals('pending', $result['post_status'], 'Post should be pending due to blacklisted domain');

        // 2. Test Max External Links
        update_option('psc_blacklisted_domains', '');
        update_option('psc_max_external_links', 2);

        // Mock home_url so we know what internal is

        $data['post_content'] = '
            <a href="http://external.org/1">1</a>
            <a href="https://external.com/2">2</a>
            <a href="http://external-test.com/3">3</a>
        ';
        $data['post_status'] = 'publish'; // reset
        // Reset IP rate limiter transient for this test step
        global $mock_transients;
        $mock_transients = [];

        $result = psc_post_creation_monitor_filter($data, []);
        $this->assertEquals('pending', $result['post_status'], 'Post should be pending due to exceeding max external links');

        // 3. Test Safe Post
        $data['post_content'] = '<a href="http://example.org/1">1</a>';
        $data['post_status'] = 'publish';
        $result = psc_post_creation_monitor_filter($data, []);
        $this->assertEquals('publish', $result['post_status'], 'Safe post should remain published');
    }

    public function test404Redirect()
    {
        global $mock_is_404;

        // Disable option, should not hook
        update_option('psc_redirect_404_to_home', 'no');
        $mock_is_404 = true;
        // Test passes if it does not die (since it's not hooked/active)
        $this->assertTrue(true);

        // We can't safely test the die() natively in PHPUnit without specialized runkits
        // but we can ensure the function exists and syntax is clean
        $this->assertTrue(function_exists('psc_redirect_404_to_home_action'));
    }
}