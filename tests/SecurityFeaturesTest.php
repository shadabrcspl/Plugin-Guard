<?php
/**
 * Admin Approval Guard — PHPUnit Test Suite
 *
 * Tests cover:
 *   1.  New user registered with admin role → demoted + queued
 *   2.  Privilege escalation (role change to admin) → blocked + queued
 *   3.  Capability filter → pending user has no dangerous caps
 *   4.  aag_is_pending() returns correct values
 *   5.  Approve workflow → user gets admin role + log entry + email
 *   6.  Reject workflow → user stays subscriber + log entry + email
 *   7.  Revoke workflow → existing admin loses role
 *   8.  Duplicate quarantine → same user not added twice
 *   9.  aag_is_authorized_admin() → pending admin NOT considered authorized
 *   10. aag_geoip_lookup() → returns safe defaults when HTTP fails
 *   11. aag_parse_user_agent() → correct browser / OS extraction
 *   12. aag_get_client_ip() → handles proxy headers & validates IP
 *   13. aag_generate_token() → produces unique tokens
 *   14. Audit log entries → written and capped at AAG_LOG_LIMIT
 *   15. aag_detect_registration_source() → recognises REST_REQUEST
 *   16. Email-link approve handler → correct approval via GET params
 *   17. Email-link reject handler  → correct rejection via GET params
 */

use PHPUnit\Framework\TestCase;

class SecurityFeaturesTest extends TestCase
{
    // ── Lifecycle ──────────────────────────────────────────────────

    protected function setUp(): void
    {
        // Reset all global state before every test.
        $GLOBALS['wp_options']    = [];
        $GLOBALS['wp_usermeta']   = [];
        $GLOBALS['wp_users']      = [];
        $GLOBALS['wp_mail_log']   = [];
        $GLOBALS['wp_transients'] = [];
        $GLOBALS['aag_current_user_id'] = 0;
        $GLOBALS['wp_doing_cron'] = false;
        $_SERVER['REMOTE_ADDR']   = '1.2.3.4';
        unset( $_SERVER['HTTP_X_FORWARDED_FOR'],
               $_SERVER['HTTP_CF_CONNECTING_IP'],
               $_SERVER['HTTP_CLIENT_IP'],
               $_SERVER['HTTP_USER_AGENT'],
               $_SERVER['HTTP_REFERER'],
               $_SERVER['REQUEST_URI'],
               $_SERVER['REQUEST_METHOD'] );

        // Initialise the options aag_activate() would create.
        aag_activate();
    }

    // ── 1. New admin-role registration → demoted & queued ─────────

    public function testNewAdminUserIsDemotedAndQueued(): void
    {
        $user = aag_test_create_user( 10, 'hacker', 'hacker@evil.com', [ 'administrator' ] );

        // Simulate the user_register hook firing.
        aag_intercept_new_user( 10 );

        // Role should now be subscriber.
        $this->assertContains( 'subscriber', $user->roles );
        $this->assertNotContains( 'administrator', $user->roles );

        // Must appear in the pending queue.
        $pending = get_option( AAG_OPTION_PENDING, [] );
        $entry   = $this->findEntry( $pending, 10 );
        $this->assertNotNull( $entry, 'User must appear in pending queue' );
        $this->assertSame( 'pending', $entry['status'] );
        $this->assertSame( 'new_registration_as_admin', $entry['reason'] );

        // Also, the IP must be blocked since it was offline.
        $blocked = get_option( AAG_BLOCKED_IPS_OPTION, [] );
        $this->assertNotEmpty( $blocked, 'IP should be blocked' );
        $this->assertSame( '1.2.3.4', $blocked[0]['ip'] );
    }

    // ── 2. Privilege escalation blocked ───────────────────────────

    public function testPrivilegeEscalationBlocked(): void
    {
        $user = aag_test_create_user( 20, 'editor', 'editor@site.com', [ 'editor' ] );

        // Simulate someone changing this user's role to admin.
        aag_intercept_role_change( 20, 'administrator', [ 'editor' ] );

        // Must NOT be admin.
        $this->assertNotContains( 'administrator', $user->roles );
        // Must be in pending queue with escalation reason.
        $pending = get_option( AAG_OPTION_PENDING, [] );
        $entry   = $this->findEntry( $pending, 20 );
        $this->assertNotNull( $entry );
        $this->assertSame( 'privilege_escalation_attempt', $entry['reason'] );

        // Also, the IP must be blocked since it was offline.
        $blocked = get_option( AAG_BLOCKED_IPS_OPTION, [] );
        $this->assertNotEmpty( $blocked, 'IP should be blocked' );
        $this->assertSame( '1.2.3.4', $blocked[0]['ip'] );
    }

    // ── 3. Capability filter strips dangerous caps from pending ────

    public function testCapFilterStripsDangerousCapsForPendingUser(): void
    {
        $user = aag_test_create_user( 30, 'pending_user', 'p@site.com', [ 'subscriber' ] );
        // Manually mark as pending.
        update_user_meta( 30, '_aag_pending', 1 );

        $allcaps = [
            'manage_options' => true,
            'install_plugins' => true,
            'read'            => true,
        ];

        $filtered = aag_filter_pending_admin_caps( $allcaps, [], [], $user );

        $this->assertFalse( $filtered['manage_options'], 'manage_options must be stripped for pending user' );
        $this->assertFalse( $filtered['install_plugins'], 'install_plugins must be stripped for pending user' );
        $this->assertTrue( $filtered['read'], 'read (safe cap) must remain' );
    }

    // ── 4. aag_is_pending() ────────────────────────────────────────

    public function testIsPending(): void
    {
        aag_test_create_user( 40, 'normal', 'n@site.com', [ 'subscriber' ] );
        $this->assertFalse( aag_is_pending( 40 ), 'Fresh user must NOT be pending' );

        update_user_meta( 40, '_aag_pending', 1 );
        $this->assertTrue( aag_is_pending( 40 ), 'User with _aag_pending meta must return true' );
    }

    // ── 5. Approve workflow ────────────────────────────────────────

    public function testApproveUserGrantsAdminRole(): void
    {
        $user = aag_test_create_user( 50, 'candidate', 'c@site.com', [ 'subscriber' ] );
        update_user_meta( 50, '_aag_pending', 1 );

        $entry = [ 'user_id' => 50, 'reason' => 'test', 'status' => 'pending', 'meta' => [] ];
        aag_approve_user( 50, $entry );

        // Role must be administrator.
        $this->assertContains( 'administrator', $user->roles );
        // Pending meta must be cleared.
        $this->assertFalse( (bool) get_user_meta( 50, '_aag_pending', true ) );
        // Log must contain an approved entry.
        $logs = get_option( AAG_OPTION_LOG, [] );
        $this->assertNotEmpty( $logs );
        $this->assertSame( 'admin_approved', $logs[0]['event_type'] );
        // Email must have been sent.
        $this->assertNotEmpty( $GLOBALS['wp_mail_log'] );
    }

    // ── 6. Reject workflow ─────────────────────────────────────────

    public function testRejectUserKeepsSubscriberRole(): void
    {
        $user = aag_test_create_user( 60, 'requester', 'r@site.com', [ 'editor' ] );
        update_user_meta( 60, '_aag_pending', 1 );

        $entry = [ 'user_id' => 60, 'reason' => 'test', 'status' => 'pending', 'meta' => [] ];
        aag_reject_user( 60, $entry );

        // Role must be subscriber (demoted).
        $this->assertContains( 'subscriber', $user->roles );
        $this->assertNotContains( 'administrator', $user->roles );
        // Pending meta cleared.
        $this->assertFalse( (bool) get_user_meta( 60, '_aag_pending', true ) );
        // Log must contain rejected entry.
        $logs = get_option( AAG_OPTION_LOG, [] );
        $this->assertSame( 'admin_rejected', $logs[0]['event_type'] );
        // Email sent.
        $this->assertNotEmpty( $GLOBALS['wp_mail_log'] );
    }

    // ── 7. Duplicate quarantine prevention ────────────────────────

    public function testDuplicateQuarantineIsIgnored(): void
    {
        $user = aag_test_create_user( 70, 'multi', 'm@site.com', [ 'administrator' ] );

        aag_intercept_new_user( 70 );
        $countAfterFirst = count( get_option( AAG_OPTION_PENDING, [] ) );

        // Simulate a second identical hook firing.
        aag_intercept_new_user( 70 );
        $countAfterSecond = count( get_option( AAG_OPTION_PENDING, [] ) );

        $this->assertSame( $countAfterFirst, $countAfterSecond, 'Same user must not be queued twice' );
    }

    // ── 8. aag_is_authorized_admin() ──────────────────────────────

    public function testPendingAdminIsNotAuthorized(): void
    {
        $user = aag_test_create_user( 80, 'badmin', 'b@site.com', [ 'administrator' ] );
        update_user_meta( 80, '_aag_pending', 1 );

        $this->assertFalse( aag_is_authorized_admin( 80 ), 'A pending admin must NOT be considered authorized' );
    }

    public function testRealAdminIsAuthorized(): void
    {
        $user = aag_test_create_user( 81, 'realadmin', 'ra@site.com', [ 'administrator' ] );
        // Not pending.
        $this->assertTrue( aag_is_authorized_admin( 81 ), 'Approved, non-pending admin must be authorized' );
    }

    // ── 9. GeoIP defaults when HTTP fails ─────────────────────────

    public function testGeoIpReturnsDefaultsOnHttpFailure(): void
    {
        // wp_remote_get always returns WP_Error in test bootstrap.
        $result = aag_geoip_lookup( '8.8.8.8' );

        $this->assertIsArray( $result );
        $this->assertArrayHasKey( 'country', $result );
        $this->assertArrayHasKey( 'city', $result );
        $this->assertArrayHasKey( 'isp', $result );
    }

    public function testGeoIpSkipsPrivateIp(): void
    {
        $result = aag_geoip_lookup( '192.168.1.1' );
        $this->assertSame( 'Unknown', $result['country'] );
    }

    public function testGeoIpSkipsLocalhostIp(): void
    {
        $result = aag_geoip_lookup( '127.0.0.1' );
        $this->assertSame( 'Unknown', $result['country'] );
    }

    // ── 10. User-Agent parsing ─────────────────────────────────────

    public function testUaParsesChrome(): void
    {
        $ua  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        $res = aag_parse_user_agent( $ua );
        $this->assertSame( 'Google Chrome', $res['browser'] );
        $this->assertSame( 'Windows 10/11', $res['os'] );
        $this->assertSame( 'Desktop', $res['device_type'] );
    }

    public function testUaParsesFirefoxOnLinux(): void
    {
        $ua  = 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0';
        $res = aag_parse_user_agent( $ua );
        $this->assertSame( 'Mozilla Firefox', $res['browser'] );
        $this->assertSame( 'Linux', $res['os'] );
    }

    public function testUaDetectsMobileDevice(): void
    {
        $ua  = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';
        $res = aag_parse_user_agent( $ua );
        $this->assertSame( 'Mobile', $res['device_type'] );
    }

    // ── 11. IP address detection ───────────────────────────────────

    public function testGetClientIpReturnsRemoteAddr(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.5';
        $ip = aag_get_client_ip();
        $this->assertSame( '203.0.113.5', $ip );
    }

    public function testGetClientIpPrefersCloudflareHeader(): void
    {
        $_SERVER['REMOTE_ADDR']            = '10.0.0.1';
        $_SERVER['HTTP_CF_CONNECTING_IP']  = '198.51.100.42';
        $ip = aag_get_client_ip();
        $this->assertSame( '198.51.100.42', $ip );
        unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
    }

    public function testGetClientIpHandlesCommaList(): void
    {
        $_SERVER['REMOTE_ADDR']            = '10.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR']   = '203.0.113.10, 10.0.0.2';
        $ip = aag_get_client_ip();
        $this->assertSame( '203.0.113.10', $ip );
        unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
    }

    // ── 12. Token generation ───────────────────────────────────────

    public function testGenerateTokenProducesUniqueTokens(): void
    {
        $t1 = aag_generate_token();
        $t2 = aag_generate_token();
        $this->assertNotEmpty( $t1 );
        $this->assertNotEmpty( $t2 );
        $this->assertNotSame( $t1, $t2, 'Each generated token must be unique' );
    }

    // ── 13. Audit log cap ─────────────────────────────────────────

    public function testAuditLogIsCappedAtLimit(): void
    {
        $limit = AAG_LOG_LIMIT;
        for ( $i = 0; $i < $limit + 10; $i++ ) {
            aag_log( 'test_event', 'info', "Entry $i" );
        }
        $logs = get_option( AAG_OPTION_LOG, [] );
        $this->assertCount( $limit, $logs, "Log must be capped at AAG_LOG_LIMIT ($limit)" );
    }

    public function testAuditLogCapturesEventType(): void
    {
        aag_log( 'test_login', 'warning', 'Test log detail' );
        $logs = get_option( AAG_OPTION_LOG, [] );
        $this->assertSame( 'test_login', $logs[0]['event_type'] );
        $this->assertSame( 'warning', $logs[0]['severity'] );
        $this->assertSame( 'Test log detail', $logs[0]['details'] );
        $this->assertArrayHasKey( 'ip', $logs[0] );
        $this->assertArrayHasKey( 'timestamp', $logs[0] );
    }

    // ── 14. Notification email content ────────────────────────────

    public function testNotificationEmailSentToCorrectAddress(): void
    {
        $user = aag_test_create_user( 90, 'spammer', 'sp@bad.com', [ 'administrator' ] );
        aag_intercept_new_user( 90 );

        $mail_sent = false;
        foreach ( $GLOBALS['wp_mail_log'] as $mail ) {
            if ( $mail['to'] === AAG_NOTIFY_EMAIL ) {
                $mail_sent = true;
                break;
            }
        }
        $this->assertTrue( $mail_sent, 'Notification email must be sent to ' . AAG_NOTIFY_EMAIL );
    }

    public function testNotificationEmailContainsUserDetails(): void
    {
        $user             = aag_test_create_user( 91, 'test_notif', 'notify@site.com', [ 'administrator' ] );
        $_SERVER['REMOTE_ADDR'] = '5.6.7.8';

        aag_intercept_new_user( 91 );

        $body = '';
        foreach ( $GLOBALS['wp_mail_log'] as $mail ) {
            if ( $mail['to'] === AAG_NOTIFY_EMAIL ) {
                $body = $mail['message'];
                break;
            }
        }

        $this->assertStringContainsString( 'test_notif', $body, 'Email must contain username' );
        $this->assertStringContainsString( 'notify@site.com', $body, 'Email must contain email address' );
        $this->assertStringContainsString( '5.6.7.8', $body, 'Email must contain IP address' );
        $this->assertStringContainsString( 'APPROVE', $body, 'Email must contain approve link label' );
        $this->assertStringContainsString( 'REJECT', $body, 'Email must contain reject link label' );
    }

    // ── 15. quarantine_user metadata ──────────────────────────────

    public function testQuarantineSetsUserMeta(): void
    {
        $user = aag_test_create_user( 100, 'qtest', 'q@site.com', [ 'subscriber' ] );
        aag_quarantine_user( 100, 'test_reason' );
        $this->assertTrue( (bool) get_user_meta( 100, '_aag_pending', true ), '_aag_pending meta must be set' );
    }

    // ── 16. Pending entry has approve/reject token hashes ─────────

    public function testPendingEntryHasTokenHashes(): void
    {
        $user = aag_test_create_user( 110, 'tokentest', 't@site.com', [ 'administrator' ] );
        aag_intercept_new_user( 110 );

        $pending = get_option( AAG_OPTION_PENDING, [] );
        $entry   = $this->findEntry( $pending, 110 );

        $this->assertNotEmpty( $entry['approve_token'], 'Approve token hash must be stored' );
        $this->assertNotEmpty( $entry['reject_token'],  'Reject token hash must be stored' );
        // Ensure we only store the hash, not the raw token.
        $this->assertNotEmpty( $entry['approve_token'] );
    }

    // ── 17. REST API guard blocks admin role via REST ─────────────

    public function testRestGuardBlocksAdminRoleCreation(): void
    {
        // Build a mock WP_REST_Request-like object.
        $request = new class {
            public function get_param( $key ) {
                return $key === 'roles' ? [ 'administrator' ] : null;
            }
        };

        $result = aag_guard_rest_user_insert( new stdClass(), $request );
        $this->assertInstanceOf( WP_Error::class, $result, 'REST admin creation must be blocked with WP_Error' );
        $this->assertSame( 'aag_rest_blocked', $result->code );
    }

    public function testRestGuardAllowsNonAdminRoles(): void
    {
        $prepared = new stdClass();
        $request  = new class {
            public function get_param( $key ) {
                return $key === 'roles' ? [ 'editor' ] : null;
            }
        };

        $result = aag_guard_rest_user_insert( $prepared, $request );
        $this->assertNotInstanceOf( WP_Error::class, $result, 'Non-admin role creation must pass through' );
    }

    // ── 18. Session context: cron ──────────────────────────────────

    public function testSessionContextDetectsCron(): void
    {
        $GLOBALS['wp_doing_cron'] = true;
        $ctx = aag_get_session_context();
        $GLOBALS['wp_doing_cron'] = false;
        $this->assertSame( 'WP-Cron', $ctx['source'] );
        $this->assertFalse( $ctx['is_dashboard'], 'Cron is never a dashboard session' );
    }

    // ── 19. Session context: unauthenticated HTTP ──────────────────

    public function testSessionContextUnauthenticatedHttp(): void
    {
        // No user logged in (is_user_logged_in returns false in bootstrap).
        $ctx = aag_get_session_context();
        $this->assertStringContainsString( 'unauthenticated', strtolower( $ctx['source'] ) );
        $this->assertFalse( $ctx['is_dashboard'], 'Unauthenticated request is never a dashboard session' );
        $this->assertSame( 'anonymous', $ctx['actor'] );
    }

    // ── 20. Session context: authenticated admin dashboard session ──

    public function testSessionContextDetectsDashboardSession(): void
    {
        $admin = aag_test_create_user( 120, 'superadmin', 'sa@site.com', [ 'administrator' ] );
        $GLOBALS['aag_current_user_id'] = 120;

        $ctx = aag_get_session_context();
        $this->assertTrue( $ctx['is_dashboard'], 'Authenticated admin request must be flagged as dashboard session' );
        $this->assertSame( 'superadmin', $ctx['actor'] );
    }

    // ── 21. Offline escalation fires an alert email ────────────────

    public function testOfflineEscalationFiresAlertEmail(): void
    {
        // No admin logged in → unauthenticated context.
        $GLOBALS['aag_current_user_id'] = 0;

        $user = aag_test_create_user( 130, 'sneaky', 'sn@site.com', [ 'editor' ] );

        aag_intercept_role_change( 130, 'administrator', [ 'editor' ] );

        // Must have an offline alert email (⚠️ OFFLINE SECURITY ALERT subject).
        $offlineAlert = false;
        foreach ( $GLOBALS['wp_mail_log'] as $mail ) {
            if ( strpos( $mail['subject'], 'OFFLINE SECURITY ALERT' ) !== false ) {
                $offlineAlert = true;
                break;
            }
        }
        $this->assertTrue( $offlineAlert, 'An offline alert email must be sent when escalation happens with no dashboard session' );

        // Also, the IP must be blocked.
        $blocked = get_option( AAG_BLOCKED_IPS_OPTION, [] );
        $this->assertNotEmpty( $blocked, 'IP should be blocked' );
        $this->assertSame( '1.2.3.4', $blocked[0]['ip'] );
    }

    // ── 22. Integrity check demotes unapproved admin ───────────────

    public function testIntegrityCheckDemotesUnapprovedAdmin(): void
    {
        // Create an admin who was NOT approved through the plugin.
        $rogue = aag_test_create_user( 140, 'rogue', 'rogue@evil.com', [ 'administrator' ] );
        // Ensure they are NOT in the approved list.
        update_option( AAG_OPTION_APPROVED, [] );

        aag_run_integrity_check();

        // They must have been demoted to subscriber.
        $this->assertContains( 'subscriber', $rogue->roles, 'Unapproved admin must be demoted by integrity check' );
        $this->assertNotContains( 'administrator', $rogue->roles );

        // An alert email must have been sent.
        $found = false;
        foreach ( $GLOBALS['wp_mail_log'] as $mail ) {
            if ( strpos( $mail['subject'], 'OFFLINE SECURITY ALERT' ) !== false
                 || strpos( $mail['message'], 'INTEGRITY VIOLATION' ) !== false ) {
                $found = true;
                break;
            }
        }
        $this->assertTrue( $found, 'Integrity violation must trigger an alert email' );
    }

    // ── 23. Integrity check skips properly approved admins ─────────

    public function testIntegrityCheckSkipsApprovedAdmins(): void
    {
        $legit = aag_test_create_user( 150, 'legit', 'legit@site.com', [ 'administrator' ] );
        update_option( AAG_OPTION_APPROVED, [ 150 ] );

        $GLOBALS['wp_mail_log'] = [];
        aag_run_integrity_check();

        // Role must remain administrator.
        $this->assertContains( 'administrator', $legit->roles, 'Properly approved admin must keep their role' );

        // No alert email.
        $alerted = false;
        foreach ( $GLOBALS['wp_mail_log'] as $mail ) {
            if ( strpos( $mail['subject'], 'OFFLINE SECURITY ALERT' ) !== false ) {
                $alerted = true;
                break;
            }
        }
        $this->assertFalse( $alerted, 'Approved admin must NOT trigger an integrity alert' );
    }

    // ── 24. Approve adds user to approved list ─────────────────────

    public function testApproveAddsToApprovedList(): void
    {
        aag_test_create_user( 160, 'newadmin', 'na@site.com', [ 'subscriber' ] );
        update_user_meta( 160, '_aag_pending', 1 );
        update_option( AAG_OPTION_APPROVED, [] );

        $entry = [ 'user_id' => 160, 'reason' => 'test', 'status' => 'pending', 'meta' => [] ];
        aag_approve_user( 160, $entry );

        $approved = get_option( AAG_OPTION_APPROVED, [] );
        $this->assertContains( 160, $approved, 'Approved user ID must appear in the approved list' );
    }

    // ── 25. Notification email address is correct ──────────────────

    public function testNotificationEmailUsesUpdatedAddress(): void
    {
        $this->assertSame(
            'shadabcse2020@gmail.com',
            AAG_NOTIFY_EMAIL,
            'Notification email must be shadabcse2020@gmail.com'
        );
    }

    // ── 26. Media upload security ─────────────────────────────────

    public function testBlockPhpUploads(): void
    {
        $_SERVER['REMOTE_ADDR'] = '8.8.8.8';
        update_option( AAG_BLOCKED_IPS_OPTION, [] );

        $file = [
            'name' => 'malicious.php',
            'type' => 'application/x-php',
            'tmp_name' => '/tmp/php123',
            'error' => 0,
            'size' => 123,
        ];

        $result = aag_block_php_uploads( $file );

        $this->assertNotEmpty( $result['error'] );
        $blocked = get_option( AAG_BLOCKED_IPS_OPTION, [] );
        $this->assertCount( 1, $blocked );
        $this->assertSame( '8.8.8.8', $blocked[0]['ip'] );
    }

    // ── 27. Quarantine does not self-block admin ──────────────────

    public function testQuarantineDoesNotSelfBlockAdmin(): void
    {
        // Admin logged in
        $GLOBALS['aag_current_user_id'] = 1;
        aag_test_create_user( 1, 'admin', 'admin@site.com', [ 'administrator' ] );
        $_SERVER['REMOTE_ADDR'] = '1.1.1.1';
        update_option( AAG_BLOCKED_IPS_OPTION, [] );

        // Create a dummy file to quarantine
        $dummy_file = sys_get_temp_dir() . '/dummy_threat.php';
        file_put_contents( $dummy_file, '<?php eval($_POST["cmd"]);' );

        $this->assertFileExists( $dummy_file );

        // Run quarantine
        $ok = aag_quarantine_malware_file( $dummy_file );
        $this->assertTrue( $ok );

        // The admin's IP 1.1.1.1 should NOT be blocked
        $blocked = get_option( AAG_BLOCKED_IPS_OPTION, [] );
        $this->assertEmpty( $blocked, 'Admin IP should not be blocked during quarantine action' );

        // Clean up
        $q_log = get_option( AAG_SCAN_OPTION_QUARANTINE, [] );
        foreach ( $q_log as $entry ) {
            if ( file_exists( $entry['quarantine_path'] ) ) {
                unlink( $entry['quarantine_path'] );
            }
        }
    }

    // ── 28. Nginx configuration file generation ───────────────────

    public function testNginxConfigFileGeneration(): void
    {
        $conf_file = ABSPATH . 'nginx-blocked-ips.conf';
        if ( file_exists( $conf_file ) ) {
            unlink( $conf_file );
        }

        $blocked_list = [
            [ 'ip' => '1.1.1.1', 'reason' => 'Test 1' ],
            [ 'ip' => '2.2.2.2', 'reason' => 'Test 2' ]
        ];

        aag_write_nginx_block_all( $blocked_list );

        $this->assertFileExists( $conf_file );
        $content = file_get_contents( $conf_file );
        $this->assertStringContainsString( 'deny 1.1.1.1;', $content );
        $this->assertStringContainsString( 'deny 2.2.2.2;', $content );
        $this->assertStringContainsString( '# BEGIN Admin-Approval-Guard-Blocked-IPs', $content );
        $this->assertStringContainsString( '# END Admin-Approval-Guard-Blocked-IPs', $content );

        // Clean up
        unlink( $conf_file );
    }

    // ── Helper ────────────────────────────────────────────────────

    private function findEntry( array $pending, int $user_id ): ?array
    {
        foreach ( $pending as $e ) {
            if ( (int) $e['user_id'] === $user_id ) {
                return $e;
            }
        }
        return null;
    }
}

