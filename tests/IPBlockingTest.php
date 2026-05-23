<?php
use PHPUnit\Framework\TestCase;

class IPBlockingTest extends TestCase
{
    protected function setUp(): void
    {
        global $wp_options;
        $wp_options = [];
        delete_option('psc_blocked_ips');
    }

    public function testBlockAndUnblockIP()
    {
        $ip = '10.0.0.1';
        $remark = 'Test remark';

        psc_block_ip($ip, $remark);
        $blocked = get_option('psc_blocked_ips', []);

        $this->assertArrayHasKey($ip, $blocked);
        $this->assertEquals($remark, $blocked[$ip]['remark']);

        psc_unblock_ip($ip);
        $blocked = get_option('psc_blocked_ips', []);

        $this->assertArrayNotHasKey($ip, $blocked);
    }
}
