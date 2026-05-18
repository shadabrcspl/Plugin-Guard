<?php
use PHPUnit\Framework\TestCase;

class CoreScannerTest extends TestCase
{
    public function testScanAndRepairFunctionsExist()
    {
        $this->assertTrue(function_exists('psc_run_core_checksum_scan'));
        $this->assertTrue(function_exists('psc_repair_core_files'));
    }
}
