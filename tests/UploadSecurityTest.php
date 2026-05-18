<?php
use PHPUnit\Framework\TestCase;

class UploadSecurityTest extends TestCase
{
    protected function setUp(): void
    {
        $upload_dir = wp_upload_dir();
        if (!is_dir($upload_dir['basedir'])) {
            mkdir($upload_dir['basedir'], 0777, true);
        }
    }

    public function testSecureUploadsDirectory()
    {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

        if (file_exists($htaccess_file)) {
            unlink($htaccess_file);
        }

        secure_uploads_directory();

        $this->assertFileExists($htaccess_file);
        $content = file_get_contents($htaccess_file);
        $this->assertStringContainsString('<Files *.php>', $content);
        $this->assertStringContainsString('Deny from all', $content);
    }

    public function testRemoveSecureUploadsDirectory()
    {
        $upload_dir = wp_upload_dir();
        $htaccess_file = $upload_dir['basedir'] . '/.htaccess';

        // Ensure it's there
        secure_uploads_directory();
        $this->assertFileExists($htaccess_file);

        // Remove it
        remove_secure_uploads_directory();

        $this->assertFileDoesNotExist($htaccess_file);
    }
}
