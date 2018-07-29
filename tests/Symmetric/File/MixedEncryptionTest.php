<?php declare(strict_types = 1);

namespace ricwein\Crypto\Tests\Symmetric\File;

use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;

/**
 * test symmetric message en/decryption
 */
class MixedEncryptionTest extends TestCase
{
    /**
     * @return string
     */
    protected function getMessage(): string
    {
        return base64_encode(random_bytes(random_int(2 << 9, 2 << 10)));
    }

    /**
     * @return void
     */
    public function testMemoryToDisk()
    {
        $key = (new Key)->keygen();
        $message = $this->getMessage();

        $source = (new File(new Storage\Memory))->write($message);
        $cipher = (new Crypto($key))->encryptFile($source, new Storage\Disk\Temp);

        $this->assertInstanceOf(Storage\Disk\Temp::class, $cipher->storage());

        $plainA = (new Crypto($key))->decryptFile($cipher, new Storage\Memory);
        $plainB = (new Crypto($key))->decryptFile($cipher, new Storage\Disk\Temp);

        $this->assertSame($message, $plainA->read());
        $this->assertSame($message, $plainB->read());
    }


    /**
     * @return void
     */
    public function testDiskToMemory()
    {
        $key = (new Key)->keygen();
        $message = $this->getMessage();

        $source = (new File(new Storage\Disk\Temp))->write($message);
        $cipher = (new Crypto($key))->encryptFile($source, new Storage\Memory);

        $this->assertInstanceOf(Storage\Memory::class, $cipher->storage());

        $plainA = (new Crypto($key))->decryptFile($cipher, new Storage\Memory);
        $plainB = (new Crypto($key))->decryptFile($cipher, new Storage\Disk\Temp);

        $this->assertSame($message, $plainA->read());
        $this->assertSame($message, $plainB->read());
    }
}
