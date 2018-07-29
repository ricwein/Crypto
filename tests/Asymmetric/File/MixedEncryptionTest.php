<?php declare(strict_types = 1);

namespace ricwein\Crypto\Tests\Asymmetric\File;

use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Asymmetric\Crypto;
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
        $keypairA = (new KeyPair)->keygen();
        $keypairB = (new KeyPair)->keygen();

        $message = $this->getMessage();

        $source = (new File(new Storage\Memory))->write($message);
        $cipher = (new Crypto($keypairA))->encryptFile($source, new Storage\Disk\Temp, $keypairB);

        $this->assertInstanceOf(Storage\Disk\Temp::class, $cipher->storage());

        $plainA = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Memory, $keypairA);
        $plainB = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Disk\Temp, $keypairA);

        $this->assertSame($message, $plainA->read());
        $this->assertSame($message, $plainB->read());
    }


    /**
     * @return void
     */
    public function testDiskToMemory()
    {
        $keypairA = (new KeyPair)->keygen();
        $keypairB = (new KeyPair)->keygen();

        $message = $this->getMessage();

        $source = (new File(new Storage\Disk\Temp))->write($message);
        $cipher = (new Crypto($keypairA))->encryptFile($source, new Storage\Memory, $keypairB);

        $this->assertInstanceOf(Storage\Memory::class, $cipher->storage());

        $plainA = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Memory, $keypairA);
        $plainB = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Disk\Temp, $keypairA);

        $this->assertSame($message, $plainA->read());
        $this->assertSame($message, $plainB->read());
    }
}
