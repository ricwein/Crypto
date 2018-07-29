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
class MemoryEncryptionTest extends TestCase
{
    /**
     * @return File
     */
    protected function getSourceFile(): File
    {
        $message = base64_encode(random_bytes(random_int(2 << 9, 2 << 10)));
        $file = new File(new Storage\Memory);
        $file->write($message);
        return $file;
    }

    /**
     * @return void
     */
    public function testEncryption()
    {
        $sourceFile = $this->getSourceFile();
        $destinationCipher = new Storage\Memory;
        $destinationPlain = new Storage\Memory;
        $key = (new Key)->keygen();

        // encrypt
        $cipherFile = (new Crypto($key))->encryptFile($sourceFile, $destinationCipher);

        $this->assertNotSame($sourceFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($key))->decryptFile($cipherFile, $destinationPlain);

        $this->assertSame($sourceFile->read(), $plainFile->read());
    }

    /**
     * @return void
     */
    public function testSelfEncryption()
    {
        $sourceFile = $this->getSourceFile();
        $key = (new Key)->keygen();

        $compareFile = $sourceFile->copyTo(new Storage\Memory);

        // encrypt
        $cipherFile = (new Crypto($key))->encryptFile($sourceFile);

        $this->assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($key))->decryptFile($cipherFile);

        $this->assertSame($plainFile->read(), $compareFile->read());
    }
}
