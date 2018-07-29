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

        $keypairA = (new KeyPair)->keygen();
        $keypairB = (new KeyPair)->keygen();

        // encrypt
        $cipherFile = (new Crypto($keypairA))->encryptFile($sourceFile, $destinationCipher, $keypairB);

        $this->assertNotSame($sourceFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypairB))->decryptFile($cipherFile, $destinationPlain, $keypairA);

        $this->assertSame($sourceFile->read(), $plainFile->read());
    }

    /**
     * @return void
     */
    public function testSelfEncryption()
    {
        $sourceFile = $this->getSourceFile();

        $keypairA = (new KeyPair)->keygen();
        $keypairB = (new KeyPair)->keygen();

        $compareFile = $sourceFile->copyTo(new Storage\Memory);

        // encrypt
        $cipherFile = (new Crypto($keypairA))->encryptFile($sourceFile, null, $keypairB);

        $this->assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypairB))->decryptFile($cipherFile, null, $keypairA);

        $this->assertSame($plainFile->read(), $compareFile->read());
    }
}
