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
class DiskEncryptionTest extends TestCase
{
    /**
     * @return File
     */
    protected function getSourceFile(): File
    {
        $message = base64_encode(random_bytes(random_int(2 << 9, 2 << 10)));
        $file = new File(new Storage\Disk\Temp);
        $file->write($message);
        return $file;
    }

    /**
     * @return void
     */
    public function testEncryption()
    {
        $sourceFile = $this->getSourceFile();
        $destinationCipher = new Storage\Disk\Temp;
        $destinationPlain = new Storage\Disk\Temp;

        $keypairA = (new KeyPair)->keygen();
        $keypairB = (new KeyPair)->keygen();

        // encrypt
        $cipherFile = (new Crypto($keypairA))->encryptFile($sourceFile, $destinationCipher, $keypairB);

        $this->assertSame($destinationCipher->path()->real, $cipherFile->path()->real);
        $this->assertNotSame($sourceFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypairB))->decryptFile($cipherFile, $destinationPlain, $keypairA);

        $this->assertSame($destinationPlain->path()->real, $plainFile->path()->real);
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

        $comparePath = $sourceFile->path()->real;
        $compareFile = $sourceFile->copyTo(new Storage\Disk\Temp);

        // encrypt
        $cipherFile = (new Crypto($keypairA))->encryptFile($sourceFile, null, $keypairB);

        $this->assertSame($comparePath, $cipherFile->path()->real);
        $this->assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypairB))->decryptFile($cipherFile, null, $keypairA);

        $this->assertSame($comparePath, $plainFile->path()->real);
        $this->assertSame($plainFile->read(), $compareFile->read());
    }
}
