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
        $key = (new Key)->keygen();

        // encrypt
        $cipherFile = (new Crypto($key))->encryptFile($sourceFile, $destinationCipher);

        $this->assertSame($destinationCipher->path()->real, $cipherFile->path()->real);
        $this->assertNotSame($sourceFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($key))->decryptFile($cipherFile, $destinationPlain);

        $this->assertSame($destinationPlain->path()->real, $plainFile->path()->real);
        $this->assertSame($sourceFile->read(), $plainFile->read());
    }

    /**
     * @return void
     */
    public function testSelfEncryption()
    {
        $sourceFile = $this->getSourceFile();
        $key = (new Key)->keygen();

        $comparePath = $sourceFile->path()->real;
        $compareFile = $sourceFile->copyTo(new Storage\Disk\Temp);

        // encrypt
        $cipherFile = (new Crypto($key))->encryptFile($sourceFile);

        $this->assertSame($comparePath, $cipherFile->path()->real);
        $this->assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($key))->decryptFile($cipherFile);

        $this->assertSame($comparePath, $plainFile->path()->real);
        $this->assertSame($plainFile->read(), $compareFile->read());
    }
}
