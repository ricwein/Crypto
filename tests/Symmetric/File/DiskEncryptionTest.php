<?php declare(strict_types=1);

namespace ricwein\Crypto\Tests\Symmetric\File;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\FileSystem\Exceptions\AccessDeniedException as FileSystemAccessDeniedException;
use ricwein\FileSystem\Exceptions\ConstraintsException as FileSystemConstraintsException;
use ricwein\FileSystem\Exceptions\Exception as FileSystemException;
use ricwein\FileSystem\Exceptions\FileNotFoundException;
use ricwein\FileSystem\Exceptions\RuntimeException as FileSystemRuntimeException;
use ricwein\FileSystem\Exceptions\UnexpectedValueException as FileSystemUnexpectedValueException;
use ricwein\FileSystem\Exceptions\UnsupportedException as FileSystemUnsupportedException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;
use SodiumException;

/**
 * test symmetric message en/decryption
 */
class DiskEncryptionTest extends TestCase
{
    /**
     * @return File
     * @throws FileSystemAccessDeniedException
     * @throws FileSystemConstraintsException
     * @throws FileSystemException
     * @throws Exception
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
     * @throws FileSystemAccessDeniedException
     * @throws FileSystemConstraintsException
     * @throws FileSystemException
     * @throws SodiumException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws UnexpectedValueException
     * @throws FileNotFoundException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws FileSystemUnsupportedException
     */
    public function testEncryption(): void
    {
        $sourceFile = $this->getSourceFile();
        $destinationCipher = new Storage\Disk\Temp;
        $destinationPlain = new Storage\Disk\Temp;
        $key = Key::generate();

        // encrypt
        $cipherFile = (new Crypto($key))->encryptFile($sourceFile, $destinationCipher);

        self::assertSame($destinationCipher->path()->real, $cipherFile->path()->real);
        self::assertNotSame($sourceFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($key))->decryptFile($cipherFile, $destinationPlain);

        self::assertSame($destinationPlain->path()->real, $plainFile->path()->real);
        self::assertSame($sourceFile->read(), $plainFile->read());
    }

    /**
     * @return void
     * @throws FileNotFoundException
     * @throws FileSystemAccessDeniedException
     * @throws FileSystemConstraintsException
     * @throws FileSystemException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws FileSystemUnsupportedException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function testSelfEncryption(): void
    {
        $sourceFile = $this->getSourceFile();
        $key = Key::generate();

        $comparePath = $sourceFile->path()->real;
        $compareFile = $sourceFile->copyTo(new Storage\Disk\Temp);

        // encrypt
        $cipherFile = (new Crypto($key))->encryptFile($sourceFile);

        self::assertSame($comparePath, $cipherFile->path()->real);
        self::assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($key))->decryptFile($cipherFile);

        self::assertSame($comparePath, $plainFile->path()->real);
        self::assertSame($plainFile->read(), $compareFile->read());
    }
}
