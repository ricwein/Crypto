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
use ricwein\FileSystem\Exceptions\FileNotFoundException as FileSystemFileNotFoundException;
use ricwein\FileSystem\Exceptions\RuntimeException as FileSystemRuntimeException;
use ricwein\FileSystem\Exceptions\UnexpectedValueException as FileSystemUnexpectedValueException;
use ricwein\FileSystem\Exceptions\UnsupportedException as FileSystemUnsupportedException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;
use SodiumException;

/**
 * test symmetric message en/decryption
 */
class MixedEncryptionTest extends TestCase
{
    /**
     * @return string
     * @throws Exception
     */
    protected function getMessage(): string
    {
        return base64_encode(random_bytes(random_int(2 << 9, 2 << 10)));
    }

    /**
     * @return void
     * @throws SodiumException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws UnexpectedValueException
     * @throws FileSystemAccessDeniedException
     * @throws FileSystemConstraintsException
     * @throws FileSystemException
     * @throws FileSystemFileNotFoundException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws FileSystemUnsupportedException
     * @throws Exception
     */
    public function testMemoryToDisk(): void
    {
        $key = Key::generate();
        $message = $this->getMessage();

        $source = (new File(new Storage\Memory))->write($message);
        $cipher = (new Crypto($key))->encryptFile($source, new Storage\Disk\Temp);

        self::assertInstanceOf(Storage\Disk\Temp::class, $cipher->storage());

        $plainA = (new Crypto($key))->decryptFile($cipher, new Storage\Memory);
        $plainB = (new Crypto($key))->decryptFile($cipher, new Storage\Disk\Temp);

        self::assertSame($message, $plainA->read());
        self::assertSame($message, $plainB->read());
    }


    /**
     * @return void
     * @throws FileSystemAccessDeniedException
     * @throws FileSystemConstraintsException
     * @throws FileSystemException
     * @throws FileSystemFileNotFoundException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws FileSystemUnsupportedException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testDiskToMemory(): void
    {
        $key = Key::generate();
        $message = $this->getMessage();

        $source = (new File(new Storage\Disk\Temp))->write($message);
        $cipher = (new Crypto($key))->encryptFile($source, new Storage\Memory);

        self::assertInstanceOf(Storage\Memory::class, $cipher->storage());

        $plainA = (new Crypto($key))->decryptFile($cipher, new Storage\Memory);
        $plainB = (new Crypto($key))->decryptFile($cipher, new Storage\Disk\Temp);

        self::assertSame($message, $plainA->read());
        self::assertSame($message, $plainB->read());
    }
}
