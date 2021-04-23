<?php declare(strict_types=1);

namespace ricwein\Crypto\Tests\Asymmetric\File;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\FileSystem\Exceptions\AccessDeniedException;
use ricwein\FileSystem\Exceptions\ConstraintsException;
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
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws UnexpectedValueException
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws FileSystemException
     * @throws FileNotFoundException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws FileSystemUnsupportedException
     * @throws Exception
     */
    public function testMemoryToDisk(): void
    {
        $keypairA = KeyPair::generate();
        $keypairB = KeyPair::generate();

        $message = $this->getMessage();

        $source = (new File(new Storage\Memory))->write($message);
        $cipher = (new Crypto($keypairA))->encryptFile($source, new Storage\Disk\Temp, $keypairB);

        self::assertInstanceOf(Storage\Disk\Temp::class, $cipher->storage());

        $plainA = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Memory, $keypairA);
        $plainB = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Disk\Temp, $keypairA);

        self::assertSame($message, $plainA->read());
        self::assertSame($message, $plainB->read());
    }


    /**
     * @return void
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws FileNotFoundException
     * @throws FileSystemException
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
        $keypairA = KeyPair::generate();
        $keypairB = KeyPair::generate();

        $message = $this->getMessage();

        $source = (new File(new Storage\Disk\Temp))->write($message);
        $cipher = (new Crypto($keypairA))->encryptFile($source, new Storage\Memory, $keypairB);

        self::assertInstanceOf(Storage\Memory::class, $cipher->storage());

        $plainA = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Memory, $keypairA);
        $plainB = (new Crypto($keypairB))->decryptFile($cipher, new Storage\Disk\Temp, $keypairA);

        self::assertSame($message, $plainA->read());
        self::assertSame($message, $plainB->read());
    }
}
