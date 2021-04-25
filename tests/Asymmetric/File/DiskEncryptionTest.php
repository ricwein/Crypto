<?php declare(strict_types=1);

namespace ricwein\Crypto\Tests\Asymmetric\File;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\Crypto\Exceptions\RuntimeException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
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
     * @throws EncodingException
     * @throws FileNotFoundException
     * @throws FileSystemAccessDeniedException
     * @throws FileSystemConstraintsException
     * @throws FileSystemException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws FileSystemUnsupportedException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function testEncryption(): void
    {
        $sourceFile = $this->getSourceFile();
        $destinationCipher = new Storage\Disk\Temp;
        $destinationPlain = new Storage\Disk\Temp;

        $keypairA = KeyPair::generate();
        $keypairB = KeyPair::generate();

        // encrypt
        $cipherFile = (new Crypto($keypairA))->encryptFile($sourceFile, $destinationCipher, $keypairB);

        self::assertSame($destinationCipher->path()->real, $cipherFile->path()->real);
        self::assertNotSame($sourceFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypairB))->decryptFile($cipherFile, $destinationPlain, $keypairA);

        self::assertSame($destinationPlain->path()->real, $plainFile->path()->real);
        self::assertSame($sourceFile->read(), $plainFile->read());
    }

    /**
     * @return void
     * @throws EncodingException
     * @throws FileNotFoundException
     * @throws FileSystemAccessDeniedException
     * @throws FileSystemConstraintsException
     * @throws FileSystemException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws FileSystemUnsupportedException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function testSelfEncryption(): void
    {
        $sourceFile = $this->getSourceFile();

        $keypairA = KeyPair::generate();
        $keypairB = KeyPair::generate();

        $comparePath = $sourceFile->path()->real;
        $compareFile = $sourceFile->copyTo(new Storage\Disk\Temp);

        // encrypt
        $cipherFile = (new Crypto($keypairA))->encryptFile($sourceFile, null, $keypairB);

        self::assertSame($comparePath, $cipherFile->path()->real);
        self::assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypairB))->decryptFile($cipherFile, null, $keypairA);

        self::assertSame($comparePath, $plainFile->path()->real);
        self::assertSame($plainFile->read(), $compareFile->read());
    }

    /**
     * @throws EncodingException
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
    public function testSelfSealing(): void
    {
        $sourceFile = $this->getSourceFile();
        $keypair = KeyPair::generate();

        $compareFile = $sourceFile->copyTo(new Storage\Disk\Temp);

        // encrypt
        $cipherFile = (new Crypto($keypair->copyWithExclusive(KeyPair::PUB_KEY)))->sealFile($sourceFile);
        self::assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypair->copyWithExclusive(KeyPair::PRIV_KEY)))->unsealFile($cipherFile);
        self::assertSame($plainFile->read(), $compareFile->read());
    }

    /**
     * @throws EncodingException
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
     * @throws Exception
     */
    public function testMemoryFileSealing(): void
    {
        $message = base64_encode(random_bytes(random_int(2 << 9, 2 << 10)));
        $sourceFile = new File(new Storage\Memory($message));
        $keypair = KeyPair::generate();

        $compareFile = $sourceFile->copyTo(new Storage\Memory);

        // encrypt
        $cipherFile = (new Crypto($keypair->copyWithExclusive(KeyPair::PUB_KEY)))->sealFile($sourceFile);
        self::assertNotSame($compareFile->read(), $cipherFile->read());

        // decrypt
        $plainFile = (new Crypto($keypair->copyWithExclusive(KeyPair::PRIV_KEY)))->unsealFile($cipherFile);
        self::assertSame($plainFile->read(), $compareFile->read());
    }

    /**
     * @throws EncodingException
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
    public function testEmptyDecrypt(): void
    {
        $cipherFile = new File(new Storage\Memory);
        $crypto = new Crypto(KeyPair::generate());

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Input file is too small\. Expected at least.+/');
        $crypto->decryptFile($cipherFile);
    }
}
