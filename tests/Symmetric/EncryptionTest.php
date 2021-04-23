<?php declare(strict_types=1);

namespace ricwein\Crypto\Tests\Symmetric;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\Crypto\Exceptions\RuntimeException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Symmetric\Crypto;
use SodiumException;

/**
 * test symmetric message en/decryption
 */
class EncryptionTest extends TestCase
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
     * @throws KeyMismatchException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testEncryption(): void
    {
        $message = $this->getMessage();
        $key = Key::generate();

        // encrypt
        $ciphertext = (new Crypto($key))->encrypt($message)->getString(Encoding::RAW);

        // decrypt
        $plaintext = (new Crypto($key))->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW));
        self::assertSame($plaintext, $message);
    }
}
