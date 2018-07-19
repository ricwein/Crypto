<?php declare(strict_types = 1);

namespace ricwein\Crypto\Tests\Symmetric;

use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Symmetric\Crypto;

/**
 * test symmetric message en/decryption
 */
class EncryptionTest extends TestCase
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
    public function testEncryption()
    {
        $message = $this->getMessage();
        $key = (new Key())->keygen();

        // encrypt
        $ciphertext = (new Crypto($key))->encrypt($message)->getString(Encoding::RAW);

        // decrypt
        $plaintext = (new Crypto($key))->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW));
        $this->assertSame($plaintext, $message);
    }
}
