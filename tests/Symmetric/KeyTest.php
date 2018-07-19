<?php declare(strict_types = 1);

namespace ricwein\Crypto\Tests\Symmetric;

use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Symmetric\Key;

/**
* test symmetric key generation and usage
 */
class KeyTest extends TestCase
{
    /**
     * @return void
     */
    public function testKeyGeneration()
    {
        $key = new Key();
        $this->assertNull($key->getKey());

        $key->keygen();
        $this->assertSame(mb_strlen($key->getKey(), '8bit'), \SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    /**
     * @return void
     */
    public function testKeyLoading()
    {
        $keyA = (new Key())->keygen();

        $keyB = new Key($keyA->getKey());
        $keyC = new Key($keyA->getKey(Encoding::BASE64URLSAFE), Encoding::BASE64URLSAFE);
        $this->assertSame($keyA->getKey(), $keyB->getKey());
        $this->assertSame($keyA->getKey(), $keyC->getKey());
    }

    /**
     * @return void
     */
    public function testFingerprinting()
    {
        $keyA = (new Key())->keygen();

        $keyB = new Key($keyA->getKey());
        $keyC = new Key($keyA->getKey(Encoding::BASE64URLSAFE), Encoding::BASE64URLSAFE);
        $this->assertSame($keyA->fingerprint(), $keyB->fingerprint());
        $this->assertSame($keyA->fingerprint(), $keyC->fingerprint());
    }

    /**
     * @return void
     */
    public function testHKDFSplitting()
    {
        $keyA = (new Key())->keygen();
        list($encKeyA, $authKeyA) = $keyA->hkdfSplit();

        $keyB = (new Key())->load($keyA->getKey());
        list($encKeyB, $authKeyB) = $keyA->hkdfSplit();

        $this->assertSame($encKeyA, $encKeyB);
        $this->assertSame($authKeyA, $authKeyB);
    }

    /**
     * @return void
     */
    public function testSaltedHKDFSplitting()
    {
        $salt = random_bytes(\SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

        $keyA = (new Key())->keygen();
        list($encKeyA, $authKeyA) = $keyA->hkdfSplit($salt);

        $keyB = (new Key())->load($keyA->getKey());
        list($encKeyB, $authKeyB) = $keyA->hkdfSplit($salt);

        $this->assertSame($encKeyA, $encKeyB);
        $this->assertSame($authKeyA, $authKeyB);
    }
}
