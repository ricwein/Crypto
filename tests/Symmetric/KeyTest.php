<?php declare(strict_types=1);

namespace ricwein\Crypto\Tests\Symmetric;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Exceptions\CannotAccessHiddenException;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Symmetric\Key;
use SodiumException;

/**
 * test symmetric key generation and usage
 */
class KeyTest extends TestCase
{
    /**
     * @return void
     * @throws SodiumException
     * @throws EncodingException
     * @throws InvalidArgumentException
     */
    public function testKeyGeneration(): void
    {
        $key = Key::generate();
        self::assertSame(mb_strlen($key->getKey(), '8bit'), SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }


    /**
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public function testHiddenKey(): void
    {
        $keypair = Key::generate();
        $this->expectOutputString('');
        echo $keypair;
    }

    /**
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public function testCloneKey(): void
    {
        $keypair = Key::generate();
        $this->expectException(CannotAccessHiddenException::class);
        $_ = clone $keypair;
    }

    /**
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public function testSerializeKey(): void
    {
        $keypair = Key::generate();
        $this->expectException(CannotAccessHiddenException::class);
        $_ = serialize($keypair);
    }

    /**
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public function testKeyLoading(): void
    {
        $keyA = Key::generate();

        $keyB = Key::load($keyA);
        $keyC = Key::load($keyA->getKey(Encoding::BASE64URLSAFE), Encoding::BASE64URLSAFE);
        self::assertSame($keyA->getKey(), $keyB->getKey());
        self::assertSame($keyA->getKey(), $keyC->getKey());
    }

    /**
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public function testFingerprinting(): void
    {
        $keyA = Key::generate();

        $keyB = Key::load($keyA);
        $keyC = Key::load($keyA->getKey(Encoding::BASE64URLSAFE), Encoding::BASE64URLSAFE);
        self::assertSame($keyA->fingerprint(), $keyB->fingerprint());
        self::assertSame($keyA->fingerprint(), $keyC->fingerprint());
    }

    /**
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function testHKDFSplitting(): void
    {
        $keyA = Key::generate();
        [$encKeyA, $authKeyA] = $keyA->hkdfSplit();

        $keyB = Key::load($keyA);
        [$encKeyB, $authKeyB] = $keyB->hkdfSplit();

        self::assertSame($encKeyA, $encKeyB);
        self::assertSame($authKeyA, $authKeyB);
    }

    /**
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testSaltedHKDFSplitting(): void
    {
        $salt = random_bytes(SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

        $keyA = Key::generate();
        [$encKeyA, $authKeyA] = $keyA->hkdfSplit($salt);

        $keyB = Key::load($keyA);
        [$encKeyB, $authKeyB] = $keyB->hkdfSplit($salt);

        self::assertSame($encKeyA, $encKeyB);
        self::assertSame($authKeyA, $authKeyB);
    }

    /**
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws Exception
     */
    public function testKeyPasswordDerivation(): void
    {
        $password = 'test-passwd';
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

        $keyA = Key::generateFrom($password, $salt);
        $keyB = Key::generateFrom($password, $salt);

        self::assertSame($keyA->getKey(), $keyB->getKey());
    }
}
