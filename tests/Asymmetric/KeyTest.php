<?php declare(strict_types=1);

namespace ricwein\Crypto\Tests\Asymmetric;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use SodiumException;

/**
 * test keypair generation and usage
 */
class KeyTest extends TestCase
{
    /**
     * @return void
     * @throws SodiumException
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     */
    public function testKeyGeneration(): void
    {
        $keypair = KeyPair::generate();
        self::assertSame(mb_strlen($keypair->getKey(KeyPair::PUB_KEY), '8bit'), SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
        self::assertSame(mb_strlen($keypair->getKey(KeyPair::PRIV_KEY), '8bit'), SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
    }

    /**
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testKeyDerivation(): void
    {
        $keyAlice = KeyPair::generate();
        $keyBob = KeyPair::generate();

        $secretAlice = new KeyPair([KeyPair::PRIV_KEY => $keyAlice, KeyPair::PUB_KEY => $keyBob]);
        $secretBob = new KeyPair([KeyPair::PRIV_KEY => $keyBob, KeyPair::PUB_KEY => $keyAlice]);

        self::assertSame($secretAlice->getSharedSecret()->getKey(), $secretBob->getSharedSecret()->getKey());

        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

        [$authAlice, $encAlice] = $secretAlice->hkdfSplit($salt);
        [$authBob, $encBob] = $secretBob->hkdfSplit($salt);

        self::assertSame($authAlice, $authBob);
        self::assertSame($encAlice, $encBob);
    }

    /**
     * test asymmetric key derivation from password/salt
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testKeyPasswortDerivation(): void
    {
        $passwort = random_bytes(random_int(2 << 9, 2 << 10));
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

        $keyA = KeyPair::generateFrom($passwort, $salt);
        $keyB = KeyPair::generateFrom($passwort, $salt);

        self::assertSame($keyA->getKey(KeyPair::PUB_KEY), $keyB->getKey(KeyPair::PUB_KEY));
        self::assertSame($keyA->getKey(KeyPair::PRIV_KEY), $keyB->getKey(KeyPair::PRIV_KEY));
        self::assertSame($keyA->getSharedSecret()->getKey(), $keyB->getSharedSecret()->getKey());
    }
}
