<?php declare(strict_types = 1);

namespace ricwein\Crypto\Tests\Asymmetric;

use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\KeyPair;

/**
 * test keypair generation and usage
 */
class AsymmetricKeyTest extends TestCase
{
    /**
     * @return void
     */
    public function testKeyGeneration()
    {
        $keypair = new KeyPair;
        $this->assertNull($keypair->getKey(KeyPair::PUB_KEY));
        $this->assertNull($keypair->getKey(KeyPair::PRIV_KEY));

        $keypair->keygen();
        $this->assertSame(mb_strlen($keypair->getKey(KeyPair::PUB_KEY), '8bit'), \SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
        $this->assertSame(mb_strlen($keypair->getKey(KeyPair::PRIV_KEY), '8bit'), \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
    }

    /**
     * @return void
     */
    public function testKeyDerivation()
    {
        $keyAlice = (new KeyPair)->keygen();
        $keyBob = (new KeyPair)->keygen();

        $secretAlice = new KeyPair([KeyPair::PRIV_KEY => $keyAlice, KeyPair::PUB_KEY => $keyBob]);
        $secretBob = new KeyPair([KeyPair::PRIV_KEY => $keyBob, KeyPair::PUB_KEY => $keyAlice]);

        $this->assertSame($secretAlice->getSharedSecret()->getKey(), $secretBob->getSharedSecret()->getKey());

        $salt = \random_bytes(\SODIUM_CRYPTO_PWHASH_SALTBYTES);

        list($authAlice, $encAlice) = $secretAlice->hkdfSplit($salt);
        list($authBob, $encBob) = $secretBob->hkdfSplit($salt);

        $this->assertSame($authAlice, $authBob);
        $this->assertSame($encAlice, $encBob);
    }

    /**
     * test asymmetric key derivation from password/salt
     * @return void
     */
    public function testKeyPasswortDerivation()
    {
        $passwort = \random_bytes(random_int(2 << 9, 2 << 10));
        $salt = \random_bytes(\SODIUM_CRYPTO_PWHASH_SALTBYTES);

        $keyA = (new KeyPair)->keygen($passwort, $salt);
        $keyB = (new KeyPair)->keygen($passwort, $salt);

        $this->assertSame($keyA->getKey(KeyPair::PUB_KEY), $keyB->getKey(KeyPair::PUB_KEY));
        $this->assertSame($keyA->getKey(KeyPair::PRIV_KEY), $keyB->getKey(KeyPair::PRIV_KEY));
        $this->assertSame($keyA->getSharedSecret()->getKey(), $keyB->getSharedSecret()->getKey());
    }
}
