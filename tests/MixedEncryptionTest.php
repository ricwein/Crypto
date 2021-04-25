<?php

namespace ricwein\Crypto\Tests;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\Crypto as AsymmetricCrypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Symmetric\Key;
use SodiumException;

class MixedEncryptionTest extends TestCase
{
    /**
     * @throws SodiumException
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws KeyMismatchException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testMixedCrypto(): void
    {
        // use as symmetric key, as an asymmetric keypairs private key
        $secret = Key::generate();
        $keypair = $secret->asKeypair();
        $message = bin2hex(random_bytes(2 << 10));

        // public-key only crypto
        $cryptoA = new AsymmetricCrypto(KeyPair::load([KeyPair::PUB_KEY => $keypair->getKey(KeyPair::PUB_KEY)]));

        // private-key crypto
        $cryptoB = new AsymmetricCrypto($keypair);

        $ciphertext = $cryptoA->seal($message);
        $ciphertext2 = $cryptoB->seal($message);

        $plaintext = $cryptoB->unseal($ciphertext);
        $plaintext2 = $cryptoB->unseal($ciphertext2);

        self::assertNotSame($message, $ciphertext);
        self::assertSame($message, $plaintext);
        self::assertSame($message, $plaintext2);
    }

}
