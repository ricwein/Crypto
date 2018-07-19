<?php declare(strict_types = 1);

namespace ricwein\Crypto\Tests\Asymmetric;

use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Encoding;

/**
* test asymmetric message en/decryption
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
     * test single-key encryption and decryption with random keypair
     * @return void
     */
    public function testCrypto()
    {
        $key = (new Crypto((new KeyPair())->keygen()));

        // encoded ciphertext
        $message = $this->getMessage();
        $ciphertext = $key->encrypt($message)->getString();
        $plaintext = $key->decrypt(Ciphertext::fromString($ciphertext));

        $this->assertSame($message, $plaintext);

        // raw binary ciphertext
        $message = $this->getMessage();
        $ciphertext = $key->encrypt($message)->getString(Encoding::RAW);
        $plaintext = $key->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW));

        $this->assertSame($message, $plaintext);
    }

    /**
     * test asymmetric authenticated encryption with two keypairs
     * @return void
     */
    public function testAsymmetricCrypto()
    {
        $clientKey = (new KeyPair())->keygen();
        $serverKey = (new KeyPair())->keygen();

        $clientCrypto = new Crypto($clientKey);
        $serverCrypto = new Crypto($serverKey);

        // request from client to server
        $message = $this->getMessage();
        $ciphertext = $clientCrypto->encrypt($message, $serverKey)->getString();
        $plaintext = $serverCrypto->decrypt(Ciphertext::fromString($ciphertext), $clientKey);

        $this->assertSame($message, $plaintext);

        // response from server to client
        $message = $this->getMessage();
        $ciphertext = $serverCrypto->encrypt($message, $clientKey)->getString();
        $plaintext = $clientCrypto->decrypt(Ciphertext::fromString($ciphertext), $serverKey);

        $this->assertSame($message, $plaintext);

        // request from client to server
        $message = $this->getMessage();
        $ciphertext = $clientCrypto->encrypt($message, $serverKey)->getString(Encoding::RAW);
        $plaintext = $serverCrypto->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW), $clientKey);

        $this->assertSame($message, $plaintext);

        // response from server to client
        $message = $this->getMessage();
        $ciphertext = $serverCrypto->encrypt($message, $clientKey)->getString(Encoding::RAW);
        $plaintext = $clientCrypto->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW), $serverKey);

        $this->assertSame($message, $plaintext);
    }

    /**
     * test asymmetric authenticated encryption with two keypairs
     * and a third MITM Key attack
     * @return void
     *
     * @expectedException ricwein\Crypto\Exceptions\MacMismatchException
     */
    public function testMITMSend()
    {
        $keyAlice = (new KeyPair())->keygen();
        $keyBob = (new KeyPair())->keygen();
        $keyEve = (new KeyPair())->keygen();

        $cryptoAlice = new Crypto($keyAlice);
        $cryptoEve = new Crypto($keyEve);

        // simulate MITM
        // Eve (send message) => Alice (awaits) from Bob
        $message = $this->getMessage();
        $ciphertext = $cryptoEve->encrypt($message, $keyAlice->getKey(KeyPair::PUB_KEY))->getString();
        $plaintext = $cryptoAlice->decrypt(Ciphertext::fromString($ciphertext), $keyBob);

        $this->assertNotSame($message, $plaintext);
    }

    /**
     * test asymmetric authenticated encryption with two keypairs
     * and a third MITM Key attack
     * @return void
     *
     * @expectedException ricwein\Crypto\Exceptions\MacMismatchException
     */
    public function testMITMReceive()
    {
        $keyAlice = (new KeyPair())->keygen();
        $keyBob = (new KeyPair())->keygen();
        $keyEve = (new KeyPair())->keygen();

        $cryptoAlice = new Crypto($keyAlice);
        $cryptoEve = new Crypto($keyEve);

        // simulate MITM
        // Alice (send message) => Bob, Eve intercepts
        $message = $this->getMessage();
        $ciphertext = $cryptoAlice->encrypt($message, $keyBob->getKey(KeyPair::PUB_KEY))->getString();
        $plaintext = $cryptoEve->decrypt(Ciphertext::fromString($ciphertext), $keyAlice);

        $this->assertNotSame($message, $plaintext);
    }

    /**
     * test asymmetric key exchange and priv-key => pub-key derivation
     * @return void
     */
    public function testPrivKeyExchange()
    {
        $keyA = (new KeyPair())->keygen();
        $cryptoA = new Crypto($keyA);

        // encoded ciphertext
        $message = $this->getMessage();
        $ciphertext = $cryptoA->encrypt($message)->getString();
        $plaintext = $cryptoA->decrypt(Ciphertext::fromString($ciphertext));

        $this->assertSame($message, $plaintext);

        $keyB = new KeyPair([
            KeyPair::PRIV_KEY => $keyA->getKey(KeyPair::PRIV_KEY),
        ]);
        $cryptoB = new Crypto($keyB);

        $plaintext = $cryptoB->decrypt(Ciphertext::fromString($ciphertext));

        $this->assertSame($message, $plaintext);
    }
}
