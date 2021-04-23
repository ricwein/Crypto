<?php declare(strict_types=1);

namespace ricwein\Crypto\Tests\Asymmetric;

use Exception;
use PHPUnit\Framework\TestCase;
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\Crypto\Exceptions\RuntimeException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use SodiumException;

/**
 * test asymmetric message en/decryption
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
     * test single-key encryption and decryption with random keypair
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
    public function testCrypto(): void
    {
        $key = (new Crypto(KeyPair::generate()));

        // encoded ciphertext
        $message = $this->getMessage();
        $ciphertext = $key->encrypt($message)->getString();
        $plaintext = $key->decrypt(Ciphertext::fromString($ciphertext));

        self::assertSame($message, $plaintext);

        // raw binary ciphertext
        $message = $this->getMessage();
        $ciphertext = $key->encrypt($message)->getString(Encoding::RAW);
        $plaintext = $key->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW));

        self::assertSame($message, $plaintext);
    }

    /**
     * test asymmetric authenticated encryption with two keypair
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws KeyMismatchException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testAsymmetricCrypto(): void
    {
        $clientKey = KeyPair::generate();
        $serverKey = KeyPair::generate();

        $clientCrypto = new Crypto($clientKey);
        $serverCrypto = new Crypto($serverKey);

        // request from client to server
        $message = $this->getMessage();
        $ciphertext = $clientCrypto->encrypt($message, $serverKey)->getString();
        $plaintext = $serverCrypto->decrypt(Ciphertext::fromString($ciphertext), $clientKey);

        self::assertSame($message, $plaintext);

        // response from server to client
        $message = $this->getMessage();
        $ciphertext = $serverCrypto->encrypt($message, $clientKey)->getString();
        $plaintext = $clientCrypto->decrypt(Ciphertext::fromString($ciphertext), $serverKey);

        self::assertSame($message, $plaintext);

        // request from client to server
        $message = $this->getMessage();
        $ciphertext = $clientCrypto->encrypt($message, $serverKey)->getString(Encoding::RAW);
        $plaintext = $serverCrypto->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW), $clientKey);

        self::assertSame($message, $plaintext);

        // response from server to client
        $message = $this->getMessage();
        $ciphertext = $serverCrypto->encrypt($message, $clientKey)->getString(Encoding::RAW);
        $plaintext = $clientCrypto->decrypt(Ciphertext::fromString($ciphertext, Encoding::RAW), $serverKey);

        self::assertSame($message, $plaintext);
    }

    /**
     * test asymmetric authenticated encryption with two keypair
     * and a third MITM Key attack
     * @return void
     *
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws KeyMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testMITMSend(): void
    {
        $keyAlice = KeyPair::generate();
        $keyBob = KeyPair::generate();
        $keyEve = KeyPair::generate();

        $cryptoAlice = new Crypto($keyAlice);
        $cryptoEve = new Crypto($keyEve);

        // simulate MITM
        // Eve (send message) => Alice (awaits) from Bob
        $message = $this->getMessage();
        $ciphertext = $cryptoEve->encrypt($message, $keyAlice->getKey(KeyPair::PUB_KEY))->getString();

        $this->expectException(MacMismatchException::class);
        $this->expectExceptionMessage('Invalid message authentication code');
        $plaintext = $cryptoAlice->decrypt(Ciphertext::fromString($ciphertext), $keyBob);

        self::assertNotSame($message, $plaintext);
    }

    /**
     * test asymmetric authenticated encryption with two keypair
     * and a third MITM Key attack
     * @return void
     *
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws KeyMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testMITMReceive(): void
    {
        $keyAlice = KeyPair::generate();
        $keyBob = KeyPair::generate();
        $keyEve = KeyPair::generate();

        $cryptoAlice = new Crypto($keyAlice);
        $cryptoEve = new Crypto($keyEve);

        // simulate MITM
        // Alice (send message) => Bob, Eve intercepts
        $message = $this->getMessage();
        $ciphertext = $cryptoAlice->encrypt($message, $keyBob->getKey(KeyPair::PUB_KEY))->getString();

        $this->expectException(MacMismatchException::class);
        $this->expectExceptionMessage('Invalid message authentication code');
        $plaintext = $cryptoEve->decrypt(Ciphertext::fromString($ciphertext), $keyAlice);

        self::assertNotSame($message, $plaintext);
    }

    /**
     * test asymmetric key exchange and private-key => public-key derivation
     * @return void
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws KeyMismatchException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function testPrivateKeyExchange(): void
    {
        $keyA = KeyPair::generate();
        $cryptoA = new Crypto($keyA);

        // encoded ciphertext
        $message = $this->getMessage();
        $ciphertext = $cryptoA->encrypt($message)->getString();
        $plaintext = $cryptoA->decrypt(Ciphertext::fromString($ciphertext));

        self::assertSame($message, $plaintext);

        $keyB = new KeyPair([
            KeyPair::PRIV_KEY => $keyA->getKey(KeyPair::PRIV_KEY),
        ]);
        $cryptoB = new Crypto($keyB);

        $plaintext = $cryptoB->decrypt(Ciphertext::fromString($ciphertext));

        self::assertSame($message, $plaintext);
    }
}
