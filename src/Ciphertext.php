<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto;

use ricwein\Crypto\Exceptions\RuntimeException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use SodiumException;
use function sodium_crypto_generichash;
use function sodium_memzero;
use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;
use const SODIUM_CRYPTO_GENERICHASH_KEYBYTES;
use const SODIUM_CRYPTO_STREAM_NONCEBYTES;

/**
 * represents ciphertext parts
 */
class Ciphertext
{
    protected string $encrypted;
    protected string $salt;
    protected string $nonce;
    protected ?string $authKey = null;
    protected ?string $mac = null;
    protected string $cipher = 'unknown';

    public function __construct(string $encrypted, string $salt, string $nonce)
    {
        $this->encrypted = $encrypted;

        $this->salt = $salt;
        $this->nonce = $nonce;
    }

    /**
     * override and release class members
     * @throws SodiumException
     */
    public function __destruct()
    {
        sodium_memzero($this->encrypted);
        sodium_memzero($this->salt);
        sodium_memzero($this->nonce);

        if ($this->authKey !== null) {
            sodium_memzero($this->authKey);
        }

        if ($this->mac !== null) {
            sodium_memzero($this->mac);
        }
    }

    /**
     * @throws Exceptions\EncodingException
     * @throws RuntimeException
     * @throws SodiumException
     */
    public static function fromString(string $ciphertext, string $encoding = Encoding::BASE64URLSAFE): self
    {
        $ciphertext = Encoding::decode($ciphertext, $encoding);

        [$salt, $nonce, $encrypted, $mac] = self::unpackMessageForDecryption($ciphertext);

        $newCiphertextObj = new static($encrypted, $salt, $nonce);

        // verify mac length
        if (mb_strlen($mac, '8bit') !== SODIUM_CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new RuntimeException('Invalid length for MAC, is it encoded?', 400);
        }

        $newCiphertextObj->setMac($mac);
        return $newCiphertextObj;
    }

    /**
     * @throws SodiumException
     * @throws RuntimeException
     */
    private static function unpackMessageForDecryption(string $message): array
    {
        $length = mb_strlen($message, '8bit');

        if ($length <= (SODIUM_CRYPTO_GENERICHASH_KEYBYTES + SODIUM_CRYPTO_STREAM_NONCEBYTES + SODIUM_CRYPTO_GENERICHASH_BYTES_MAX)) {
            throw new RuntimeException('Invalid length for Ciphertext, is it encoded?', 400);
        }

        // the salt is used for key splitting (via HKDF)
        $salt = mb_substr($message, 0, SODIUM_CRYPTO_GENERICHASH_KEYBYTES, '8bit');

        // this is the nonce (we authenticated it):
        $nonce = mb_substr($message, SODIUM_CRYPTO_GENERICHASH_KEYBYTES, SODIUM_CRYPTO_STREAM_NONCEBYTES, '8bit');

        // this is the crypto_stream_xor()ed ciphertext
        $encrypted = mb_substr(
            $message,
            SODIUM_CRYPTO_GENERICHASH_KEYBYTES + SODIUM_CRYPTO_STREAM_NONCEBYTES,
            $length - (SODIUM_CRYPTO_GENERICHASH_KEYBYTES + SODIUM_CRYPTO_STREAM_NONCEBYTES + SODIUM_CRYPTO_GENERICHASH_BYTES_MAX),
            '8bit'
        );

        // $hmac is the last 32 bytes
        $hmac = mb_substr($message, $length - SODIUM_CRYPTO_GENERICHASH_BYTES_MAX, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX, '8bit');

        // We don't need this anymore.
        sodium_memzero($message);

        // Now we return the pieces in a specific order:
        return [$salt, $nonce, $encrypted, $hmac];
    }

    /**
     * get ciphertext as string, including mac
     * @throws Exceptions\EncodingException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function getString(string $encoding = Encoding::BASE64URLSAFE): string
    {
        $message = $this->salt . $this->nonce . $this->encrypted . $this->getMac();

        return Encoding::encode($message, $encoding);
    }

    /**
     * @throws Exceptions\EncodingException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function __toString(): string
    {
        return $this->getString();
    }

    public function setCipher(string $cipher): self
    {
        $this->cipher = $cipher;
        return $this;
    }

    public function getCipher(): string
    {
        return $this->cipher;
    }

    public function setMac(string $mac): self
    {
        $this->mac = $mac;
        return $this;
    }

    /**
     * @throws Exceptions\EncodingException
     * @throws UnexpectedValueException
     * @throws SodiumException
     */
    public function getMac(string $encoding = Encoding::RAW): string
    {
        if ($this->mac === null) {

            // calculate Message Authentication Code
            $this->mac = $this->calcMac();
        }

        return Encoding::encode($this->mac, $encoding);
    }

    /**
     * @throws Exceptions\EncodingException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function isValidMac(?string $mac = null): bool
    {
        return hash_equals($mac ?? $this->getMac(), $this->calcMac());
    }

    /**
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    protected function calcMac(): string
    {
        if ($this->authKey === null) {
            throw new UnexpectedValueException('Expected a valid authentication-key but none given', 400);
        }

        return sodium_crypto_generichash($this->salt . $this->nonce . $this->encrypted, $this->authKey, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
    }

    public function setAuthKey(string $authKey): self
    {
        $this->authKey = $authKey;
        return $this;
    }

    public function getSalt(): string
    {
        return $this->salt;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function getEncrypted(): string
    {
        return $this->encrypted;
    }
}
