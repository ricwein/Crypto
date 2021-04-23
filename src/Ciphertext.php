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

    /**
     * @var string
     */
    protected string $encrypted;

    /**
     * @var string
     */
    protected string $salt;

    /**
     * @var string
     */
    protected string $nonce;

    /**
     * @var string|null
     */
    protected ?string $authKey = null;

    /**
     * @var string|null
     */
    protected ?string $mac = null;

    /**
     * @var string
     */
    protected string $cipher = 'unknown';

    /**
     * @param string $encrypted
     * @param string $salt
     * @param string $nonce
     */
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
     * @param string $ciphertext
     * @param string $encoding
     * @return self
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
     * @param string $message
     * @return array
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
     * @param string $encoding
     * @return string
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
     * @return string
     * @throws Exceptions\EncodingException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function __toString(): string
    {
        return $this->getString();
    }

    /**
     * @param string $cipher
     * @return self
     */
    public function setCipher(string $cipher): self
    {
        $this->cipher = $cipher;
        return $this;
    }

    /**
     * @return string
     */
    public function getCipher(): string
    {
        return $this->cipher;
    }

    /**
     * @param string $mac
     * @return self
     */
    public function setMac(string $mac): self
    {
        $this->mac = $mac;
        return $this;
    }

    /**
     * @param string $encoding
     * @return string
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
     * @param string|null $mac
     * @return bool
     * @throws Exceptions\EncodingException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function isValidMac(?string $mac = null): bool
    {
        return hash_equals($mac ?? $this->getMac(), $this->calcMac());
    }

    /**
     * @return string raw-binary
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

    /**
     * @param string $authKey
     * @return self
     */
    public function setAuthKey(string $authKey): self
    {
        $this->authKey = $authKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * @return string
     */
    public function getEncrypted(): string
    {
        return $this->encrypted;
    }
}
