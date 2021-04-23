<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto\Symmetric;

use Exception;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Helper;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use SodiumException;
use function random_bytes;
use function sodium_crypto_pwhash;
use function sodium_crypto_secretbox_keygen;
use function sodium_memzero;
use const SODIUM_CRYPTO_AUTH_KEYBYTES;
use const SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;
use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_SALTBYTES;
use const SODIUM_CRYPTO_SECRETBOX_KEYBYTES;

/**
 * Symmetric Sodium-Key (Secret)
 */
class Key
{
    private const CONTEXT_AUTH_KEY = 'AuthenticationKey';
    private const CONTEXT_ENC_KEY = 'EncryptionKey';

    private string $key;

    /**
     * create new Sodium-Key
     * @param string $key
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @internal
     */
    public function __construct(string $key)
    {
        if (SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== $isLength = mb_strlen($key, '8bit')) {
            throw new InvalidArgumentException(sprintf('Secret-Key must be %d bytes long, but is %d bytes', SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $isLength), 400);
        }

        // set public key
        $this->key = $key;
        sodium_memzero($key);
    }

    /**
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public static function generate(): self
    {
        $key = sodium_crypto_secretbox_keygen();
        return new self($key);
    }

    /**
     * @param string $password
     * @param string|null $salt
     * @return static
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws Exception
     */
    public static function generateFrom(string $password, ?string $salt = null): self
    {
        if ($salt !== null && SODIUM_CRYPTO_PWHASH_SALTBYTES !== $isLength = mb_strlen($salt, '8bit')) {
            throw new InvalidArgumentException(sprintf('Expected salt to be %d bytes long, but is %d bytes', SODIUM_CRYPTO_PWHASH_SALTBYTES, $isLength), 400);
        }

        if ($salt === null) {
            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        }

        /**
         * Diffie Hellman key-derivation
         * @var string
         */
        $key = @sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );

        sodium_memzero($password);
        sodium_memzero($salt);

        return new self($key);
    }

    /**
     * @param Key|string $key
     * @param string $encoding
     * @return static
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public static function load(self|string $key, string $encoding = Encoding::RAW): self
    {
        $keyData = is_string($key) ? Encoding::decode($key, $encoding) : $key->getKey();
        return new self($keyData);
    }

    /**
     * safe free key
     * @throws SodiumException
     */
    public function __destruct()
    {
        if ($this->key !== null) {
            sodium_memzero($this->key);
        }
    }

    /**
     * @param string $encoding
     * @return string
     * @throws EncodingException
     * @throws SodiumException
     */
    public function getKey(string $encoding = Encoding::RAW): string
    {
        $key = Helper::safeStrcpy($this->key);
        return Encoding::encode($key, $encoding);
    }

    /**
     * use Blake2b HKDF to derive separated encryption and authentication keys from derived shared-secret
     * @param string|null $salt
     * @return array
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws SodiumException
     */
    public function hkdfSplit(?string $salt = null): array
    {
        if ($this->key === null) {
            throw new UnexpectedValueException('deriving subkeys via HKDF requires a secret to be set, but none given', 500);
        }

        $encKey = Helper::hkdfBlake2b($this->key, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, self::CONTEXT_ENC_KEY, $salt);
        $authKey = Helper::hkdfBlake2b($this->key, SODIUM_CRYPTO_AUTH_KEYBYTES, self::CONTEXT_AUTH_KEY, $salt);

        return [$encKey, $authKey];
    }

    /**
     * calculate (hash-based) key fingerprint
     * @param string $encoding
     * @param string $algo
     * @return string|null
     * @throws EncodingException
     * @throws SodiumException
     */
    public function fingerprint(string $encoding = Encoding::HEX, string $algo = 'sha256'): ?string
    {
        if ($this->key === null) {
            return null;
        }

        $fingerprint = hash($algo, $this->key, true);
        return Encoding::encode($fingerprint, $encoding);
    }
}
