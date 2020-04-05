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

    /**
     * @var string
     */
    private const CONTEXT_AUTH_KEY = 'AuthenticationKey';

    /**
     * @var string
     */
    private const CONTEXT_ENC_KEY = 'EncryptionKey';

    /**
     * @var string|null
     */
    private $key = null;

    /**
     * create new Sodium-Key
     * @param string|null $key
     * @param string $encoding
     * @throws EncodingException
     * @throws InvalidArgumentException
     */
    public function __construct(?string $key = null, string $encoding = Encoding::RAW)
    {
        if ($key !== null) {
            $this->load($key, $encoding);
        }
    }

    /**
     * safe free key
     */
    public function __destruct()
    {
        if ($this->key !== null) {
            sodium_memzero($this->key);
        }
    }

    /**
     * create new symmetric key (secret)
     * @param string|null $password
     * @param string|null $salt
     * @return self
     * @throws InvalidArgumentException
     * @throws Exception
     */
    public function keygen(?string $password = null, ?string $salt = null): self
    {

        // create actual secret (key)
        if ($password !== null) {
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
        } else {

            // secret-key
            $key = sodium_crypto_secretbox_keygen();
        }

        // extract private-key from keypair
        $this->key = $key;

        // Let's wipe our $keyPair variable
        sodium_memzero($key);

        return $this;
    }

    /**
     * @param string $key
     * @param string $encoding
     * @return self
     * @throws InvalidArgumentException
     * @throws EncodingException
     */
    public function load(string $key, string $encoding = Encoding::RAW): self
    {
        $key = Encoding::decode($key, $encoding);

        if (SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== $isLength = mb_strlen($key, '8bit')) {
            throw new InvalidArgumentException(sprintf('Secret-Key must be %d bytes long, but is %d bytes', SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $isLength), 400);
        }

        // set public key
        $this->key = $key;
        sodium_memzero($key);

        return $this;
    }

    /**
     * @param string $encoding
     * @return string|null
     * @throws EncodingException
     */
    public function getKey(string $encoding = Encoding::RAW): ?string
    {
        if ($this->key === null) {
            return null;
        }

        $key = Helper::safeStrcpy($this->key);
        return Encoding::encode($key, $encoding);
    }

    /**
     * use Blake2b HKDF to derive separated encryption and authentication keys from derived shared-secret
     * @param string|null $salt
     * @return array
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
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
