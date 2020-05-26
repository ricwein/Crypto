<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto\Asymmetric;

use Exception;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Helper;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use function random_bytes;
use function sodium_crypto_box_keypair;
use function sodium_crypto_box_keypair_from_secretkey_and_publickey;
use function sodium_crypto_box_publickey;
use function sodium_crypto_box_publickey_from_secretkey;
use function sodium_crypto_box_secretkey;
use function sodium_crypto_box_seed_keypair;
use function sodium_crypto_pwhash;
use function sodium_crypto_scalarmult;
use function sodium_memzero;
use const SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
use const SODIUM_CRYPTO_BOX_SECRETKEYBYTES;
use const SODIUM_CRYPTO_BOX_SEEDBYTES;
use const SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;
use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_SALTBYTES;

/**
 * Asymmetric Sodium-KeyPair
 */
class KeyPair
{
    /**
     * public key
     * @var string
     */
    public const PUB_KEY = 'publickey';

    /**
     * private key
     * @var string
     */
    public const PRIV_KEY = 'privatekey';

    /**
     * @var string[]
     */
    private $keypair = [
        self::PUB_KEY => null,
        self::PRIV_KEY => null,
    ];

    /**
     * create new Sodium-KeyPair (X25519)
     * @param string[]|null $keys
     * @param string $encoding
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     */
    public function __construct(?array $keys = null, string $encoding = Encoding::RAW)
    {
        if ($keys !== null) {
            $this->load($keys, $encoding);
        }
    }

    /**
     * safe free keys
     */
    public function __destruct()
    {
        foreach ([self::PUB_KEY, self::PRIV_KEY] as $key) {
            if ($this->keypair[$key] !== null) {
                sodium_memzero($this->keypair[$key]);
            }
        }
    }

    /**
     * create new priv/pub keypair
     * @param string|null $password
     * @param string|null $salt
     * @return self
     * @throws Exception
     * @throws InvalidArgumentException
     */
    public function keygen(?string $password = null, ?string $salt = null): self
    {

        // create actual keypair
        if ($password !== null) {
            if ($salt !== null && SODIUM_CRYPTO_PWHASH_SALTBYTES !== $isLength = mb_strlen($salt, '8bit')) {
                throw new InvalidArgumentException(sprintf('Keypair-Salt must be %d bytes long, but is %d bytes', SODIUM_CRYPTO_PWHASH_SALTBYTES, $isLength), 400);
            }

            if ($salt === null) {
                $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            }

            /**
             * Diffie Hellman key exchange key pair
             * @var string
             */
            $seed = @sodium_crypto_pwhash(
                SODIUM_CRYPTO_BOX_SEEDBYTES,
                $password,
                $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
            );

            sodium_memzero($password);
            sodium_memzero($salt);

            // Encryption keypair
            $keyPair = sodium_crypto_box_seed_keypair($seed);

            // Let's wipe our $keyPair variable
            sodium_memzero($seed);
        } else {

            // Encryption keypair
            $keyPair = sodium_crypto_box_keypair();
        }

        // extract private-key from keypair
        $this->keypair[self::PRIV_KEY] = sodium_crypto_box_secretkey($keyPair);

        // extract public-key from keypair
        $this->keypair[self::PUB_KEY] = sodium_crypto_box_publickey($keyPair);

        // Let's wipe our $keyPair variable
        sodium_memzero($keyPair);

        return $this;
    }

    /**
     * @param string[]|self[]|Key[] $keys
     * @param string $encoding
     * @return self
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws EncodingException
     */
    public function load(array $keys, string $encoding = Encoding::RAW): self
    {
        foreach ($keys as $type => $key) {
            if (in_array($type, [self::PUB_KEY, 'publicKey', 'public', 'pubKey'], true)) {

                // fetch/decoded key
                if (is_string($key)) {
                    $key = Encoding::decode($key, $encoding);
                } elseif ($key instanceof self) {
                    $key = $key->getKey(self::PUB_KEY);
                } elseif ($key instanceof Key) {
                    $key = $key->getKey();
                } else {
                    throw new InvalidArgumentException(sprintf('invalid type \'%s\' for key \'%s\'', gettype($key), $type), 500);
                }

                // check key-length
                if (SODIUM_CRYPTO_BOX_PUBLICKEYBYTES !== $isLength = mb_strlen($key, '8bit')) {
                    throw new InvalidArgumentException(sprintf('Encryption-public-key must be %d bytes long, but is %d bytes', SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, $isLength), 400);
                }

                // set public key
                $this->keypair[self::PUB_KEY] = $key;

                sodium_memzero($key);
                unset($keys[$type]);
            } elseif (in_array($type, [self::PRIV_KEY, 'privateKey', 'secretKey', 'private', 'secret', 'privKey', 'secKey'], true)) {

                // fetch/decoded key
                if (is_string($key)) {
                    $key = Encoding::decode($key, $encoding);
                } elseif ($key instanceof self) {
                    $key = $key->getKey(self::PRIV_KEY);
                } elseif ($key instanceof Key) {
                    $key = $key->getKey();
                } else {
                    throw new InvalidArgumentException(sprintf('invalid type \'%s\' for key \'%s\'', gettype($key), $type), 500);
                }

                // check key-length
                if (SODIUM_CRYPTO_BOX_SECRETKEYBYTES !== $isLength = mb_strlen($key, '8bit')) {
                    throw new InvalidArgumentException(sprintf('Encryption-secret-key must be %d bytes long, but is %d bytes', SODIUM_CRYPTO_BOX_SECRETKEYBYTES, $isLength), 400);
                }

                // set private key
                $this->keypair[self::PRIV_KEY] = $key;

                sodium_memzero($key);
                unset($keys[$type]);
            } else {
                throw new InvalidArgumentException(sprintf('invalid key-type \'%s\'', $type), 500);
            }
        }

        if ($this->keypair[self::PUB_KEY] === null) {
            $this->derivePublicKey();
        }

        return $this;
    }

    /**
     * @return self
     * @throws UnexpectedValueException
     */
    public function derivePublicKey(): self
    {
        if ($this->keypair[self::PRIV_KEY] === null) {
            throw new UnexpectedValueException('deriving a public key requires a private key to be set, but none given', 500);
        }

        $this->keypair[self::PUB_KEY] = sodium_crypto_box_publickey_from_secretkey($this->keypair[self::PRIV_KEY]);
        return $this;
    }

    /**
     * @param string $type
     * @param string $encoding
     * @return string|null
     * @throws InvalidArgumentException
     * @throws EncodingException
     */
    public function getKey(string $type, string $encoding = Encoding::RAW): ?string
    {
        if (array_key_exists($type, $this->keypair)) {
            $key = Helper::safeStrcpy($this->keypair[$type]);
            return $key !== null ? Encoding::encode($key, $encoding) : null;
        }

        throw new InvalidArgumentException(sprintf('unknown key-type \'%s\'', $type), 400);
    }

    /**
     * Get a Sodium box keypair
     * @param string $encoding
     * @return string|null
     * @throws EncodingException
     * @throws UnexpectedValueException
     */
    public function getKeyPair(string $encoding = Encoding::RAW): ?string
    {
        if ($this->keypair[self::PRIV_KEY] === null) {
            return null;
        }

        if ($this->keypair[self::PUB_KEY] === null) {
            $this->derivePublicKey();
        }

        $keyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey($this->keypair[self::PRIV_KEY], $this->keypair[self::PUB_KEY]);
        return Encoding::encode($keyPair, $encoding);
    }

    /**
     * Elliptical Curve (Curve25519) Diffie-Hellman X25519
     * @return Key
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     */
    public function getSharedSecret(): Key
    {
        if ($this->keypair[self::PRIV_KEY] === null) {
            throw new UnexpectedValueException('deriving a shared secret requires a valid keypair, but none given', 500);
        }

        if ($this->keypair[self::PUB_KEY] === null) {
            $this->derivePublicKey();
        }

        $secret = sodium_crypto_scalarmult($this->keypair[self::PRIV_KEY], $this->keypair[self::PUB_KEY]);

        $key = new Key($secret);
        sodium_memzero($secret);

        return $key;
    }

    /**
     * use Blake2b HKDF to derive separated encryption and authentication keys from derived shared-secret
     * @param string|null $salt
     * @return array
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws EncodingException
     */
    public function hkdfSplit(?string $salt = null): array
    {
        $sharedSecret = $this->getSharedSecret();

        return $sharedSecret->hkdfSplit($salt);
    }
}
