<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto\Asymmetric;

use Exception;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Helper;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Key as KeyBase;
use ricwein\Crypto\Symmetric\Key;
use SodiumException;
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
class KeyPair extends KeyBase
{
    public const PUB_KEY = 'publickey';
    public const PRIV_KEY = 'privatekey';

    /**
     * @var array<string, string>
     */
    private array $keypair = [
        self::PUB_KEY => null,
        self::PRIV_KEY => null,
    ];

    /**
     * create new Sodium-KeyPair (X25519)
     * @param array<string, string|self|KeyBase> $keys
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @internal
     */
    public function __construct(array $keys, string $encoding = Encoding::RAW)
    {
        foreach ($keys as $type => $key) {
            if (!is_string($key) && !$key instanceof KeyBase) {
                throw new InvalidArgumentException(sprintf("Invalid datatype (%s) for %s-key.", get_debug_type($key), $type), 500);
            }

            if (in_array($type, [self::PUB_KEY, 'publicKey', 'public', 'pubKey'], true)) {

                $this->loadPublicKey($key, $encoding);
                unset($keys[$type]);

            } elseif (in_array($type, [self::PRIV_KEY, 'privateKey', 'secretKey', 'private', 'secret', 'privKey', 'secKey'], true)) {

                $this->loadPrivateKey($key, $encoding);
                unset($keys[$type]);

            } else {
                throw new InvalidArgumentException("Invalid key-type: $type", 500);
            }
        }

        if ($this->keypair[self::PUB_KEY] === null) {
            $this->derivePublicKey();
        }
    }

    /**
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public static function generate(): self
    {
        $keyPair = sodium_crypto_box_keypair();

        $key = new self([
            self::PRIV_KEY => sodium_crypto_box_secretkey($keyPair),
            self::PUB_KEY => sodium_crypto_box_publickey($keyPair),
        ]);

        // Let's wipe our $keyPair variable
        sodium_memzero($keyPair);

        return $key;
    }

    /**
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public static function generateFrom(string $password, ?string $salt = null): self
    {
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

        $key = new self([
            self::PRIV_KEY => sodium_crypto_box_secretkey($keyPair),
            self::PUB_KEY => sodium_crypto_box_publickey($keyPair),
        ]);

        // Let's wipe our $keyPair variable
        sodium_memzero($keyPair);

        return $key;
    }

    /**
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public static function load(array $keys, string $encoding = Encoding::RAW): self
    {
        return new self($keys, $encoding);
    }

    /**
     * safe free keys
     * @throws SodiumException
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
     * @throws EncodingException
     * @throws SodiumException
     * @throws InvalidArgumentException
     */
    private function loadPublicKey(string|self|Key $key, string $encoding = Encoding::RAW): void
    {
        // fetch/decoded key
        if ($key instanceof self) {
            $keyData = $key->getKey(self::PUB_KEY);
        } elseif ($key instanceof KeyBase) {
            $keyData = $key->getKey();
        } else {
            $keyData = Encoding::decode($key, $encoding);
        }

        // check key-length
        if (SODIUM_CRYPTO_BOX_PUBLICKEYBYTES !== $isLength = mb_strlen($keyData, '8bit')) {
            throw new InvalidArgumentException(sprintf('Encryption-public-key must be %d bytes long, but is %d bytes', SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, $isLength), 400);
        }

        // set public key
        $this->keypair[self::PUB_KEY] = $keyData;

        sodium_memzero($keyData);
    }

    /**
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    private function loadPrivateKey(string|self|Key $key, string $encoding = Encoding::RAW): void
    {
        // fetch/decoded key
        if ($key instanceof self) {
            $keyData = $key->getKey(self::PRIV_KEY);
        } elseif ($key instanceof KeyBase) {
            $keyData = $key->getKey();
        } else {
            $keyData = Encoding::decode($key, $encoding);
        }

        // check key-length
        if (SODIUM_CRYPTO_BOX_SECRETKEYBYTES !== $isLength = mb_strlen($keyData, '8bit')) {
            throw new InvalidArgumentException(sprintf('Encryption-secret-key must be %d bytes long, but is %d bytes', SODIUM_CRYPTO_BOX_SECRETKEYBYTES, $isLength), 400);
        }

        // set private key
        $this->keypair[self::PRIV_KEY] = $keyData;

        sodium_memzero($keyData);
    }

    /**
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function derivePublicKey(): self
    {
        if ($this->keypair[self::PRIV_KEY] === null) {
            throw new UnexpectedValueException('Trying to derive a public key for this keypair failed. Missing or invalid private Key.', 500);
        }

        $this->keypair[self::PUB_KEY] = sodium_crypto_box_publickey_from_secretkey($this->keypair[self::PRIV_KEY]);
        return $this;
    }

    /**
     * @throws InvalidArgumentException
     * @throws EncodingException
     * @throws SodiumException
     */
    public function getKey(string $type, string $encoding = Encoding::RAW): ?string
    {
        if (array_key_exists($type, $this->keypair)) {
            $key = Helper::safeStrcpy($this->keypair[$type]);
            return $key !== null ? Encoding::encode($key, $encoding) : null;
        }

        throw new InvalidArgumentException("Unknown key for type '$type'.", 400);
    }

    /**
     * Get a Sodium box keypair
     * @throws EncodingException
     * @throws SodiumException
     */
    public function getKeyPair(string $encoding = Encoding::RAW): ?string
    {
        if ($this->keypair[self::PRIV_KEY] === null) {
            return null;
        }

        $keyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey($this->keypair[self::PRIV_KEY], $this->keypair[self::PUB_KEY]);
        return Encoding::encode($keyPair, $encoding);
    }

    /**
     * Elliptical Curve (Curve25519) Diffie-Hellman X25519
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function getSharedSecret(): Key
    {
        if ($this->keypair[self::PRIV_KEY] === null) {
            throw new UnexpectedValueException('deriving a shared secret requires a valid keypair, but none given', 500);
        }

        $secret = sodium_crypto_scalarmult($this->keypair[self::PRIV_KEY], $this->keypair[self::PUB_KEY]);

        $key = new Key($secret);
        sodium_memzero($secret);

        return $key;
    }

    /**
     * use Blake2b HKDF to derive separated encryption and authentication keys from derived shared-secret
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function hkdfSplit(?string $salt = null): array
    {
        $sharedSecret = $this->getSharedSecret();

        return $sharedSecret->hkdfSplit($salt);
    }

    public function __debugInfo(): array
    {
        return [
            'type' => 'asymmetric keypair',
            'length' => [
                'public' => (null !== $pubKey = $this->keypair[self::PUB_KEY]) ? mb_strlen($pubKey, '8bit') : null,
                'private' => (null !== $privKey = $this->keypair[self::PRIV_KEY]) ? mb_strlen($privKey, '8bit') : null,
            ]
        ];
    }

    /**
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function copyWithExclusive(string $keyType): static
    {
        return new static([$keyType => $this->getKey($keyType)]);
    }
}
