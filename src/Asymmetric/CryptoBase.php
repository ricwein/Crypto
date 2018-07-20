<?php
/**
 * @author Richard Weinhold
 */
namespace ricwein\Crypto\Asymmetric;

use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;

/**
 * crypto-base for asymmetric keypair handling
 */
abstract class CryptoBase
{

    /**
     * @var KeyPair|null
     */
    protected $keypair = null;

    /**
     * @param KeyPair|null $key
     */
    public function __construct(KeyPair $key = null)
    {
        if ($key !== null) {
            $this->keypair = $key;
        }
    }

    /**
     * wipe it from memory after it's been used
     */
    public function __destruct()
    {
        unset($this->keypair);
    }

    /**
     * @return KeyPair|null
     */
    public function getKey(): ?KeyPair
    {
        return $this->keypair;
    }

    /**
     * @param  KeyPair $key
     * @return self
     */
    public function loadKey(KeyPair $key): self
    {
        $this->keypair = $key;
        return $this;
    }

    /**
     * load pub and secret keys as emphemeral keypair
     * @param  string|KeyPair|null $pubKey
     * @return KeyPair
     * @throws UnexpectedValueException|InvalidArgumentException
     */
    public function deriveKeyPair($pubKey = null): KeyPair
    {
        if ($this->keypair === null) {
            throw new UnexpectedValueException('asymmetric authentication crypto requires a keypair, but none given', 500);
        } elseif ($this->keypair->getKey(KeyPair::PRIV_KEY) === null) {
            throw new UnexpectedValueException('asymmetric authentication crypto requires a valid keypair, but is invalid', 500);
        }

        // load private key
        $privKey = $this->keypair->getKey(KeyPair::PRIV_KEY);

        // load public key
        if ($pubKey === null) {

            // use internal public-key
            if ($this->keypair->getKey(KeyPair::PUB_KEY) === null) {
                $this->keypair->derivePublicKey();
            }
            $pubKey = $this->keypair->getKey(KeyPair::PUB_KEY);
        } elseif ($pubKey instanceof KeyPair) {

            // use public key from given keypair
            if ($pubKey->getKey(KeyPair::PUB_KEY) === null) {
                $pubKey->derivePublicKey();
            }
            $pubKey = $pubKey->getKey(KeyPair::PUB_KEY);
        } elseif (!is_string($pubKey)) {
            throw new InvalidArgumentException(sprintf('Encryption-public-key must be string of length %d bytes long, but is of type %s', \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, is_object($pubKey) ? get_class($pubKey) : gettype($pubKey)), 400);
        } elseif (mb_strlen($pubKey, '8bit') !== \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException(sprintf('Encryption-public-key must be string of length %d bytes long, but is %d bytes', \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, mb_strlen($pubKey, '8bit')), 400);
        }

        // create new Alice-Priv <=> Bob-Pub ephemeral KeyPair
        return new KeyPair([
            KeyPair::PUB_KEY  => $pubKey,
            KeyPair::PRIV_KEY => $privKey,
        ]);
    }

    /**
     * encrypt plaintext with libsodium authenticated asymmetric crypto
     * @param  string              $plaintext
     * @param  string|KeyPair|null $pubKey
     * @return Ciphertext
     */
    abstract public function encrypt(string $plaintext, $pubKey = null): Ciphertext;

    /**
     * decrypt ciphertext with libsodium authenticated asymmetric crypto
     * @param  Ciphertext          $ciphertext
     * @param  string|KeyPair|null $pubKey
     * @return string
     */
    abstract public function decrypt(Ciphertext $ciphertext, $pubKey = null): string;
}
