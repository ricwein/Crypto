<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto\Asymmetric;

use Exception;
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Crypto as CryptoBase;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\Crypto\Exceptions\RuntimeException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Symmetric\Crypto as SymmetricCrypto;
use ricwein\FileSystem\Exceptions\AccessDeniedException;
use ricwein\FileSystem\Exceptions\ConstraintsException;
use ricwein\FileSystem\Exceptions\Exception as FileSystemException;
use ricwein\FileSystem\Exceptions\FileNotFoundException;
use ricwein\FileSystem\Exceptions\RuntimeException as FileSystemRuntimeException;
use ricwein\FileSystem\Exceptions\UnexpectedValueException as FileSystemUnexpectedValueException;
use ricwein\FileSystem\Exceptions\UnsupportedException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;
use ricwein\FileSystem\Storage\Extensions\Binary;
use SodiumException;
use function is_string;
use function random_bytes;
use function sodium_crypto_box_seal;
use function sodium_crypto_box_seal_open;
use function sodium_crypto_generichash;
use const SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
use const SODIUM_CRYPTO_GENERICHASH_KEYBYTES;
use const SODIUM_CRYPTO_STREAM_NONCEBYTES;

/**
 * asymmetric Crypto using libsodium
 */
class Crypto extends CryptoBase
{
    protected KeyPair $keypair;

    public function __construct(KeyPair $key)
    {
        $this->keypair = $key;
    }

    /**
     * wipe it from memory after it's been used
     */
    public function __destruct()
    {
        unset($this->keypair);
    }

    public function getKey(): KeyPair
    {
        return $this->keypair;
    }

    /**
     * load pub and secret keys as ephemeral keypair
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws SodiumException
     */
    public function deriveKeyPair(string|KeyPair $pubKey = null): KeyPair
    {
        if ($this->keypair === null) {
            throw new UnexpectedValueException('asymmetric authentication crypto requires a keypair, but none given', 500);
        }

        if ($this->keypair->getKey(KeyPair::PRIV_KEY) === null) {
            throw new UnexpectedValueException('asymmetric authentication crypto requires a valid keypair, but is invalid', 500);
        }

        // load private key
        $privateKey = $this->keypair->getKey(KeyPair::PRIV_KEY);

        // load public key
        if ($pubKey === null) {

            // use internal public-key
            $pubKey = $this->keypair->getKey(KeyPair::PUB_KEY);
        } elseif ($pubKey instanceof KeyPair) {

            // use public key from given keypair
            $pubKey = $pubKey->getKey(KeyPair::PUB_KEY);
        } elseif (!is_string($pubKey)) {
            throw new InvalidArgumentException(sprintf('Encryption-public-key must be string of length %d bytes long, but is of type %s.', SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, get_debug_type($pubKey)), 400);
        } elseif (mb_strlen($pubKey, '8bit') !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidArgumentException(sprintf('Encryption-public-key must be string of length %d bytes long, but is %d bytes.', SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, mb_strlen($pubKey, '8bit')), 400);
        }

        // create new Alice-Private <=> Bob-Public ephemeral KeyPair
        return new KeyPair([
            KeyPair::PUB_KEY => $pubKey,
            KeyPair::PRIV_KEY => $privateKey,
        ]);
    }

    /**
     * @param string|KeyPair|null $pubKey
     * @return SymmetricCrypto
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    protected function deriveSymmetricCrypto(string|KeyPair $pubKey = null): SymmetricCrypto
    {
        // derive ephemeral public-private encryption keypair
        $encKeyPair = $this->deriveKeyPair($pubKey);

        // create a symmetric secret from KeyPair per Diffie-Hellman KeyExchange
        return new SymmetricCrypto($encKeyPair->getSharedSecret());
    }

    /**
     * encrypt plaintext with libsodium authenticated asymmetric crypto
     * using ECDH to derive a shared secret (keyA-priv + keyB-pub)
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws KeyMismatchException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function encrypt(string $plaintext, string|KeyPair $pubKey = null): Ciphertext
    {
        // use symmetric authenticated encryption to encrypt and sign the given message
        return $this->deriveSymmetricCrypto($pubKey)->encrypt($plaintext);
    }

    /**
     * decrypt ciphertext with libsodium authenticated asymmetric crypto
     * using ECDH to derive a shared secret (keyA-priv + keyB-pub)
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws UnexpectedValueException
     * @throws SodiumException
     */
    public function decrypt(Ciphertext $ciphertext, string|KeyPair $pubKey = null): string
    {
        // use symmetric authenticated encryption to decrypt and validate (HMAC) the given message
        return $this->deriveSymmetricCrypto($pubKey)->decrypt($ciphertext);
    }

    /**
     * encrypt plaintext with libsodium asymmetric crypto
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     */
    public function seal(string $plaintext, string $encoding = Encoding::RAW): string
    {
        $publicKey = $this->getKey()->getKey(KeyPair::PUB_KEY);
        $sealed = sodium_crypto_box_seal($plaintext, $publicKey);
        return Encoding::encode($sealed, $encoding);
    }

    /**
     * decrypt ciphertext with libsodium asymmetric crypto
     * @throws EncodingException
     * @throws KeyMismatchException
     * @throws SodiumException
     * @throws UnexpectedValueException
     */
    public function unseal(string $ciphertext, string $encoding = Encoding::RAW): string
    {
        $ciphertext = Encoding::decode($ciphertext, $encoding);

        // Get a box keypair (needed by crypto_box_seal_open)
        $keyPair = $this->getKey()->getKeyPair();

        if ($keyPair === null) {
            throw new KeyMismatchException('Missing private key for asymmetric unseal().', 500);
        }

        // Now let's open that sealed box
        $message = sodium_crypto_box_seal_open($ciphertext, $keyPair);
        unset($keyPair);

        if (!is_string($message)) {
            throw new KeyMismatchException('Incorrect private key for this sealed message.');
        }

        return $message;
    }

    /**
     * authenticated asymmetric File encryption using libsodium
     * using ECDH to derive a shared secret (keyA-priv + keyB-pub)
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws FileSystemException
     * @throws FileNotFoundException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws FileSystemRuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     */
    public function encryptFile(File $source, Storage|File $destination = null, string|KeyPair $pubKey = null): File
    {
        // use symmetric authenticated encryption to encrypt and sign the given file
        return $this->deriveSymmetricCrypto($pubKey)->encryptFile($source, $destination);
    }

    /**
     * authenticated asymmetric File decryption using libsodium
     * using ECDH to derive a shared secret (keyA-priv + keyB-pub)
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws FileSystemException
     * @throws FileNotFoundException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws FileSystemRuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     * @throws RuntimeException
     */
    public function decryptFile(File $source, Storage|File $destination = null, string|KeyPair $pubKey = null): File
    {
        // use symmetric authenticated encryption to encrypt and sign the given file
        return $this->deriveSymmetricCrypto($pubKey)->decryptFile($source, $destination);
    }

    /**
     * asymmetric File encryption using libsodium
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws Exception
     */
    public function sealFile(File $source, Storage|File $destination = null): File
    {
        $destination = $this->prepareDestination($source->storage(), $destination);

        // run actual stream public-key only encryption
        $this->streamSealFile($source, $destination);

        // replace the source-file with the encrypted one
        if ($destination === null && $source->storage() instanceof Storage\Disk) {
            return $destination->moveTo($source->storage());
        }

        return $destination;
    }

    /**
     * @param File $source
     * @param File $destination
     * @return int
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws FileNotFoundException
     * @throws InvalidArgumentException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     * @throws Exception
     */
    protected function streamSealFile(File $source, File $destination): int
    {
        $publicKey = $this->keypair->getKey(KeyPair::PUB_KEY);

        $ephemeralKeyPair = KeyPair::generate();
        $ephemeralPublicKey = $ephemeralKeyPair->getKey(KeyPair::PUB_KEY);
        $ephemeralPrivateKey = $ephemeralKeyPair->getKey(KeyPair::PRIV_KEY);
        unset($ephemeralKeyPair);

        // Calculate the shared secret key
        $sharedSecret = (new KeyPair([
            KeyPair::PUB_KEY => $publicKey,
            KeyPair::PRIV_KEY => $ephemeralPrivateKey
        ]))->getSharedSecret();

        unset($ephSecret);

        $nonce = sodium_crypto_generichash(
            $ephemeralPublicKey . $publicKey,
            '',
            SODIUM_CRYPTO_STREAM_NONCEBYTES
        );

        // Generate a random HKDF salt
        $salt = random_bytes(SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

        [$encKey, $authKey] = $sharedSecret->hkdfSplit($salt);

        return $this->encryptFileStream($source, $destination, [
            ['value' => $ephemeralPublicKey, 'length' => SODIUM_CRYPTO_BOX_PUBLICKEYBYTES],
            ['value' => $salt, 'length' => SODIUM_CRYPTO_GENERICHASH_KEYBYTES],
        ], $authKey, $encKey, $nonce);
    }

    /**
     * asymmetric File decryption using libsodium
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws FileNotFoundException
     * @throws FileSystemException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws FileSystemRuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     */
    public function unsealFile(File $source, Storage|File $destination = null): File
    {
        $encryptSelf = ($destination === null);
        $destination = $this->prepareDestination($source->storage(), $destination);

        // run actual stream-encryption
        $this->streamUnsealFile($source, $destination);

        // replace the source-file with the encrypted one
        if ($encryptSelf && $source->storage() instanceof Storage\Disk) {
            return $destination->moveTo($source->storage());
        }

        return $destination;
    }

    /**
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws FileNotFoundException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws FileSystemRuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     */
    protected function streamUnsealFile(File $source, File $destination): int
    {
        // open locking file-handles
        $sourceHandle = $source->getHandle(Binary::MODE_READ);
        $destinationHandle = $destination->getHandle(Binary::MODE_WRITE);

        // Is the file at least as long as a header?
        if ($sourceHandle->getSize() < (SODIUM_CRYPTO_BOX_PUBLICKEYBYTES + SODIUM_CRYPTO_GENERICHASH_KEYBYTES)) {
            throw new FileSystemRuntimeException(sprintf('Input file is too small. Expected at least %d bytes, but got %d.',
                SODIUM_CRYPTO_BOX_PUBLICKEYBYTES + SODIUM_CRYPTO_GENERICHASH_KEYBYTES,
                $sourceHandle->getSize()
            ));
        }

        $publicKey = $this->keypair->getKey(KeyPair::PUB_KEY);

        $sourceHandle->seek();

        $ephemeralPublicKey = $sourceHandle->read(SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
        $salt = $sourceHandle->read(SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

        // Generate the same nonce, as per streamSealFile()
        $nonce = sodium_crypto_generichash(
            $ephemeralPublicKey . $publicKey,
            '',
            SODIUM_CRYPTO_STREAM_NONCEBYTES
        );

        // Calculate the shared secret key
        $sharedSecret = (new KeyPair([
            KeyPair::PUB_KEY => $ephemeralPublicKey,
            KeyPair::PRIV_KEY => $this->keypair->getKey(KeyPair::PRIV_KEY)
        ]))->getSharedSecret();

        // split our key into authentication and encryption keys
        [$encKey, $authKey] = $sharedSecret->hkdfSplit($salt);

        $written = $this->decryptFileStream(
            $sourceHandle, $destinationHandle,
            [['value' => $ephemeralPublicKey], ['value' => $salt]],
            $authKey, $encKey,
            $nonce
        );

        // free handles
        $sourceHandle = null;
        $destinationHandle = null;

        return $written;
    }
}
