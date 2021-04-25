<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto\Symmetric;

use Exception;
use ricwein\Crypto\Crypto as CryptoBase;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\RuntimeException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\FileSystem\Exceptions\ConstraintsException;
use ricwein\FileSystem\Exceptions\Exception as FileSystemException;
use ricwein\FileSystem\Exceptions\FileNotFoundException;
use ricwein\FileSystem\Exceptions\RuntimeException as FileSystemRuntimeException;
use ricwein\FileSystem\Exceptions\UnexpectedValueException as FileSystemUnexpectedValueException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;
use ricwein\FileSystem\Exceptions\UnsupportedException;
use ricwein\FileSystem\Exceptions\AccessDeniedException;
use ricwein\FileSystem\Storage\Extensions\Binary;
use SodiumException;
use function is_string;
use function random_bytes;
use function sodium_crypto_stream_xor;
use function sodium_memzero;
use const SODIUM_CRYPTO_GENERICHASH_KEYBYTES;
use const SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
use const SODIUM_CRYPTO_STREAM_KEYBYTES;
use const SODIUM_CRYPTO_STREAM_NONCEBYTES;

/**
 * asymmetric Crypto using libsodium
 */
class Crypto extends CryptoBase
{
    protected Key $key;

    public function __construct(Key $key)
    {
        $this->key = $key;
    }

    /**
     * wipe it from memory after it's been used
     */
    public function __destruct()
    {
        unset($this->key);
    }

    public function getKey(): Key
    {
        return $this->key;
    }

    /**
     * encrypt plaintext with libsodium authenticated asymmetric crypto
     * @throws KeyMismatchException
     */
    public function encrypt(string $plaintext): Ciphertext
    {
        try {

            // generate nonce and HKDF salt
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $salt = random_bytes(SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

            // split shared secret into authentication and encryption keys
            [$encKey, $authKey] = $this->key->hkdfSplit($salt);

            /**
             * encrypt actual plaintext (XSalsa20)
             * @see https://download.libsodium.org/doc/advanced/xsalsa20.html
             */
            $encrypted = sodium_crypto_stream_xor($plaintext, $nonce, $encKey);
            sodium_memzero($plaintext);
            sodium_memzero($encKey);

            $ciphertext = new Ciphertext($encrypted, $salt, $nonce);
            $ciphertext->setAuthKey($authKey);

            sodium_memzero($encrypted);
            sodium_memzero($salt);
            sodium_memzero($nonce);
            sodium_memzero($authKey);

            // save used cipher algorithm for later
            $ciphertext->setCipher('xsalsa20');

            return $ciphertext;
        } catch (Exception $exception) {
            throw new KeyMismatchException('invalid security key', 500, $exception);
        }
    }

    /**
     * decrypt ciphertext with libsodium authenticated asymmetric crypto
     * @throws MacMismatchException
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws SodiumException
     */
    public function decrypt(Ciphertext $ciphertext): string
    {

        // split shared secret into authentication and encryption keys
        [$encKey, $authKey] = $this->key->hkdfSplit($ciphertext->getSalt());

        // validate ciphertext mac
        if (!$ciphertext->setAuthKey($authKey)->isValidMac()) {
            throw new MacMismatchException('Invalid message authentication code', 400);
        }

        sodium_memzero($authKey);

        // decrypt actual ciphertext
        $plaintext = sodium_crypto_stream_xor($ciphertext->getEncrypted(), $ciphertext->getNonce(), $encKey);

        sodium_memzero($encKey);

        /** @noinspection UselessUnsetInspection */
        unset($ciphertext);

        if (!is_string($plaintext)) {
            throw new MacMismatchException('Invalid message authentication code', 400);
        }

        return $plaintext;
    }

    /**
     * symmetric File encryption using libsodium
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws FileNotFoundException
     * @throws FileSystemException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     */
    public function encryptFile(File $source, File|Storage $destination = null): File
    {
        $encryptSelf = ($destination === null);
        $destination = $this->prepareDestination($source->storage(), $destination);

        // run actual stream-encryption
        $this->streamEncryptFile($source, $destination);

        // replace the source-file with the encrypted one
        if ($encryptSelf && $source->storage() instanceof Storage\Disk) {
            return $destination->moveTo($source->storage());
        }

        return $destination;
    }

    /**
     * @return int bytes written
     * @throws ConstraintsException
     * @throws FileNotFoundException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     * @throws Exception
     */
    protected function streamEncryptFile(File $source, File $destination): int
    {
        // generate (first) nonce and HKDF salt
        $nonce = random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $salt = random_bytes(SODIUM_CRYPTO_STREAM_KEYBYTES);

        // split our key into authentication and encryption keys
        [$encKey, $authKey] = $this->key->hkdfSplit($salt);

        return $this->encryptFileStream($source, $destination, [
            ['value' => $nonce, 'length' => SODIUM_CRYPTO_STREAM_NONCEBYTES],
            ['value' => $salt, 'length' => SODIUM_CRYPTO_STREAM_KEYBYTES],
        ], $authKey, $encKey, $nonce);
    }

    /**
     * symmetric File decryption using libsodium
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws FileNotFoundException
     * @throws FileSystemException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     * @throws SodiumException
     */
    public function decryptFile(File $source, File|Storage $destination = null): File
    {
        $encryptSelf = ($destination === null);
        $destination = $this->prepareDestination($source->storage(), $destination);

        // run actual stream-encryption
        $this->streamDecryptFile($source, $destination);

        // replace the source-file with the encrypted one
        if ($encryptSelf && $source->storage() instanceof Storage\Disk) {
            return $destination->moveTo($source->storage());
        }

        return $destination;
    }

    /**
     * @return int bytes written
     * @throws ConstraintsException
     * @throws FileNotFoundException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     * @throws FileSystemRuntimeException
     */
    protected function streamDecryptFile(File $source, File $destination): int
    {
        // open locking file-handles
        $sourceHandle = $source->getHandle(Binary::MODE_READ);
        $destinationHandle = $destination->getHandle(Binary::MODE_WRITE);

        // Is the file at least as long as a header?
        if ($sourceHandle->getSize() < (SODIUM_CRYPTO_STREAM_NONCEBYTES + SODIUM_CRYPTO_STREAM_KEYBYTES)) {
            throw new RuntimeException(sprintf('Input file is too small. Expected at least %d bytes, but got %d.',
                SODIUM_CRYPTO_STREAM_NONCEBYTES + SODIUM_CRYPTO_STREAM_KEYBYTES,
                $sourceHandle->getSize()
            ));
        }

        $sourceHandle->seek();

        // read file-header from encrypted file
        $nonce = $sourceHandle->read(SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $salt = $sourceHandle->read(SODIUM_CRYPTO_STREAM_KEYBYTES);

        // split our key into authentication and encryption keys
        [$encKey, $authKey] = $this->key->hkdfSplit($salt);

        $written = $this->decryptFileStream(
            $sourceHandle, $destinationHandle,
            [['value' => $nonce], ['value' => $salt]],
            $authKey, $encKey,
            $nonce
        );

        // free handles
        $sourceHandle = null;
        $destinationHandle = null;

        return $written;
    }
}
