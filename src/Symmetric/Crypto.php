<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto\Symmetric;

use Exception;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Helper;
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\FileSystem\Exceptions\ConstraintsException;
use ricwein\FileSystem\Exceptions\Exception as FileSystemException;
use ricwein\FileSystem\Exceptions\FileNotFoundException;
use ricwein\FileSystem\Exceptions\RuntimeException;
use ricwein\FileSystem\Exceptions\UnexpectedValueException as FileSystemUnexpectedValueException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;
use ricwein\FileSystem\Exceptions\UnsupportedException;
use ricwein\FileSystem\Exceptions\AccessDeniedException;
use ricwein\FileSystem\Storage\Extensions\Binary;
use SodiumException;
use function array_shift;
use function hash_equals;
use function is_string;
use function random_bytes;
use function sodium_crypto_generichash_final;
use function sodium_crypto_generichash_init;
use function sodium_crypto_generichash_update;
use function sodium_crypto_stream_xor;
use function sodium_increment;
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

    /**
     * @var int
     */
    public const FILE_BUFFER = 1048576; // == 1024^2 == 2^20

    /**
     * @inheritDoc
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
     * @inheritDoc
     * @param Ciphertext $ciphertext
     * @return string
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
        unset($ciphertext);

        if (!is_string($plaintext)) {
            throw new MacMismatchException('Invalid message authentication code', 400);
        }

        return $plaintext;
    }

    /**
     * @param Storage $source source-storage
     * @param File|Storage|null $destination given destination
     * @return File
     * @throws AccessDeniedException
     * @throws UnsupportedException
     * @throws ConstraintsException
     * @throws FileSystemException
     * @throws RuntimeException
     * @throws FileSystemUnexpectedValueException
     */
    protected function prepareDestination(Storage $source, $destination = null): File
    {
        // en/decryping the current file requires a temp-destination,
        // which is later used to overwrite our original source
        if ($destination === null && $source instanceof Storage\Disk) {
            $destination = new File(new Storage\Disk\Temp());
        } elseif ($destination === null && $source instanceof Storage\Memory) {
            $destination = new File(new Storage\Memory());
        } elseif ($destination instanceof Storage) {
            $destination = new File($destination);
        }

        if (!$destination instanceof File) {
            throw new UnsupportedException(sprintf('unable to use file-base cryptography for the given destination-storage \'%s\'', get_class($destination)), 400);
        }

        if ($destination->isFile() && !$destination->isWriteable()) {
            throw new AccessDeniedException('unable to write to destination', 500);
        }

        if (!$destination->isFile() && !$destination->touch(true)) {
            throw new AccessDeniedException('unable to create destination file', 500);
        }

        return $destination;
    }

    /**
     * @inheritDoc
     * @param File $source
     * @param null $destination
     * @return File
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
     */
    public function encryptFile(File $source, $destination = null): File
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
     * @param File $source
     * @param File $destination
     * @return int bytes written
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws FileNotFoundException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
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

        // fetch initial file-hash from source-file
        $initHash = $source->getHash();

        // open locking file-handles
        $sourceHandle = $source->getHandle(Binary::MODE_READ);
        $destinationHandle = $destination->getHandle(Binary::MODE_WRITE);

        // write file-header
        $destinationHandle->write($nonce, SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $destinationHandle->write($salt, SODIUM_CRYPTO_STREAM_KEYBYTES);

        // calculate initial mac
        $mac = sodium_crypto_generichash_init($authKey);
        sodium_crypto_generichash_update($mac, $nonce);
        sodium_crypto_generichash_update($mac, $salt);

        sodium_memzero($authKey);
        sodium_memzero($salt);

        // fetch initial stats from source-file
        $size = $sourceHandle->getSize();
        $written = 0;

        // begin the streaming encryption
        while ($sourceHandle->remainingBytes() > 0) {

            // prevent overflow
            if (($sourceHandle->getPos() + self::FILE_BUFFER) > $size) {
                $readBytes = $size - $sourceHandle->getPos();
            } else {
                $readBytes = self::FILE_BUFFER;
            }

            $read = $sourceHandle->read($readBytes);
            $encrypted = sodium_crypto_stream_xor($read, $nonce, $encKey);

            sodium_crypto_generichash_update($mac, $encrypted);
            $written += $destinationHandle->write($encrypted);

            sodium_increment($nonce);
        }

        sodium_memzero($encKey);
        sodium_memzero($nonce);

        // Check that our input file was not modified before we MAC it
        if (!hash_equals($source->getHash(), $initHash)) {
            throw new MacMismatchException('read-only file has been modified since it was opened for reading', 500);
        }

        // finish encryption
        $written += $destinationHandle->write(
            sodium_crypto_generichash_final($mac, SODIUM_CRYPTO_GENERICHASH_KEYBYTES),
            SODIUM_CRYPTO_GENERICHASH_KEYBYTES
        );

        // free handles
        $sourceHandle = null;
        $destinationHandle = null;

        return $written;
    }

    /**
     * @inheritDoc
     * @param File $source
     * @param null $destination
     * @return File
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
    public function decryptFile(File $source, $destination = null): File
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
     * @param File $source
     * @param File $destination
     * @return int bytes written
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws FileNotFoundException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     * @throws SodiumException
     */
    protected function streamDecryptFile(File $source, File $destination): int
    {
        // open locking file-handles
        $sourceHandle = $source->getHandle(Binary::MODE_READ);
        $destinationHandle = $destination->getHandle(Binary::MODE_WRITE);

        $sourceHandle->seek();

        // read file-header from encrypted file
        $nonce = $sourceHandle->read(SODIUM_CRYPTO_STREAM_NONCEBYTES);
        $salt = $sourceHandle->read(SODIUM_CRYPTO_STREAM_KEYBYTES);

        // split our key into authentication and encryption keys
        [$encKey, $authKey] = $this->key->hkdfSplit($salt);

        $mac = sodium_crypto_generichash_init($authKey);
        sodium_crypto_generichash_update($mac, $nonce);
        sodium_crypto_generichash_update($mac, $salt);

        // verify stream-mac
        $chunkMacs = $this->verifyStreamMac($sourceHandle, $mac);

        sodium_memzero($authKey);
        sodium_memzero($salt);

        // fetch initial stats from source-file
        $cipherEnd = $sourceHandle->getSize() - SODIUM_CRYPTO_GENERICHASH_KEYBYTES;
        $received = 0;

        // decrypt stream
        while ($sourceHandle->remainingBytes() > SODIUM_CRYPTO_GENERICHASH_KEYBYTES) {

            // prevent overflow
            if (($sourceHandle->getPos() + self::FILE_BUFFER) > $cipherEnd) {
                $readBytes = $cipherEnd - $sourceHandle->getPos();
            } else {
                $readBytes = self::FILE_BUFFER;
            }

            $read = $sourceHandle->read($readBytes);

            sodium_crypto_generichash_update($mac, $read);
            $calcMAC = Helper::safeStrcpy($mac);
            $calc = sodium_crypto_generichash_final($calcMAC, SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

            // someone attempted to add a chunk at the end.
            if (empty($chunkMacs)) {
                throw new MacMismatchException('Invalid message authentication code', 400);
            }

            // this chunk was altered after the original MAC was verified
            $chunkMAC = array_shift($chunkMacs);
            if (!hash_equals($chunkMAC, $calc)) {
                throw new MacMismatchException('Invalid message authentication code', 400);
            }

            // this is where the decryption actually occurs
            $decrypted = sodium_crypto_stream_xor($read, $nonce, $encKey);
            $received += $destinationHandle->write($decrypted);

            sodium_memzero($decrypted);
            sodium_increment($nonce);
        }

        sodium_memzero($encKey);
        sodium_memzero($nonce);

        // free handles
        $sourceHandle = null;
        $destinationHandle = null;

        sodium_memzero($mac);
        unset($chunkMacs);

        return $received;
    }


    /**
     * read chunk-macs from stream
     * @param Binary $sourceHandle
     * @param string $mac
     * @return array
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws SodiumException
     */
    private function verifyStreamMac(Binary $sourceHandle, string $mac): array
    {
        $start = $sourceHandle->getPos();

        // fetch hmac
        $cipherEnd = $sourceHandle->getSize() - SODIUM_CRYPTO_GENERICHASH_KEYBYTES;
        $sourceHandle->seek($cipherEnd);
        $storedMac = $sourceHandle->read(SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
        $sourceHandle->seek($start);

        $chunkMACs = [];

        $break = false;

        while (!$break && $sourceHandle->getPos() < $cipherEnd) {

            // Would a full file-buffer read put it past the end of the
            // ciphertext? If so, only return a portion of the file
            if (($sourceHandle->getPos() + self::FILE_BUFFER) >= $cipherEnd) {
                $break = true;
                $read = $sourceHandle->read($cipherEnd - $sourceHandle->getPos());
            } else {
                $read = $sourceHandle->read(self::FILE_BUFFER);
            }

            // We're updating our HMAC and nothing else
            sodium_crypto_generichash_update($mac, $read);

            // Copy the hash state then store the MAC of this chunk
            /** @var string $chunkMAC */
            $chunkMAC = Helper::safeStrcpy($mac);
            $chunkMACs[] = sodium_crypto_generichash_final($chunkMAC, SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
        }

        /**
         * We should now have enough data to generate an identical MAC
         */
        $finalHMAC = sodium_crypto_generichash_final($mac, SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

        /**
         * Use hash_equals() to be timing-invariant
         */
        if (!hash_equals($finalHMAC, $storedMac)) {
            throw new MacMismatchException('Invalid message authentication code', 400);
        }

        $sourceHandle->seek($start);
        return $chunkMACs;
    }
}
