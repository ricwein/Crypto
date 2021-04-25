<?php

namespace ricwein\Crypto;

use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\FileSystem\Exceptions\AccessDeniedException;
use ricwein\FileSystem\Exceptions\ConstraintsException;
use ricwein\FileSystem\Exceptions\Exception as FileSystemException;
use ricwein\FileSystem\Exceptions\FileNotFoundException;
use ricwein\FileSystem\Exceptions\RuntimeException as FileSystemRuntimeException;
use ricwein\FileSystem\Exceptions\UnexpectedValueException as FileSystemUnexpectedValueException;
use ricwein\FileSystem\Exceptions\UnsupportedException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;
use ricwein\FileSystem\Storage\Extensions\Binary as BinaryFileHandle;
use SodiumException;
use function array_shift;
use function is_string;
use function hash_equals;
use function sodium_crypto_generichash_final;
use function sodium_crypto_generichash_init;
use function sodium_crypto_generichash_update;
use function sodium_crypto_stream_xor;
use function sodium_increment;
use function sodium_memzero;
use const SODIUM_CRYPTO_GENERICHASH_KEYBYTES;

abstract class Crypto
{
    protected const MAC_BYTES = SODIUM_CRYPTO_GENERICHASH_KEYBYTES;

    public const FILE_BUFFER = 1048576; // == 1024^2 == 2^20

    abstract public function getKey(): Key;

    abstract public function encrypt(string $plaintext): Ciphertext;

    abstract public function decrypt(Ciphertext $ciphertext): string;

    abstract public function encryptFile(File $source, Storage|File $destination = null): File;

    abstract public function decryptFile(File $source, Storage|File $destination = null): File;

    /**
     * @param Storage $source
     * @param File|Storage|null $destination
     * @return File
     * @throws AccessDeniedException
     * @throws UnsupportedException
     * @throws ConstraintsException
     * @throws FileSystemException
     */
    protected function prepareDestination(Storage $source, File|Storage $destination = null): File
    {
        // en/decrypting the current file requires a temp-destination,
        // which is later used to overwrite our original source
        if ($destination === null && $source instanceof Storage\Disk) {
            $destination = new File(new Storage\Disk\Temp());
        } elseif ($destination === null && $source instanceof Storage\Memory) {
            $destination = new File(new Storage\Memory());
        } elseif ($destination instanceof Storage) {
            $destination = new File($destination);
        }

        if (!$destination instanceof File) {
            throw new UnsupportedException(sprintf('Unable to use file-base cryptography for the given destination-storage: \'%s\'', get_class($destination)), 400);
        }

        if ($destination->isFile() && !$destination->isWriteable()) {
            throw new AccessDeniedException('Unable to write to destination.', 500);
        }

        if (!$destination->isFile() && !$destination->touch(true)) {
            throw new AccessDeniedException('Unable to write to destination file.', 500);
        }

        return $destination;
    }

    /**
     * @param File $source
     * @param File $destination
     * @param array $headers
     * @param string $authKey
     * @param string $encKey
     * @param string $nonce
     * @return int
     * @throws ConstraintsException
     * @throws MacMismatchException
     * @throws UnsupportedException
     * @throws SodiumException
     * @throws FileNotFoundException
     * @throws FileSystemRuntimeException
     * @throws FileSystemUnexpectedValueException
     */
    protected function encryptFileStream(
        File $source, File $destination,
        array $headers,
        string $authKey, string $encKey,
        string $nonce
    ): int
    {
        // fetch initial file-hash from source-file
        $initHash = $source->getHash();

        // open locking file-handles
        $sourceHandle = $source->getHandle(BinaryFileHandle::MODE_READ);
        $destinationHandle = $destination->getHandle(BinaryFileHandle::MODE_WRITE);

        $mac = sodium_crypto_generichash_init($authKey);

        // write file-header and calculate initial mac
        foreach ($headers as $header) {
            $destinationHandle->write($header['value'], (int)$header['length']);
            sodium_crypto_generichash_update($mac, $header['value']);
        }

        sodium_memzero($authKey);

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
            sodium_crypto_generichash_final($mac, static::MAC_BYTES),
            static::MAC_BYTES
        );

        // free handles
        $sourceHandle = null;
        $destinationHandle = null;

        return $written;
    }

    /**
     * @throws FileSystemRuntimeException
     * @throws MacMismatchException
     * @throws SodiumException
     */
    protected function decryptFileStream(
        BinaryFileHandle $sourceHandle, BinaryFileHandle $destinationHandle,
        array $headers,
        string $authKey, string $encKey,
        string $nonce
    ): int
    {
        $mac = sodium_crypto_generichash_init($authKey);
        sodium_memzero($authKey);

        foreach ($headers as $header) {
            sodium_crypto_generichash_update($mac, $header['value']);
            if (is_string($header['value'])) {
                sodium_memzero($header['value']);
            } else {
                unset($header['value']);
            }
        }

        // verify stream-mac
        $chunkMacs = $this->verifyStreamMac($sourceHandle, $mac);

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

        sodium_memzero($mac);
        unset($chunkMacs);

        return $received;
    }

    /**
     * read chunk-macs from stream
     * @throws MacMismatchException
     * @throws FileSystemRuntimeException
     * @throws SodiumException
     */
    private function verifyStreamMac(BinaryFileHandle $sourceHandle, string $mac): array
    {
        $start = $sourceHandle->getPos();

        // fetch hmac
        $cipherEnd = $sourceHandle->getSize() - static::MAC_BYTES;
        $sourceHandle->seek($cipherEnd);
        $storedMac = $sourceHandle->read(static::MAC_BYTES);
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
            $chunkMACs[] = sodium_crypto_generichash_final($chunkMAC, static::MAC_BYTES);
        }

        /**
         * We should now have enough data to generate an identical MAC
         */
        $finalHMAC = sodium_crypto_generichash_final($mac, static::MAC_BYTES);

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
