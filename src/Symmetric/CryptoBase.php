<?php
/**
 * @author Richard Weinhold
 */
namespace ricwein\Crypto\Symmetric;

use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;

/**
 * crypto-base for symmetric key handling
 */
abstract class CryptoBase
{

    /**
     * @var Key|null
     */
    protected $key = null;

    /**
     * @param Key|null $key
     */
    public function __construct(Key $key = null)
    {
        if ($key !== null) {
            $this->key = $key;
        }
    }

    /**
     * wipe it from memory after it's been used
     */
    public function __destruct()
    {
        unset($this->key);
    }

    /**
     * @return Key|null
     */
    public function getKey(): ?Key
    {
        return $this->key;
    }

    /**
     * @param  Key  $key
     * @return self
     */
    public function loadKey(Key $key): self
    {
        $this->key = $key;
        return $this;
    }

    /**
     * encrypt plaintext with libsodium authenticated asymmetric crypto
     * @param  string $plaintext
     * @throws KeyMismatchException
     * @return Ciphertext
     */
    abstract public function encrypt(string $plaintext): Ciphertext;

    /**
     * decrypt ciphertext with libsodium authenticated asymmetric crypto
     * @param  Ciphertext $ciphertext
     * @throws MacMismatchException
     * @return string
     */
    abstract public function decrypt(Ciphertext $ciphertext): string;

    /**
     * symmetric File encryption using libsodium
     * @param  File              $source
     * @param  Storage|File|null $destination
     * @return File
     */
    abstract public function encryptFile(File $source, $destination = null): File;

    /**
     * symmetric File decryption using libsodium
     * @param  File              $source
     * @param  Storage|File|null $destination
     * @return File
     */
    abstract public function decryptFile(File $source, $destination = null): File;
}
