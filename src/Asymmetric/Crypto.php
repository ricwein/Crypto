<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto\Asymmetric;

use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Exceptions\EncodingException;
use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use ricwein\Crypto\Symmetric\Crypto as SymmetricCrypto;
use ricwein\FileSystem\Exceptions\AccessDeniedException;
use ricwein\FileSystem\Exceptions\ConstraintsException;
use ricwein\FileSystem\Exceptions\Exception;
use ricwein\FileSystem\Exceptions\FileNotFoundException;
use ricwein\FileSystem\Exceptions\RuntimeException;
use ricwein\FileSystem\Exceptions\UnexpectedValueException as FileSystemUnexpectedValueException;
use ricwein\FileSystem\Exceptions\UnsupportedException;
use ricwein\FileSystem\File;

/**
 * asymmetric Crypto using libsodium
 */
class Crypto extends CryptoBase
{
    /**
     * @param string|KeyPair|null $pubKey
     * @return SymmetricCrypto
     * @throws EncodingException
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     */
    protected function deriveSymmetricCrypto($pubKey = null): SymmetricCrypto
    {
        // derive ephemeral public-private encryption keypair
        $encKeyPair = $this->deriveKeyPair($pubKey);

        // create a symmetric secret from KeyPair per Diffie-Hellman KeyExchange
        return new SymmetricCrypto($encKeyPair->getSharedSecret());
    }

    /**
     * @inheritDoc
     * @param string $plaintext
     * @param null $pubKey
     * @return Ciphertext
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws KeyMismatchException
     * @throws EncodingException
     */
    public function encrypt(string $plaintext, $pubKey = null): Ciphertext
    {
        // use symmetric authenticated encryption to encryt and sign the given message
        return $this->deriveSymmetricCrypto($pubKey)->encrypt($plaintext);
    }

    /**
     * @inheritDoc
     * @param Ciphertext $ciphertext
     * @param null $pubKey
     * @return string
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     * @throws EncodingException
     * @throws MacMismatchException
     */
    public function decrypt(Ciphertext $ciphertext, $pubKey = null): string
    {
        // use symmetric authenticated encryption to decryt and validate (HMAC) the given message
        return $this->deriveSymmetricCrypto($pubKey)->decrypt($ciphertext);
    }

    /**
     * @inheritDoc
     * @param File $source
     * @param null $destination
     * @param null $pubKey
     * @return File
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws Exception
     * @throws FileNotFoundException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     */
    public function encryptFile(File $source, $destination = null, $pubKey = null): File
    {
        // use symmetric authenticated encryption to encryt and sign the given file
        return $this->deriveSymmetricCrypto($pubKey)->encryptFile($source, $destination);
    }

    /**
     * @inheritDoc
     * @param File $source
     * @param null $destination
     * @param null $pubKey
     * @return File
     * @throws AccessDeniedException
     * @throws ConstraintsException
     * @throws EncodingException
     * @throws Exception
     * @throws FileNotFoundException
     * @throws FileSystemUnexpectedValueException
     * @throws InvalidArgumentException
     * @throws MacMismatchException
     * @throws RuntimeException
     * @throws UnexpectedValueException
     * @throws UnsupportedException
     */
    public function decryptFile(File $source, $destination = null, $pubKey = null): File
    {
        // use symmetric authenticated encryption to encryt and sign the given file
        return $this->deriveSymmetricCrypto($pubKey)->decryptFile($source, $destination);
    }
}
