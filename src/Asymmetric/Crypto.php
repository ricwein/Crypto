<?php
/**
 * @author Richard Weinhold
 */
namespace ricwein\Crypto\Asymmetric;

use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Symmetric\Crypto as SymmetricCrypto;
use ricwein\FileSystem\File;

/**
 * asymmetric Crypto using libsodium
 */
class Crypto extends CryptoBase
{
    /**
     * @param  string|KeyPair|null $pubKey
     * @return SymmetricCrypto
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
     */
    public function encrypt(string $plaintext, $pubKey = null): Ciphertext
    {
        // use symmetric authenticated encryption to encryt and sign the given message
        return $this->deriveSymmetricCrypto($pubKey)->encrypt($plaintext);
    }

    /**
     * @inheritDoc
     */
    public function decrypt(Ciphertext $ciphertext, $pubKey = null): string
    {
        // use symmetric authenticated encryption to decryt and validate (HMAC) the given message
        return $this->deriveSymmetricCrypto($pubKey)->decrypt($ciphertext);
    }

    /**
     * @inheritDoc
     */
    public function encryptFile(File $source, $destination = null, $pubKey = null): File
    {
        // use symmetric authenticated encryption to encryt and sign the given file
        return $this->deriveSymmetricCrypto($pubKey)->encryptFile($source, $destination);
    }
    /**
     * @inheritDoc
     */
    public function decryptFile(File $source, $destination = null, $pubKey = null): File
    {
        // use symmetric authenticated encryption to encryt and sign the given file
        return $this->deriveSymmetricCrypto($pubKey)->decryptFile($source, $destination);
    }
}
