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
     * @inheritDoc
     */
    public function encrypt(string $plaintext, $pubKey = null): Ciphertext
    {
        // derive ephemeral public-private encryption keypair
        $encKeyPair = $this->deriveKeyPair($pubKey);

        // create a symmetric secret from KeyPair per Diffie-Hellman KeyExchange
        $symmetricCrypto = new SymmetricCrypto($encKeyPair->getSharedSecret());

        // use symmetric authenticated encryption to encryt and sign the given message
        return $symmetricCrypto->encrypt($plaintext);
    }

    /**
     * @inheritDoc
     */
    public function decrypt(Ciphertext $ciphertext, $pubKey = null): string
    {
        // derive ephemeral public-private encryption keypair
        $encKeyPair = $this->deriveKeyPair($pubKey);

        // create a symmetric secret from KeyPair per Diffie-Hellman KeyExchange
        $symmetricCrypto = new SymmetricCrypto($encKeyPair->getSharedSecret());

        // use symmetric authenticated encryption to decryt and validate (HMAC) the given message
        return $symmetricCrypto->decrypt($ciphertext);
    }

    /**
     * @inheritDoc
     */
    public function encryptFile(File $source, $destination = null, $pubKey = null): File
    {
        // derive ephemeral public-private encryption keypair
        $encKeyPair = $this->deriveKeyPair($pubKey);

        // create a symmetric secret from KeyPair per Diffie-Hellman KeyExchange
        $symmetricCrypto = new SymmetricCrypto($encKeyPair->getSharedSecret());

        // use symmetric authenticated encryption to encryt and sign the given file
        return $symmetricCrypto->encryptFile($source, $destination);
    }
    /**
     * @inheritDoc
     */
    public function decryptFile(File $source, $destination = null, $pubKey = null): File
    {
        // derive ephemeral public-private encryption keypair
        $encKeyPair = $this->deriveKeyPair($pubKey);

        // create a symmetric secret from KeyPair per Diffie-Hellman KeyExchange
        $symmetricCrypto = new SymmetricCrypto($encKeyPair->getSharedSecret());

        // use symmetric authenticated encryption to encryt and sign the given file
        return $symmetricCrypto->decryptFile($source, $destination);
    }
}
