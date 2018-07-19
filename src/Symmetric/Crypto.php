<?php
/**
 * @author Richard Weinhold
 */
namespace ricwein\Crypto\Symmetric;

use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Exceptions\KeyMismatchException;
use ricwein\Crypto\Exceptions\MacMismatchException;

/**
 * asymmetric Crypto using libsodium
 */
class Crypto extends CryptoBase
{

    /**
    * @inheritDoc
     */
    public function encrypt(string $plaintext): Ciphertext
    {
        try {

            // generate nonce and HKDF salt
            $nonce = \random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $salt  = \random_bytes(\SODIUM_CRYPTO_GENERICHASH_KEYBYTES);

            // split shared secret into authentication and encryption keys
            list($encKey, $authKey) = $this->key->hkdfSplit($salt);

            /**
             * encrypt actual plaintext (XSalsa20)
             * @see https://download.libsodium.org/doc/advanced/xsalsa20.html
             */
            $encrypted = \sodium_crypto_stream_xor($plaintext, $nonce, $encKey);
            \sodium_memzero($encKey);

            $ciphertext = new Ciphertext($encrypted, $salt, $nonce);
            $ciphertext->setAuthKey($authKey);

            \sodium_memzero($encrypted);
            \sodium_memzero($salt);
            \sodium_memzero($nonce);
            \sodium_memzero($authKey);

            // save used cipher algorithm for later
            $ciphertext->setCipher('xsalsa20');

            return $ciphertext;
        } catch (\Exception $exception) {
            throw new KeyMismatchException('invalid security key', 500, $exception);
        }
    }

    /**
     * @inheritDoc
     */
    public function decrypt(Ciphertext $ciphertext): string
    {

        // split shared secret into authentication and encryption keys
        list($encKey, $authKey) = $this->key->hkdfSplit($ciphertext->getSalt());

        // validate ciphertext mac
        if (!$ciphertext->setAuthKey($authKey)->isValidMac()) {
            throw new MacMismatchException('Invalid message authentication code', 400);
        }

        \sodium_memzero($authKey);

        // decrypt actual ciphertext
        $plaintext = \sodium_crypto_stream_xor($ciphertext->getEncrypted(), $ciphertext->getNonce(), $encKey);
        if (!\is_string($plaintext)) {
            throw new MacMismatchException('Invalid message authentication code', 400);
        }

        \sodium_memzero($encKey);
        unset($ciphertext);

        return $plaintext;
    }
}
