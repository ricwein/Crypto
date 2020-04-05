<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto;

use ricwein\Crypto\Exceptions\InvalidArgumentException;
use ricwein\Crypto\Exceptions\UnexpectedValueException;
use function chr;
use function is_string;
use function mb_substr;
use function sodium_crypto_generichash;
use function str_repeat;
use const SODIUM_CRYPTO_GENERICHASH_BYTES;
use const SODIUM_CRYPTO_GENERICHASH_KEYBYTES;

/**
 * provides static helper-methods
 */
final class Helper
{
    /**
     * PHP 7 uses interned strings.
     * We don't want to alter the original string.
     *
     * @param string|null $string
     * @return string|null
     */
    public static function safeStrcpy(?string $string = null): ?string
    {
        if ($string === null) {
            return null;
        }

        $length = mb_strlen($string, '8bit');
        $return = '';

        /** @var int $chunk */
        $chunk = $length >> 1;

        for ($i = 0; $i < $length; $i += $chunk) {
            $return .= mb_substr($string, $i, $chunk, '8bit');
        }

        return $return;
    }

    /**
     * @see https://github.com/paragonie/halite/blob/master/src/Util.php
     * @param string $ikm Initial Keying Material
     * @param int $length How many bytes?
     * @param string $info What sort of key are we deriving?
     * @param string|null $salt
     * @return string
     * @throws UnexpectedValueException|InvalidArgumentException
     */
    public static function hkdfBlake2b(string $ikm, int $length, string $info = '', ?string $salt = null): string
    {

        // Sanity-check the desired output length.
        if ($length < 0 || $length > (255 * SODIUM_CRYPTO_GENERICHASH_KEYBYTES)) {
            throw new InvalidArgumentException('bad HKDF digest length', 500);
        }

        // "If [salt] not provided, is set to a string of HashLen zeroes."
        if (empty($salt)) {
            $salt = str_repeat("\x00", SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = sodium_crypto_generichash($ikm, $salt, SODIUM_CRYPTO_GENERICHASH_BYTES);

        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        if (mb_strlen($prk, '8bit') < SODIUM_CRYPTO_GENERICHASH_KEYBYTES) {
            throw new UnexpectedValueException('An unknown error has occurred', 500);
        }

        // T(0) = ''
        $t = '';
        $lastBlock = '';
        for ($blockIndex = 1; mb_strlen($t, '8bit') < $length; ++$blockIndex) {

            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $lastBlock = sodium_crypto_generichash($lastBlock . $info . chr($blockIndex), $prk, SODIUM_CRYPTO_GENERICHASH_BYTES);

            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $lastBlock;
        }

        // ORM = first L octets of T
        /** @var string $orm */
        $orm = mb_substr($t, 0, $length, '8bit');

        if (!is_string($orm)) {
            throw new UnexpectedValueException('An unknown error has occurred', 500);
        }

        return $orm;
    }
}
