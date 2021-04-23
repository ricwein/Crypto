<?php
/**
 * @author Richard Weinhold
 */

namespace ricwein\Crypto;

use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ricwein\Crypto\Exceptions\EncodingException;
use SodiumException;
use function sodium_bin2hex;
use function sodium_hex2bin;

/**
 * provides time-safe en/decoding methods for sodium-crypto functions
 */
class Encoding
{
    /**
     * @var string
     */
    public const RAW = 'raw';

    /**
     * @var string
     */
    public const HEX = 'hex';

    /**
     * @var string
     */
    public const BASE64 = 'base64';

    /**
     * @var string
     */
    public const BASE64URLSAFE = 'base64urlsafe';

    /**
     * @param string $message
     * @param string $encoding
     * @return string
     * @throws EncodingException
     * @throws SodiumException
     */
    public static function encode(string $message, string $encoding): string
    {
        return match ($encoding) {
            self::RAW => $message,
            self::HEX => sodium_bin2hex($message),
            self::BASE64 => Base64::encode($message),
            self::BASE64URLSAFE => Base64UrlSafe::encode($message),
            default => throw new EncodingException(sprintf('Unknown encoding: \'%s\'', $encoding), 500),
        };
    }

    /**
     * @param string $message
     * @param string $encoding
     * @return string
     * @throws EncodingException
     * @throws SodiumException
     */
    public static function decode(string $message, string $encoding): string
    {
        return match ($encoding) {
            self::RAW => $message,
            self::HEX => sodium_hex2bin($message),
            self::BASE64 => Base64::decode($message),
            self::BASE64URLSAFE => Base64UrlSafe::decode($message),
            default => throw new EncodingException(sprintf('Unknown encoding: \'%s\'', $encoding), 500),
        };
    }

    /**
     * @param string $message
     * @param string $fromEncoding
     * @param string $toEncoding
     * @return string
     * @throws EncodingException
     * @throws SodiumException
     */
    public static function reencode(string $message, string $fromEncoding, string $toEncoding): string
    {
        if ($fromEncoding === $toEncoding) {
            return $message;
        }

        $decoded = static::decode($message, $fromEncoding);
        return static::encode($decoded, $toEncoding);
    }
}
