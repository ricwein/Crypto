<?php
/**
 * @author Richard Weinhold
 */
namespace ricwein\Crypto;

use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ricwein\Crypto\Exceptions\EncodingException;

/**
 * provides timesafe en/decoding methods for sodium-crypto functions
 */
class Encoding
{
    /**
     * @var string
     */
    const RAW = 'raw';

    /**
     * @var string
     */
    const HEX = 'hex';

    /**
     * @var string
     */
    const BASE64 = 'base64';

    /**
     * @var string
     */
    const BASE64URLSAFE = 'base64urlsafe';

    /**
     * @param  string $message
     * @param  string $encoding
     * @return string
     * @throws EncodingException
     */
    public static function encode(string $message, string $encoding): string
    {
        switch ($encoding) {
            case self::RAW: return $message;
            case self::HEX: return \sodium_bin2hex($message);
            case self::BASE64: return Base64::encode($message);
            case self::BASE64URLSAFE: return Base64UrlSafe::encode($message);
            default: throw new EncodingException(sprintf('Unknown encoding: \'%s\'', $encoding), 500);
        }
    }

    /**
     * @param  string $message
     * @param  string $encoding
     * @return string
     * @throws EncodingException
     */
    public static function decode(string $message, string $encoding): string
    {
        switch ($encoding) {
            case self::RAW: return $message;
            case self::HEX: return \sodium_hex2bin($message);
            case self::BASE64: return Base64::decode($message);
            case self::BASE64URLSAFE: return Base64UrlSafe::decode($message);
            default: throw new EncodingException(sprintf('Unknown encoding: \'%s\'', $encoding), 500);
        }
    }

    /**
     * @param  string $message
     * @param  string $fromEncoding
     * @param  string $toEncoding
     * @return string
     * @throws EncodingException
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
