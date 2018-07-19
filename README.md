# Crypto

This library wrapps the PHP 7 libsodium cryptographic functions into a object-orientated api, allowing a simple and safe usage.

This library supports:
 - symmetric authenticated en/decryption
 - asymmetric authenticated en/decryption
 - cryptographic secure key/keypair generation
 - Diffie Hellman key-derivation for keypairs for keyexchanges

## Installation

```shell
composer require ricwein/crypto
```

All classes uses the root-namespace `ricwein\Crypto`. All thrown Exceptions extend from `ricwein\Crypto\Exceptions\Exception`.

## Symmetric Crypto

A File is represented as a `File` Object and a Directory as a `Directory` Object.

### encrypt

```php
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Exceptions\Exception;

try {
    $message = 'asecretmessage';
    $key = (new Key())->keygen();

    // actual encryption
    $ciphertext = (new Crypto($key))->encrypt($message);

    // now we can use the resulting key and ciphertext, e.g. safe them to the filesystem
    file_put_contents(__DIR__ . '/key', $key->getKey(Encoding::RAW));
    file_put_contents(__DIR__ . '/message', $ciphertext->getString(Encoding::HEX));

} catch (Exception $e) {

    // something went wrong

}
```

### decrypt

```php
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Exceptions\Exception;
use ricwein\Crypto\Exceptions\MacMismatchException;

try {
    $ciphertext = Ciphertext::fromString(file_get_contents(__DIR__ . 'message'), Encoding::HEX);
    $key = new Key(file_get_contents(__DIR__ . 'key'), Encoding::RAW);

    // actual decryption
    $plaintext = (new Crypto($key))->decrypt($ciphertext);

} catch (MacMismatchException $e) {

    // unable to decrypt message, invalid HMAC

} catch (Exception $e) {

    // something else went wrong

}
```
