# Crypto

This library wrapps the PHP 7 libsodium cryptographic functions into a object-orientated api, allowing a simple and safe usage.

This library supports:

-   symmetric authenticated en/decryption
-   asymmetric authenticated en/decryption
-   cryptographic secure key/keypair generation
-   Diffie Hellman key-derivation for keypairs for keyexchanges

## Installation

```shell
composer require ricwein/crypto
```

All classes uses the root-namespace `ricwein\Crypto`. All thrown Exceptions extend from `ricwein\Crypto\Exceptions\Exception`.

## Symmetric Crypto

Symmetric cryptography uses a secret (key) to encrypt a given message to a ciphertext, and the same secret to decrypt the ciphertext to the original message again.

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
    $ciphertext = Ciphertext::fromString(file_get_contents(__DIR__ . '/message'), Encoding::HEX);
    $key = new Key(file_get_contents(__DIR__ . '/key'), Encoding::RAW);

    // actual decryption
    $plaintext = (new Crypto($key))->decrypt($ciphertext);

} catch (MacMismatchException $e) {

    // unable to decrypt message, invalid HMAC

} catch (Exception $e) {

    // something else went wrong

}
```

## Asymmetric Crypto

Asymmetric Crypto uses keypairs out of a public and a private key to encrypt and signate messages.

**sending:** Usually a Message is encrypted with the public-key of the receiver, and signated with the private-key of the sender.

**receiving:** The receiver is than able to verify the message-signature ((H)MAC) with the public-key of the sender and can decrypt it with it's own private-key.

> The following example uses two keypairs (alice and bob) with known private-keys in the same code-scope. This is just done for comprehensibility. In real-world cases on side only knowns it's own private-key (public is not required) and the public-key of the other participant.

### encrypt

```php
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\Exception;

try {
    $message = 'asecretmessage';
    $keyAlice = (new KeyPair())->keygen();
    $keyBob = (new KeyPair())->keygen();

    // send message from alice to bob
    $ciphertext = (new Crypto($keyAlice))->encrypt($message, $keyBob->getKey(KeyPair::PUB_KEY));

    // it's enough to store the private-keys of our keypairs, public-keys can be derived later if required
    file_put_contents(__DIR__ . '/alice.key', $keyAlice->getKey(KeyPair::PRIV_KEY, Encoding::RAW));
    file_put_contents(__DIR__ . '/bob.key', $keyBob->getKey(KeyPair::PRIV_KEY, Encoding::RAW));
    file_put_contents(__DIR__ . '/message', $ciphertext->getString(Encoding::BASE64URL));

} catch (Exception $e) {

    // something went wrong

}
```

### decrypt

```php
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Encoding;
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\Exception;
use ricwein\Crypto\Exceptions\MacMismatchException;

try {
    $keyAlice = new KeyPair([
        KeyPair::PRIV_KEY => file_get_contents(__DIR__ . '/alice.key')
    ], Encoding::RAW);
    $keyBob = new KeyPair([
        KeyPair::PRIV_KEY => file_get_contents(__DIR__ . '/bob.key')
    ], Encoding::RAW);
    $ciphertext = Ciphertext::fromString(file_get_contents(__DIR__ . '/message'), Encoding::BASE64URL);

    // verfiy and decrypt the ciphertext
    // it's enough to pass alice keypair with only a private key here,
    // the public key will be dynamically derived to verify the ciphertexts HMAC
    // BUT you can also directly pass alice public-key
    $plaintext = (new Crypto($keyBob))->decrypt($ciphertext, $keyAlice);

} catch (MacMismatchException $e) {

    // unable to decrypt message, invalid HMAC for alice

} catch (Exception $e) {

    // something else went wrong

}
```
