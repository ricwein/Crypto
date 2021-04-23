# Crypto

This library wraps the PHP libsodium cryptographic functions into an object-orientated api, allowing a simple and safe usage.

This library provides:

- symmetric and asymmetric authenticated en/decryption of messages and files using **XSalsa20**
- cryptographic secure key and keypair generation
- Diffie Hellman key-exchange for keypairs using Curve25519 (**X25519**)
- ex/import of keys and ciphertexts with support for most common encodings

# Installation

```shell
composer require ricwein/crypto
```

All classes uses the root-namespace `ricwein\Crypto`. All thrown Exceptions extend from `ricwein\Crypto\Exceptions\Exception`.

## Symmetric Crypto

Symmetric cryptography uses a secret (key) to encrypt a given message to a ciphertext, and the same secret to decrypt the ciphertext to the original message again.

### encrypt

```php
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Exceptions\Exception as CryptoException;

try {
    $message = 'asecretmessage';
    $key = Key::generate();

    // actual encryption
    $ciphertext = (new Crypto($key))->encrypt($message);

    // now we can use the resulting key and ciphertext, e.g. safe them to the filesystem
    file_put_contents(__DIR__ . '/key', $key->getKey());
    file_put_contents(__DIR__ . '/message', $ciphertext->getString());

} catch (CryptoException $e) {
    // something went wrong
}
```

### decrypt

```php
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Exceptions\Exception as CryptoException;
use ricwein\Crypto\Exceptions\MacMismatchException;

try {
    $ciphertext = Ciphertext::fromString(file_get_contents(__DIR__ . '/message'));
    $key = Key::load(file_get_contents(__DIR__ . '/key'));

    // actual decryption
    $plaintext = (new Crypto($key))->decrypt($ciphertext);

} catch (MacMismatchException $e) {
    // unable to decrypt message, invalid HMAC
} catch (CryptoException $e) {
    // something else went wrong
}
```

## Asymmetric Crypto

Asymmetric Crypto uses keypairs out of a public, and a private key to encrypt and sign messages.

**sending:** Usually a Message is encrypted with the public-key of the receiver, and signed with the private-key of the sender.

**receiving:** The receiver is than able to verify the message-signature ((H)MAC) with the public-key of the sender and can decrypt it with its own private-key.

> The following example uses two keypairs (alice and bob) with known private-keys in the same code-scope. This is just done for comprehensibility. In real-world cases on side only knowns it's own private-key (public is not required) and the public-key of the other participant.

### encrypt

```php
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\Exception as CryptoException;

try {
    $message = 'asecretmessage';
    $keyAlice = KeyPair::generate();
    $keyBob = KeyPair::generate();

    // send message from alice to bob
    $ciphertext = (new Crypto($keyAlice))->encrypt($message, $keyBob->getKey(KeyPair::PUB_KEY));

    // it's enough to store the private-keys of our keypairs, public-keys can be derived later if required
    file_put_contents(__DIR__ . '/alice.key', $keyAlice->getKey(KeyPair::PRIV_KEY));
    file_put_contents(__DIR__ . '/bob.key', $keyBob->getKey(KeyPair::PRIV_KEY));
    file_put_contents(__DIR__ . '/message', $ciphertext->getString());

} catch (CryptoException $e) {
    // something went wrong
}
```

### decrypt

```php
use ricwein\Crypto\Ciphertext;
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\Exception as CryptoException;
use ricwein\Crypto\Exceptions\MacMismatchException;

try {
    $keyAlice = KeyPair::load([
        KeyPair::PRIV_KEY => file_get_contents(__DIR__ . '/alice.key')
    ]);
    $keyBob = KeyPair::load([
        KeyPair::PRIV_KEY => file_get_contents(__DIR__ . '/bob.key')
    ]);
    $ciphertext = Ciphertext::fromString(file_get_contents(__DIR__ . '/message'));

    // verify and decrypt the ciphertext
    // it's enough to pass alice keypair with only a private key here,
    // the public key will be dynamically derived to verify the ciphertexts HMAC
    // BUT you can also directly pass alice public-key
    $plaintext = (new Crypto($keyBob))->decrypt($ciphertext, $keyAlice);

} catch (MacMismatchException $e) {
    // unable to decrypt message, invalid HMAC for alice
} catch (CryptoException $e) {
    // something else went wrong
}
```

# Encoding

Key-ex/import and ciphertext ex/import supports four types of encoding, provided by `ricwein\Crypto\Encoding`.

# File-Crypto

This library also provides RAM-friendly file-en/decrypting using stream-encryption. To use the integrated file-crypto, the `ricwein/filesystem` library is required. It can be installed with:

```shell
composer require ricwein/filesystem
```

The usage is the same as the sym/asymmetric en/decryption methods, but instead of encrypting strings into ciphertexts-objects, a File will be encrypted, returning a new File-Object.

Most times it's useful to encrypt a file and replace it's plaintext with the new ciphertext. It should be noted, that this library creates a temp-file in this case, encrypts the sourcefile into the new temp-file, and replaces the source
afterwards with the temp-file.

All file-crypto methods support custom destination storages, which can be provided as the last parameter in `encryptFile()` and `decryptFile()`. If a storage is given, the previously described encryption through a temp-file is skipped.

## Symmetric Crypto

### encrypt

```php
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Exceptions\Exception as CryptoException;
use ricwein\FileSystem\Exceptions\Exception as FileException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;

try {
    $file = new File(new Storage\Disk(__DIR__, 'file.txt'));
    $key = Key::generate();

    // actual encryption
    $encryptedFile = (new Crypto($key))->encryptFile($file);
    file_put_contents(__DIR__ . '/key', $key->getKey());

} catch (FileException $e) {
    // unable to open, read or write the file
} catch (CryptoException $e) {
    // something went wrong
}
```

### decrypt

```php
use ricwein\Crypto\Symmetric\Crypto;
use ricwein\Crypto\Symmetric\Key;
use ricwein\Crypto\Exceptions\Exception as CryptoException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\FileSystem\Exceptions\Exception as FileException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;

try {
    $encryptedFile = new File(new Storage\Disk(__DIR__, 'file.txt'));
    $key = Key::load(file_get_contents(__DIR__ . '/key'));

    // actual decryption
    $file = (new Crypto($key))->decryptFile($encryptedFile);

} catch (MacMismatchException $e) {
    // unable to decrypt message, invalid HMAC
} catch (FileException $e) {
    // unable to open, read or write the file
} catch (CryptoException $e) {
    // something else went wrong
}
```

## Asymmetric Crypto

> The following example uses two keypairs (alice and bob) with known private-keys in the same code-scope. This is just done for comprehensibility. In real-world cases, one side only knows its own private-key (public is not required) and the public-key of the other participant.

### encrypt

```php
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\Exception as CryptoException;
use ricwein\FileSystem\Exceptions\Exception as FileException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;

try {
    $file = new File(new Storage\Disk(__DIR__, 'file.txt'));
    $keyAlice = KeyPair::generate();
    $keyBob = KeyPair::generate();
    
    $plainTextFile = new File(new Storage\Disk(__DIR__, 'file.txt'));

    // send message from alice to bob
    $encryptedFile = (new Crypto($keyAlice))->encryptFile($plainTextFile, null, $keyBob);

    // it's enough to store the private-keys of our keypairs, public-keys can be derived later if required
    file_put_contents(__DIR__ . '/alice.key', $keyAlice->getKey(KeyPair::PRIV_KEY));
    file_put_contents(__DIR__ . '/bob.key', $keyBob->getKey(KeyPair::PRIV_KEY));

} catch (FileException $e) {
    // unable to open, read or write the file
} catch (CryptoException $e) {
    // something went wrong
}
```

### decrypt

```php
use ricwein\Crypto\Asymmetric\Crypto;
use ricwein\Crypto\Asymmetric\KeyPair;
use ricwein\Crypto\Exceptions\Exception as CryptoException;
use ricwein\Crypto\Exceptions\MacMismatchException;
use ricwein\FileSystem\Exceptions\Exception as FileException;
use ricwein\FileSystem\File;
use ricwein\FileSystem\Storage;

try {
    $keyAlice = KeyPair::load([
        KeyPair::PRIV_KEY => file_get_contents(__DIR__ . '/alice.key')
    ]);
    $keyBob = KeyPair::load([
        KeyPair::PRIV_KEY => file_get_contents(__DIR__ . '/bob.key')
    ]);
    
    $encryptedFile = new File(new Storage\Disk(__DIR__, 'file.txt'));
    
    $file = (new Crypto($keyBob))->decryptFile($encryptedFile, null, $keyAlice);

} catch (MacMismatchException $e) {
    // unable to decrypt message, invalid HMAC for alice
} catch (FileException $e) {
    // unable to open, read or write the file
} catch (CryptoException $e) {
    // something else went wrong
}
```
