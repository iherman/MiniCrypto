_NOT FINAL, DO NOT USE IT FOR CRITICAL APPLICATIONS_

# Simple interface to crypto

This package contains a set of functions that can be used to perform some basic cryptographic functions on top of the 
[WebCrypto API standard](https://www.w3.org/TR/WebCryptoAPI/), without getting into all the intricacies required by 
that API (or other, similar packages). Obviously, some of the more complex options are not available; goal is to provide
an interface to the simplest usages.

The interface functions are as follows.

## Key generation

The functions can be used to generate a private/public (also referred to as secret/public) keys. The package gives an 
option among four different asymmetric cryptographic key types:

1. Elliptic Curve Digital Signature Algorithm (ECDSA)[1]: widely used cryptographic method to sign/verify data. It has 
two "versions": P-256 and P-384[2]. The latter is more secure, but the keys and the signatures are longer. These keys are 
usable for sign and verify.
2. Edwards-Curve Digital Signature Algorithm (EdDSA)[3] (also referred to as Ed25519): more recent than ECDSA, it has a 
somewhat simpler structure. Usable to sign/verify.
3. RSA-PSS: an RSA variant used for sign/verify. The downside is that the keys and signatures are (sometimes significantly)
longer than for EdDSA or ECDSA.
4. RSA-OAEP: RSA variant used for encrypt/decrypt. Note that, in this package, that is the only key that can be used
for encryption and decryption (but cannot be used for sign/verify).

A key pair is either stored as

- (Binary) CryptoKeyPair, i.e., a pair of key stored in the native, binary format of the WebCrypto API implementation.
- [JWKKeyPair](./lib/types.ts/~/JWKeyPair.html), i.e., a pair of key stored in JSON Web Key that conforms to [RFC7517](https://www.rfc-editor.org/rfc/rfc7517). The keys are relatively
large JSON structures; advantage is that they can be managed easily by JSON tools.
- [Multikey](https://www.w3.org/TR/controller-document/#Multikey), i.e., a pair of key stored in [Multibase](https://www.w3.org/TR/controller-document/#multibase-0). The key data are encoded as strings and are therefore fairly
opaque, but are extremely compact. Note that RSA keys cannot be stored in this format (there is no specification for this).

The coding examples (see the API documentation for details):

```typescript
// Simple key generation
import { generateKeysJWK, generateKeysMK } from "@iherman/minicrypto";

const keyPairEdDSACrypto = await generateKeys("eddsa");

// Alternatively generate keys in JWK and Multikey formats.
const keyPairEdDSAJWK = await generateKeysJWK("eddsa");
const keyPairECDSAMK = await generateKeysMK("ecdsa");

// ECDSA Keys using P-384
const keyPairECDSAMK384 = await generateKeysMK("ecdsa", {namedCurve: "P-384"});

// RSA Keys generated with a larger modulus (larger key, more secure) for signature/verification
const keyPairRSAPSS = await generateKeysJWK("rsa-pss", {modulusLength: 4096});  // Default is 2048

// RSA Keys for encryption/decryption, using the default modulus length
const keyPairRSAOAEP = await generateKeys("rsa-oaep");
```

## Signature/verification

The keys can be used to sign a string message and to verify the signature. The signature itself is encoded as
base64 (more precisely, base-64-url-no-pad) or base58 encoding (more precisely, base-58-btc) and, optionally, stored as
a [Multibase](https://www.w3.org/TR/controller-document/#multibase-0) string. By default, if the key is in JWK or using the binary format, the signature is generated as a
plain, base64 string. If the key is Multikey/Multibase, then by default the signature is stored as a Multibase, base58
string. Other combinations must be set explicitly.

Note that the `sign` and `verify` functions accept the keys in any formats, i.e., as pairs or as individual keys
(private or secret, depending on the function). The only exception is that the `sign` function requires a full 
Multikey, the (Multibase encoded) secret key by itself is not accepted.

The coding examples (see the API for details):

```typescript
import { sign, verify } from "@iherman/minicrypto";

const message = "This is the string to be signed";

// Signature stored as plain base64
const signature64: string = await sign(message, keyPairRSAPSS);
const isValid64: boolean = await verify(message, signature, keyPairRSAPSS.publicKeyJwk);

// Signature stored as multibase base58
const signature58: string = await sign(message, keyPairECDSAMK);
const isValid58: boolean = await verify(message, signature, keyPairECDSAMK.publicKeyMultibase);
```

## Encryption/decryption

By default, if the key is in JWK, the ciphertext is generated as a plain, base64 string. Other combinations must be set
explicitly.

```typescript
import { encrypt, decrypt } from "@iherman/minicrypto";

const message2 = "This is the string to be encrypted";

// Signature stored as plain base64
const ciphertext64: string = await encrypt(message2, keyPairRSAOAEP.publicKey);

// Signature stored as multibase base58
const ciphertext58: string = await encrypt(message2, keyPairRSAOAEP.publicKey, {encoding: "base58", format: "multibase"});

// Decrypt a ciphertext stored in multibase. Note that the encoding field is not required, it is automatically recognized
const message2_decrypted: string = await decrypt(ciphertext58, keyPairRSAOAEP.privateKey, {format: "multibase"});
```

## Miscellaneous functions

### Hashing

Very frequently used for various type of data. There are many hash functions around, the most widely used these days
is "SHA-256", with "SHA-384" as a more secure alternative.

```typescript
import { hash } from "@iherman/minicrypto";

const message = "This is the string to be hashed";

const hash_256 = await hash(message)              
const hash_384 = await hash(message, "SHA-384");  // Default is SHA-256
```

### Key conversions

The package contains some functions to convert JWK keys or key pairs to and from their binary equivalents. For the sake
of convenience, ths package also re-exports similar functions for Multikeys and Multibase, though it is implemented
by a different, underlying package called [multikey-webcrypto](https://www.npmjs.com/package/multikey-webcrypto).



---


1. FIPS PUB 186-5: Digital Signature Standard (DSS). U.S. Department of Commerce/National Institute of Standards and
Technology. 3 February 2023. National Standard. URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf  
2. Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters. Lily Chen; Dustin Moody;
Karen Randall; Andrew Regenscheid; Angela Robinson. National Institute of Standards and Technology. February 2023.  
3. FIPS PUB 186-5: Digital Signature Standard (DSS). U.S. Department of Commerce/National Institute of Standards and
Technology. 3 February 2023. National Standard. URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf