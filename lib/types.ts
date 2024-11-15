/**
 * Common types for the package
 *
 * @module
 */

import { Multikey, Multibase } from "multikey-webcrypto";

/** Elliptic curves that are used for this package. */
export type Crv = "P-256" | "P-384";

/** Crypto hash values that are used for this package. "SHA-256" is the usual default. */
export type HashAlgorithm = "SHA-256" | "SHA-384" ;

/** Base encoding alternatives */
export type BaseEncoding = "base64" | "base58";

/**
 * Options to specify details for keys, i.e., the underlying algorithms.
 */
export interface KeyOptions {
    /** Choice of elliptic curve; relevant for ecdsa. Defaults to "P-256". */
    namedCurve    ?: Crv,
    /** Hash algorithm for internal use; relevant for "rsa-pss" and rsa-oaep". Defaults to "SHA-256".*/
    hash          ?: HashAlgorithm,
    /** Used by rsa-pss to make the signature more secure. Defaults to 32 and cannot be set externally. */
    saltLength    ?: number,
    /** RSA key modulus, relevant to RSA keys. Can be 1024, 2048, or 4096. Defaults to 2048. */
    modulusLength ?: number
}

export interface JWKeyPair {
    publicKeyJwk : JsonWebKey;
    secretKeyJwk : JsonWebKey;
}

/**
 * Used to overload the key argument for sign and decrypt operations. Note that a plain Multibase is not an option; the
 * multikey secret key alone may not contain all necessary information.
 */
export type CryptoSecretKey = CryptoKeyPair | CryptoKey | JWKeyPair | JsonWebKey | Multikey

/**
 * Used to overload the key argument for verify and encrypt operations
 */
export type CryptoPublicKey = CryptoKeyPair | CryptoKey | JWKeyPair | JsonWebKey  | Multikey | Multibase

/**
 * Options for the output of signing/verifying and for encryption/decryption.
 *
 * The defaults are dependent on the key encoding: base58 and multibase for Multikeys, base64 and plain otherwise.
 */
export interface OutputOptions {
    /** Base encoding choice for the generated signature. Can be base64 or base58 */
    encoding ?: BaseEncoding,
    /** Format of the final signature: plain encoded text, or Multibase */
    format   ?: "plain" | "multibase"
}



