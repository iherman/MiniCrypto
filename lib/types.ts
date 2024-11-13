/**
 * Common types for the package
 *
 * @module
 */

import { Multikey, Multibase } from "npm:multikey-webcrypto";

/** JWK values for the elliptic curves that are relevant for this package */
export type Crv = "P-256" | "P-384";

/** Crypto hash values that are relevant for this package */
export type HashAlgorithm = "SHA-256" | "SHA-384" ;

/** Base encoding alternatives */
export type BaseEncoding = "base64" | "base58";

export interface KeyOptions {
    namedCurve    ?: Crv,
    hash          ?: HashAlgorithm,
    saltLength    ?: number,
    modulusLength ?: number
}

export interface JWKKeyPair {
    publicKeyJwk : JsonWebKey;
    secretKeyJwk : JsonWebKey;
}

/** Just some shorthands... */
export type Key     = JsonWebKey | Multibase | CryptoKey;
export type KeyPair = JWKKeyPair | Multikey  | CryptoKeyPair;

export type CryptoSecretKey = JWKKeyPair | JsonWebKey | Multikey | CryptoKeyPair | CryptoKey
export type CryptoPublicKey = JWKKeyPair | JsonWebKey | Multikey | Multibase | CryptoKeyPair | CryptoKey

/**
 * Options for the output of signing/verifying and for encryption/decryption.
 */
export interface OutputOptions {
    /** Base encoding choice for the generated signature */
    encoding ?: BaseEncoding,
    /** Format of the final signature: plain encoded text, or Multibase */
    format   ?: "plain" | "multibase"
}



