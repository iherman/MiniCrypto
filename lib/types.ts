import * as multikeys from "npm:multikey-webcrypto";

/** JWK values for the elliptic curves that are relevant for this package */
export type Crv = "P-256" | "P-384" | "P-512";

/** Crypto identifier values that are relevant for this package */
export type CryptoAlgorithm = "ecdsa" | "eddsa" | "Ed25519" | "rsa";

/** Crypto hash values that are relevant for this package */
export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512" ;

/** Key encoding alternatives */
export type KeyEncoding = "JWK" | "Multikey";


export interface KeyOptions {
    namedCurve    ?: Crv,
    hash          ?: HashAlgorithm,
    saltLength    ?: number,
    modulusLength ?: number,
    encoding      ?: KeyEncoding,
}

export interface JWKKeyPair {
    publicKey   : JsonWebKey;
    privateKey ?: JsonWebKey;
}

export type KeyPair = JWKKeyPair | multikeys.Multikey;

