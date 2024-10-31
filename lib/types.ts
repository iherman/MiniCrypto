import { Multikey } from "npm:multikey-webcrypto";

/** Key encoding alternatives */
export type KeyEncoding = "JWK" | "Multikey";

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

export type KeyPair = JWKKeyPair | Multikey;

