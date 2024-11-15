/**
 * @module
 */



import { cryptoToMultikey, Multikey }                                      from "multikey-webcrypto";
import {generateKeys, CryptoAlgorithm, JWKeyPairToCrypto, JWKeyToCrypto }  from "./lib/keys.ts";
import { KeyOptions, JWKeyPair }                                           from "./lib/types.ts";
import { isJWKKeyPair, isCryptoKeyPair }                                   from "./lib/utils.ts";

// Re-exports; some of these may not be used in practice, but it helps
// to generate the right documentation.
export type {
    HashAlgorithm, KeyOptions, OutputOptions, CryptoSecretKey, CryptoPublicKey,
    BaseEncoding, JWKeyPair
}                                                                           from "./lib/types.ts";
export type { CryptoAlgorithm }                                             from "./lib/keys.ts";
export  { generateKeys }  from "./lib/keys.ts";
export type { Multibase, Multikey }                                         from "multikey-webcrypto";
export { multikeyToCrypto, cryptoToMultikey }                               from "multikey-webcrypto";
export { calculateHash as hash }                                            from "./lib/hash.ts";
export { sign, verify, encrypt, decrypt }                                   from "./lib/crypto.ts"

/**
 * Utility function: get a binary crypto representation from a JWK encoded key/key pair.
 *
 * @param keys
 */
export async function JWKToCrypto(keys: JWKeyPair): Promise<CryptoKeyPair>;
export async function JWKToCrypto(keys: JsonWebKey): Promise<CryptoKey>;
export async function JWKToCrypto(keys: JWKeyPair | JsonWebKey): Promise< CryptoKeyPair|CryptoKey > {
    if (isJWKKeyPair(keys)) {
        return await JWKeyPairToCrypto(keys as JWKeyPair);
    } else {
        return await JWKeyToCrypto(keys as JsonWebKey);
    }
}

/**
 * Utility function: get a JWK representation from a binary crypto key/key pair.
 *
 * @param keys
 */
export async function cryptoToJWK(keys: CryptoKeyPair): Promise< JWKeyPair>;
export async function cryptoToJWK(keys: CryptoKey): Promise<JsonWebKey>;
export async function cryptoToJWK(keys: CryptoKeyPair | CryptoKey): Promise< JsonWebKey|JWKeyPair> {
    if (isCryptoKeyPair(keys)) {
        const publicKeyJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
        const secretKeyJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
        return { publicKeyJwk, secretKeyJwk } as JWKeyPair;
    } else {
        return await crypto.subtle.exportKey("jwk", keys) as JsonWebKey;
    }
}

/**
 * Generate a new public/private key pair in one of the ecdsa/eddsa/RSA crypto algorithms
 * (the term Ed25519 can also be used for eddsa). The result is a pair or JWK format for keys.
 *
 * Some of the algorithms can be (optionally) parametrized through the key options:
 *
 * * For ecdsa: the `nameCurve` field can be set to `"P-256"` or `"P-384"` to change the EC curve. Default is `"P-256"`
 * * For RSA:
 *     * can be set to the modulus length of the key can be set with `modulusLength`. Value can be 1024, 2048, or 4096;
 *     default is 2048
 *     * the `hash` value can be set to `"SHA-256"` or `"SHA-384"`; default is "SHA-256"`
 *
 * @param algorithm - can be ecdsa, eddsa, Ed25519, or RSA
 * @param options - depends on the algorithm chosen
 * @async
 */
export async function generateKeysJWK(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<JWKeyPair> {
    const keys: CryptoKeyPair = await generateKeys(algorithm, options);
    return await cryptoToJWK(keys as CryptoKeyPair);
}

/**
 * Generate a new public/private key pair in one of the ecdsa or eddsa crypto algorithms
 * (the term Ed25519 can also be used for eddsa). The result is a pair or Multibase formatted keys, i.e., in Multikey.
 *
 * Ecdsa can be (optionally) parametrized through the key options: the `nameCurve` field can be set to `"P-256"`
 * or `"P-384"` to change the EC curve. Default is `"P-256"`
 *
 * @param algorithm - can be ecdsa, eddsa, Ed25519
 * @param options - depends on the algorithm chosen
 * @async
 */
export async function generateKeysMK(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<Multikey> {
    if (algorithm === "rsa-pss" || algorithm === "rsa-oaep") {
        throw new Error("No Multikey definition for RSA.");
    }
    const keys: CryptoKeyPair = await generateKeys(algorithm, options);
    return cryptoToMultikey(keys);
}


