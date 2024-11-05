import { cryptoToMultikey, Multikey }                  from "npm:multikey-webcrypto";
import { createNewKeys, cryptoToJWK, CryptoAlgorithm } from "./lib/keys.ts";
import { KeyOptions, JWKKeyPair }                      from "./lib/types.ts";

export type { HashAlgorithm, KeyOptions, SignatureOptions, BaseEncoding } from "./lib/types.ts";
export type { CryptoAlgorithm }    from "./lib/keys.ts";
export { calculateHash as hash }   from "./lib/hash.ts";
// export async function random(size: number): Promise<string> {};

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
 */
export async function generateKeysJWK(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<JWKKeyPair> {
    const keys: CryptoKeyPair = await createNewKeys(algorithm, options);
    return cryptoToJWK(keys);
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
 */
export async function generateKeysMK(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<Multikey> {
    if (algorithm === "rsa") {
        throw new Error("No Multikey definition for RSA.");
    }
    const keys: CryptoKeyPair = await createNewKeys(algorithm, options);
    return cryptoToMultikey(keys);
}

export { sign, verify } from "./lib/sign.ts"


