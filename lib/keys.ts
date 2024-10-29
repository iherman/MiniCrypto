import * as types from "./types.ts";
import { KeyOptions, JWKKeyPair } from './types.ts';
import * as multikeys from "npm:multikey-webcrypto";


/** JWK values for the key types that are relevant for this package */
type Kty = "EC" | "RSA" | "OKP";

const DEFAULT_CURVE = "P-256";

const DEFAULT_MODULUS_LENGTH = 2048;
const DEFAULT_HASH_ALGORITHM = "SHA-256";


export async function JWKToCrypto(key: JsonWebKey, usage: KeyUsage[] = ["verify"]): Promise<CryptoKey> {
    const algorithm: { name: string, namedCurve?: string; } = { name: "" };
    switch (key.kty) {
        // TODO: include sg for RSS
        case 'EC':
            algorithm.name = "ECDSA";
            algorithm.namedCurve = key.crv;
            break;
        case 'OKP':
            algorithm.name = "Ed25519";
            break;
        default:
            // In fact, this does not happen; the JWK comes from our own
            // generation, that raises an error earlier in this case.
            // But this keeps typescript happy...
            throw new Error("Unknown kty value for the JWK key");
    }
    return crypto.subtle.importKey("jwk", key, algorithm, true, usage);
}

export async function JWKKeyPairToCrypto(keys: types.JWKKeyPair ): Promise<CryptoKeyPair> {
    const [ publicKey , privateKey ]: [CryptoKey,CryptoKey] = await Promise.all([
        JWKToCrypto(keys.publicKey, ["verify"]),
        JWKToCrypto(keys.privateKey, ["sign"]),
    ]);
    return {
        publicKey, privateKey
    };
}

export async function createNewKeys(algorithm: types.CryptoAlgorithm, options: KeyOptions): Promise<CryptoKeyPair> {
    const cryptoOptions: WebCryptoAPIData = ((): WebCryptoAPIData => {
        switch(algorithm) {
            case "ecdsa" : return {
                name       : "ECDSA",
                namedCurve : options?.namedCurve || DEFAULT_CURVE
            }
            case "eddsa" : case "Ed25519" : return {
                name : "Ed25519"
            }
            case "rsa": default: return {
                name           : "RSA-PSS",
                modulusLength  : options?.modulusLength || DEFAULT_MODULUS_LENGTH,
                publicExponent : new Uint8Array([0x01, 0x00, 0x01]),
                hash           : options?.hash || DEFAULT_HASH_ALGORITHM
            }
        }
    })();
    return crypto.subtle.generateKey(cryptoOptions, true, ["sign", "verify"]);
}

export async function cryptoToJWK(pair: CryptoKeyPair): Promise<JWKKeyPair> {
    const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const privateKey = await crypto.subtle.exportKey("jwk", pair.privateKey);
    return { publicKey, privateKey }
}

