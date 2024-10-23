import * as types from "./types.ts";
import { KeyOptions, KeyEncoding } from './types.ts';
import * as multikeys from "npm:multikey-webcrypto";


/** JWK values for the key types that are relevant for this package */
type Kty = "EC" | "RSA" | "OKP";

const DEFAULT_CURVE = "P-256";

const SALT_LENGTH          = 32;
const DEFAULT_MODULUS_LENGTH = 4096;
const DEFAULT_HASH_ALGORITHM = "SHA-256";
const DEFAULT_KEY_ENCODING   = "JWK";

interface WebCryptoAPIData extends types.KeyOptions {
    name: string,
    publicExponent ?: Uint8Array,
}

export async function createNewKeys(algorithm: types.CryptoAlgorithm, options: KeyOptions): Promise<types.KeyPair> {
    const cryptoOptions = ((): WebCryptoAPIData => {
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
    const newPair: CryptoKeyPair = await crypto.subtle.generateKey(cryptoOptions, true, ["sign", "verify"]) as CryptoKeyPair;
    const encoding = options?.encoding || DEFAULT_KEY_ENCODING;
    if (encoding === "JWK") {
        const publicKey = await crypto.subtle.exportKey("jwk", newPair.publicKey);
        const privateKey = await crypto.subtle.exportKey("jwk", newPair.privateKey);
        return { publicKey, privateKey }
    } else {
        // Encoding is in multikey
        return multikeys.cryptoToMultikey(newPair);
    }
}
