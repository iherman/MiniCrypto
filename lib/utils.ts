import * as types from "./types.ts";
import {Crv, HashAlgorithm} from "./types.ts";

const SALT_LENGTH            = 32;

export interface WebCryptoAPIData extends types.KeyOptions {
    name: string,
    publicExponent ?: Uint8Array,
}

/**
 * Text to array buffer, needed for crypto operations
 * @param text
 */
export function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
}

/**
 * Mapping of the CryptoKey instance and the corresponding terms for the WebCrypto API.
 *
 * @param report
 * @param key
 * @returns
 */
export function algorithmDataCR(key: CryptoKey): WebCryptoAPIData {
    const alg = key.algorithm;
    switch (alg.name) {
        case "RSA-PSS": {
            return { name: 'RSA-PSS', hash: 'SHA-256', saltLength: SALT_LENGTH };
        }
        case "ECDSA": {
            const curve = (alg as EcKeyAlgorithm).namedCurve as Crv;
            const hash = ((): HashAlgorithm => {
                switch (curve) {
                    case "P-384": return "SHA-384";
                    // case "P-512": return "SHA-512";
                    default: return "SHA-256";
                }
            })();
            return {
                name       : "ECDSA",
                namedCurve : curve,
                hash       : hash,
            };
        }
        case "Ed25519": default: {
            return {
                name: "Ed25519"
            };
        }
    }
}
