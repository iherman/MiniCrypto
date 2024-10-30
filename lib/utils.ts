import {Crv, KeyOptions } from "./types.ts";
import { Multibase, Multikey } from "npm:multikey-webcrypto";

const SALT_LENGTH= 32;

/**
 * Type guard for a Multibase value
 */
// deno-lint-ignore no-explicit-any
export function isMultibase(obj: any): obj is Multibase {
    return (typeof obj === "string" && (obj as string)[0] === 'z');
}

/**
 * Type guard for a Multikey object
 *
 * @param obj
 */
export function isMultikey(obj: object): obj is Multikey {
    const isPublic: boolean = (obj as Multikey).publicKeyMultibase !== undefined && isMultibase((obj as Multikey).publicKeyMultibase);
    if (isPublic === true) {
        // an extra check, just to be on the safer side...
        if ((obj as Multikey).secretKeyMultibase !== undefined) {
            return isMultibase((obj as Multikey).secretKeyMultibase);
        } else {
            return false;
        }
    } else {
        return false;
    }
}

/**
 * Text to array buffer, needed for crypto operations
 *
 * @param text
 */
export function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
}

/**
 * Additional structure needed for operations such as sign or verify in the WebCrypto API. Can
 * be extracted from the WebCrypto representation of the crypto keys,
 * see {@link algorithmDataCR}.
 */
export interface WebCryptoAPIData extends KeyOptions {
    name: string,
    publicExponent ?: Uint8Array,
}

/**
 * Mapping of the CryptoKey instance and the corresponding terms for the WebCrypto API like
 * sign or verify.
 *
 * @param key
 * @returns
 */
export function algorithmDataCR(key: CryptoKey): WebCryptoAPIData {
    const alg = key.algorithm;
    switch (alg.name) {
        case "RSA-PSS": {
            return {
                name: 'RSA-PSS',
                saltLength: SALT_LENGTH
            };
        }
        case "ECDSA": {
            const curve = (alg as EcKeyAlgorithm).namedCurve as Crv;
            const hash = (curve === "P-384") ? "SHA-384" : "SHA-256";
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
