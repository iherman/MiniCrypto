/**
 * Various utility functions; not meant to be exported to the external world...
 *
 * @module
 */

import { Crv, KeyOptions, OutputOptions, JWKeyPair } from "./types.ts";
import { Multibase, Multikey }                       from "jsr:@iherman/multikey-webcrypto@0.6.1";
import { base58, base64urlnopad as base64 }          from "npm:@scure/base@1.2.5";

const SALT_LENGTH= 32;

/**
 * Type guard for a Multibase value.
 *
 * Beware! Mathematically, this function is not fool-proof. After all, a random string
 * may start with a 'z' or a 'u', and contain only characters that are part of the
 * required base vocabulary. To increase the probability of success, an attempt is made to decode the multibase value.
 * If successful, the value can indeed be accepted as a multibase with a reasonable probability.
 */
// deno-lint-ignore no-explicit-any
export function isMultibase(obj: any): obj is Multibase {
    if (typeof obj === "string" && ((obj as string)[0] === 'z' || (obj as string)[0] === 'u')) {
        const possible: string = obj as string;
        const decoder = possible[0] === 'z' ? base58 : base64;
        try {
            decoder.decode(possible.slice(1));
            return true
        } catch (_e) {
            return false;
        }
    } else {
        return false;
    }
}

/**
 * Type guard for a Multikey object.
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
 * Type guard for a CryptoKey object.
 *
 * @param obj
 */
export function isCryptoKey(obj: object): obj is CryptoKey {
    return (
        (obj as CryptoKey).algorithm !== undefined &&
        (obj as CryptoKey).extractable !== undefined &&
        (obj as CryptoKey).type !== undefined &&
        (obj as CryptoKey).usages !== undefined
    );
}

/**
 * Type guard for a CryptoKeyPair object.
 *
 * @param obj
 */
export function isCryptoKeyPair(obj: object): obj is CryptoKeyPair {
    return (
        (obj as CryptoKeyPair).privateKey !== undefined &&
        (obj as CryptoKeyPair).publicKey !== undefined &&
        isCryptoKey((obj as CryptoKeyPair).privateKey) &&
        isCryptoKey((obj as CryptoKeyPair).publicKey)
    )
}

/**
 * Type guard for a JWK Key Pair
 *
 * @param obj
 */
export function isJWKKeyPair(obj: object): obj is JWKeyPair {
    return (
        (obj as JWKeyPair).publicKeyJwk !== undefined &&
        (obj as JWKeyPair).secretKeyJwk !== undefined
    )
}

/**
 * Text to array buffer, needed for crypto operations.
 *
 * @param text
 */
export function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer as ArrayBuffer;
}

/**
 * Array buffer to text, needed for crypto operations.
 *
 * @param arrayBuffer
 */
export function arrayBufferToText(arrayBuffer: ArrayBuffer): string {
    return (new TextDecoder()).decode(arrayBuffer);
}


/**
 * Additional structure needed for operations such as sign or verify in the WebCrypto API. Can
 * be extracted from the WebCrypto representation of the crypto keys,
 * see {@link algorithmDataCR}.
 */
export interface WebCryptoAPIData extends KeyOptions {
    name: string,
    publicExponent ?: Uint8Array
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
        case "RSA-OAEP": {
            return {
                name: 'RSA-OAEP',
            };
        }
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

/**
 * Merge the options with a default. The default depends on the usage of Multikeys or not.
 *
 * @param opts
 * @param multik - whether this is for a multikey/multibase environment or not
 */
function generateFullOptions(opts: OutputOptions | undefined, multik: boolean): OutputOptions {
    const defaultOptions = ((): OutputOptions => {
        if (multik) {
            return {
                format: "multibase",
                encoding: "base58",
            }
        } else {
            return {
                format: "plain",
                encoding: "base64",
            }
        }
    })();
    return (opts === undefined) ? defaultOptions : {...defaultOptions, ...opts};
}

/**
 * Encode the result in base58 or base64, possibly in Multibase. The `options` argument dictates.
 * Default is base64 encoding and plain output.
 *
 * @param options
 * @param rawMessage
 * @param multik - whether this is for a multikey/multibase environment or not
 */
export function encodeResult(options: OutputOptions | undefined, rawMessage: ArrayBuffer, multik: boolean): string {
    const fullOptions = generateFullOptions(options, multik);

    const UintMessage: Uint8Array = new Uint8Array(rawMessage);
    if (fullOptions.format === "plain") {
        return ((fullOptions.encoding === "base58") ? base58 : base64).encode(UintMessage);
    } else {
        const output = ((fullOptions.encoding === "base58") ? base58 : base64).encode(UintMessage);
        return ((fullOptions.encoding === "base58") ? 'z' : 'u') + output;
    }
}

/**
 * Decode a string from encoded form. If the text is recognized as Multibase, the encoding format is there, otherwise
 * the `options` argument rules.
 *
 * @param options
 * @param encodedMessage
 * @param multi - whether this is for a multikey/multibase environment or not
 */
export function decodeResult(options: OutputOptions | undefined, encodedMessage: string, multi: boolean): ArrayBuffer {
    const fullOptions = generateFullOptions(options, multi);
    const output: Uint8Array = ((): Uint8Array => {
            if (fullOptions.format === "multibase") {
                if (encodedMessage[0] === 'z') {
                    return base58.decode(encodedMessage.slice(1));
                } else if (encodedMessage[0] === 'u') {
                    return base64.decode(encodedMessage.slice(1));
                } else {
                    throw new Error(`Invalid multibase value (begins with '${encodedMessage[0]}'`);
                }
            } else {
                return ((fullOptions.encoding === "base58") ? base58 : base64).decode(encodedMessage);
            }
        }
    )();

    if (output === undefined) {
        throw new Error(`WTF: ${encodedMessage}, \n${JSON.stringify(fullOptions, null, 4)}`);
    } else {
        return output.buffer as ArrayBuffer;
    }
}
