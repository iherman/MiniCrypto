/**
 * Various utility functions; not meant to be exported to the external world...
 *
 * @module
 */

import {Crv, KeyOptions, OutputOptions } from "./types.ts";
import { Multibase, Multikey }           from "npm:multikey-webcrypto";
import { base58, base64 }                from "./multibase.ts";
// import * as base64Plain                 from "./base64.ts";

const SALT_LENGTH= 32;

/**
 * Type guard for a Multibase value.
 *
 * Beware! This function is not fool-proof. If a random string happens to start with 'z' or 'u', it will
 * consider it as multibase, although there may be a possibility that it does not. To increase
 * the probability of success, an attempt is made to decode the multibase value, making use
 * of the fact that the decoder returns an `undefined` if the decoding fails.
 *
 */
// deno-lint-ignore no-explicit-any
export function isMultibase(obj: any): obj is Multibase {
    if (typeof obj === "string" && ((obj as string)[0] === 'z' || (obj as string)[0] === 'u')) {
        const possible: string = obj as string;
        const decoder = possible[0] === 'z' ? base58 : base64;
        return decoder.decode(possible.slice(1)) !== undefined;
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
 * Text to array buffer, needed for crypto operations.
 *
 * @param text
 */
export function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
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
 * Merge the options with a default: encoding is base64, format is plain.
 *
 * @param opts
 */
function generateFullOptions(opts: OutputOptions | undefined): OutputOptions {
    const defaultOptions: OutputOptions = {
        format   : "plain",
    };
    if (opts === undefined) {
        defaultOptions.encoding = "base64";
        return defaultOptions;
    } else {
        const workOption: OutputOptions = {...defaultOptions, ...opts};
        // We can be sure that the format is set; filling in
        // the encoding if it is not set
        if (workOption.format === "plain") {
            if (workOption.encoding === undefined) {
                workOption.encoding = "base64";
            }
        } else {
            if (workOption.encoding === undefined) {
                workOption.encoding = "base58";
            }
        }
        return workOption;
    }
}

/**
 * Encode the result in base58 or base64, possibly in Multibase. The `options` argument dictates.
 * Default is base64 encoding and plain output.
 *
 * @param options
 * @param rawMessage
 */
export function encodeResult(options: OutputOptions | undefined, rawMessage: ArrayBuffer): string {
    const fullOptions = generateFullOptions(options);

    const UintMessage: Uint8Array = new Uint8Array(rawMessage);
    if (fullOptions.format === "plain") {
        // The difference between the two versions of base64 is still to be clarified...
        return ((fullOptions.encoding === "base58") ? base58 : base64).encode(UintMessage);
        // return ((fullOptions.encoding === "base58") ? base58 : base64Plain).encode(UintMessage);
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
 */
export function decodeResult(options: OutputOptions | undefined, encodedMessage: string): ArrayBuffer {
    const fullOptions = generateFullOptions(options);
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
        return output.buffer;
    }
}
