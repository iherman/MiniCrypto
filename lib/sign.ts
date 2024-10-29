import * as types from "./types.ts";
import * as utils from "./utils.ts";
import * as keys from './keys.ts';
import * as multikeys from "npm:multikey-webcrypto";
import * as base58 from './encodings/base58/';
import * as base64 from './encodings/base64.ts';


/**
 * Sign a message.
 *
 * Possible errors are added to the report, no exceptions should be thrown.
 *
 * @param userKeys
 * @param message
 * @param encoding - choice between base64 or base58 encoding
 * @returns - either the signature in Multicode format, or `null` in case of an error.
 */
export async function sign(message: string, userKeys: types.JWKKeyPair, encoding: types.BaseEncoding = "base64"): Promise<string> {
    const cryptoKeys: CryptoKeyPair = await keys.JWKKeyPairToCrypto(userKeys);

    // Prepare the message to signature:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKeys.privateKey);

    const rawSignature: ArrayBuffer = await crypto.subtle.sign(algorithm, cryptoKeys.privateKey, rawMessage);
    const UintSignature: Uint8Array = new Uint8Array(rawSignature);

    if(encoding === "base64") {
        return base64.encode(UintSignature);
    } else if(encoding === "base58") {
        return base58.encode(UintSignature)
    } else {
        throw new Error(`Unsupported encoding ${encoding}.`);
    }
}

export async function verify(message: string, signature: string, key: JsonWebKey, encoding: types.BaseEncoding = "base64"): Promise<boolean> {
    const cryptoKey = await keys.JWKToCrypto(key);

    // Prepare the message for verification:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // Decoding the message from the encoded version
    const rawSignature: ArrayBuffer = encoding === "base64" ? base64.decode(signature) : base58.decode(signature);

    // The crypto algorithm to be used with this key:
    const algorithm : utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKey);
    return crypto.subtle.verify(algorithm, cryptoKey, rawSignature, rawMessage)
}