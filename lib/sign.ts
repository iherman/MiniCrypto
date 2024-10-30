import { Multibase, Multikey, multikeyToCrypto } from "npm:multikey-webcrypto";

import { BaseEncoding, JWKKeyPair } from "./types.ts";
import * as utils from "./utils.ts";
import * as keys from './keys.ts';
import * as base58 from "./encodings/base58/index.js";
import * as base64 from './encodings/base64.ts';


/**
 * Sign a message.
 *
 * @param userKeys - the private/public key pair
 * @param message
 * @param encoding - choice between base64 or base58 encoding
 * @returns - either the signature in Multibase format
 */
export async function sign(message: string, userKeys: JWKKeyPair | Multikey, encoding: BaseEncoding = "base64"): Promise<string> {
    // Convert the encoded key-pair to crypto keys
    const cryptoKeys: CryptoKeyPair =(utils.isMultikey(userKeys)) ? await multikeyToCrypto(userKeys) :  await keys.JWKKeyPairToCrypto(userKeys);

    // Prepare the message to signature:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKeys.privateKey);

    const rawSignature: ArrayBuffer = await crypto.subtle.sign(algorithm, cryptoKeys.privateKey, rawMessage);
    const UintSignature: Uint8Array = new Uint8Array(rawSignature);

    if(encoding === "base64") {
        return base64.encode(UintSignature);
    } else if(encoding === "base58") {
        return base58.encode(UintSignature);
    } else {
        throw new Error(`Unsupported encoding ${encoding}.`);
    }
}

/**
 * Verify a signature.
 *
 * @param message
 * @param signature
 * @param key
 * @param encoding
 */
export async function verify(message: string, signature: string, key: JsonWebKey | Multibase, encoding: BaseEncoding = "base64"): Promise<boolean> {
    const cryptoKey = (utils.isMultibase(key)) ? await multikeyToCrypto(key) : await keys.JWKToCrypto(key)

    // Prepare the message for verification:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // Decoding the message from the encoded version
    const rawSignature: ArrayBuffer = encoding === "base64" ? base64.decode(signature) : base58.decode(signature);

    // The crypto algorithm to be used with this key:
    const algorithm : utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKey);
    return crypto.subtle.verify(algorithm, cryptoKey, rawSignature, rawMessage)
}