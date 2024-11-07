/**
 * The main crypto operations: encrypt/decrypt and sign/verify. These functions are exported (via index.ts) to the
 * external world.
 *
 * @module
 */
import { multikeyToCrypto }            from "npm:multikey-webcrypto";
import { Key, KeyPair, OutputOptions } from "./types.ts";
import * as utils                      from "./utils.ts";
import * as keys                       from "./keys.ts";


/**
 * Sign a message.
 *
 * The signature can be encoded
 *
 * * as plain string, with the value encoded, by default, in base64 or, on request, in base58
 * * as a Multibase string, with the value encoded, by default, in base58 or, on request, in base64
 *
 * Default is using plain string (with base64).
 *
 * @param message
 * @param userKeys - the private/public key pair
 * @param options - choice between signature result in multibase or plain, and between base64 or base58 encoding
 * @returns - signature in plain or multibase encoded format
 */
export async function sign(message: string, userKeys: KeyPair, options?: OutputOptions): Promise<string> {

    // Convert the encoded key-pair to crypto keys
    const cryptoKeys: CryptoKeyPair =(utils.isMultikey(userKeys)) ?
        await multikeyToCrypto(userKeys) :
        await keys.JWKKeyPairToCrypto(userKeys);

    // Prepare the message to signature:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKeys.privateKey);

    // The real crypto action
    const rawSignature: ArrayBuffer = await crypto.subtle.sign(algorithm, cryptoKeys.privateKey, rawMessage);

    return utils.encodeResult(options, rawSignature)
}


/**
 * Verify a signature.
 *
 * The option should be identical to the value used (if any) for signature, except that,
 * if the signature option refers to multibase, the values of encoding is ignored (and is deduced from the
 * multibase itself).
 *
 * @param message
 * @param signature
 * @param key
 * @param options - choice between signature result in multibase or plain, and between base64 or base58 encoding.
 */
export async function verify(message: string, signature: string, key: Key, options?: OutputOptions): Promise<boolean> {
    // The alternative to multibase is a JWK Key, which will surely fail as a multibase, so
    // it is all right to use it even if incomplete:
    const cryptoKey = (utils.isMultibase(key)) ? await multikeyToCrypto(key) : await keys.JWKToCrypto(key)

    // Prepare the message for verification:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // Prepare the signature for verification
    const rawSignature = utils.decodeResult(options, signature);

    // The crypto algorithm to be used with this key:
    const algorithm : utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKey);

    // The real crypto meat:
    return crypto.subtle.verify(algorithm, cryptoKey, rawSignature, rawMessage)
}

/**
 * Encrypt a message.
 *
 * The generated ciphertext can be encoded
 *
 * * as plain string, with the value encoded, by default, in base64 or, on request, in base58
 * * as a Multibase string, with the value encoded, by default, in base58 or, on request, in base64
 *
 * Default is using plain string (with base64).
 *
 * @param message
 * @param userKey
 * @param options - choice between signature result in multibase or plain, and between base64 or base58 encoding
 * @return - ciphertext in plain or multibase encoded format
 */
export async function encrypt(message: string, userKey: Key, options?: OutputOptions): Promise<string> {
    // The alternative to multibase is a JWK Key, which will surely fail as a multibase, so
    // it is all right to use it even if incomplete:
    if (utils.isMultibase(userKey)) {
        throw new Error("Multikey cannot be used for encryption");
    }

    // Convert the encoded key to crypto key
    const cryptoKey: CryptoKey = await keys.JWKToCrypto(userKey, ["encrypt"]);

    // Prepare the message to encryption
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKey);

    // The real crypto action
    const rawCiphertext: ArrayBuffer = await crypto.subtle.encrypt(algorithm, cryptoKey, rawMessage);

    return utils.encodeResult(options, rawCiphertext);
}

/**
 * Decrypt a ciphertext.
 *
 * The option should be identical to the value used (if any) for signature, except that,
 * if the signature option refers to multibase, the values of encoding is ignored (and is deduced from the
 * multibase itself).
 *
 * @param ciphertext
 * @param userKey
 * @param options - choice between signature result in multibase or plain, and between base64 or base58 encoding.
 */
export async function decrypt(ciphertext: string, userKey: Key, options?: OutputOptions): Promise<string> {
    // The alternative to multibase is a JWK Key, which will surely fail as a multibase, so
    // it is all right to use it even if incomplete:
    if (utils.isMultibase(userKey)) {
        throw new Error("Multikey cannot be used for encryption");
    }

    // Convert the encoded key to crypto key
    const cryptoKey: CryptoKey = await keys.JWKToCrypto(userKey, ["decrypt"]);

    // Prepare the ciphertext for decryption
    const rawCiphertext = utils.decodeResult(options, ciphertext);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKey);

    const rawMessage = await crypto.subtle.decrypt(algorithm, cryptoKey, rawCiphertext);

    return utils.arrayBufferToText(rawMessage);
}