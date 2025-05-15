/**
 * The main crypto operations: encrypt/decrypt and sign/verify. These functions are exported (via index.ts) to the
 * external world.
 *
 * @module
 */
import { type Multikey, type Multibase, multikeyToCrypto }                from "jsr:@iherman/multikey-webcrypto@0.6.1";
import type { JWKeyPair, CryptoSecretKey, CryptoPublicKey, OutputOptions} from "./types.ts";
import * as utils                                                         from "./utils.ts";
import * as keys                                                          from "./keys.ts";


async function getSecretKey(userKeys: CryptoSecretKey, usage: KeyUsage[] = ["sign"]): Promise<CryptoKey> {
    if (utils.isCryptoKeyPair(userKeys)) {
        return (userKeys as CryptoKeyPair).privateKey;
    } else if (utils.isCryptoKey(userKeys)) {
        return userKeys as CryptoKey;
    } else if (utils.isMultikey(userKeys)) {
        return (await multikeyToCrypto(userKeys as Multikey)).privateKey;
    } else if (utils.isJWKKeyPair(userKeys)) {
        return (await keys.JWKeyToCrypto((userKeys as JWKeyPair).secretKeyJwk, usage));
    } else {
        return (await keys.JWKeyToCrypto(userKeys as JsonWebKey, usage))
    }
}

async function getPublicKey(userKeys: CryptoPublicKey, usage: KeyUsage[] = ["verify"]): Promise<CryptoKey> {
    if (utils.isCryptoKeyPair(userKeys as object)) {
        return (userKeys as CryptoKeyPair).publicKey;
    } else if (utils.isCryptoKey(userKeys as object)) {
        return userKeys as CryptoKey;
    } else if (utils.isMultikey(userKeys as object)) {
        return (await multikeyToCrypto(userKeys as Multikey)).publicKey;
    } else if (utils.isMultibase(userKeys)) {
        return (await multikeyToCrypto(userKeys as Multibase));
    } else if (utils.isJWKKeyPair(userKeys)) {
        return (await keys.JWKeyToCrypto((userKeys as JWKeyPair).publicKeyJwk, usage));
    } else {
        return (await keys.JWKeyToCrypto(userKeys as JsonWebKey, usage))
    }
}

/**
 * Sign a message.
 *
 * The signature can be encoded
 *
 * * as plain string, with the value encoded, by default, in base64 or, on request, in base58
 * * as a Multibase string, with the value encoded, by default, in base58 or, on request, in base64
 *
 * Default for Multikeys is multibase with base58; plain string with base64 otherwise.
 *
 * @param message
 * @param userKeys - the private/public key pair
 * @param options - choice between signature result in multibase or plain, and between base64 or base58 encoding
 * @returns - signature in plain or multibase encoded format
 */
export async function sign(message: string, userKeys: CryptoSecretKey, options?: OutputOptions): Promise<string> {

    const key = await getSecretKey(userKeys);

    // Prepare the message to signature:
    const rawMessage: Uint8Array = utils.textToBytes(message);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(key);

    // The real crypto action
    const rawSignature: ArrayBuffer = await crypto.subtle.sign(algorithm, key, rawMessage);

    return utils.encodeResult(options, rawSignature, utils.isMultikey(userKeys))
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
 * @param userKey
 * @param options - choice between signature result in multibase or plain, and between base64 or base58 encoding.
 */
export async function verify(message: string, signature: string, userKey: CryptoPublicKey, options?: OutputOptions): Promise<boolean> {
    const key = await getPublicKey(userKey);

    // Prepare the message for verification:
    const rawMessage: Uint8Array = utils.textToBytes(message);

    // Prepare the signature for verification
    const rawSignature = utils.decodeResult(options, signature, utils.isMultibase(userKey) || utils.isMultikey(userKey));

    // The crypto algorithm to be used with this key:
    const algorithm : utils.WebCryptoAPIData = utils.algorithmDataCR(key);

    // The real crypto meat:
    return crypto.subtle.verify(algorithm, key, rawSignature, rawMessage)
}

/**
 * Encrypt a message.
 *
 * The generated ciphertext can be encoded
 *
 * * as plain string, with the value encoded, by default, in base64 or, on request, in base58.
 * * as a Multibase string, with the value encoded, by default, in base58 or, on request, in base64.
 *
 * Default is plain string with base64.
 *
 * @param message
 * @param userKey
 * @param options - choice between signature result in multibase or plain, and between base64 or base58 encoding
 * @return - ciphertext in plain or multibase encoded format
 */
export async function encrypt(message: string, userKey: CryptoPublicKey, options?: OutputOptions): Promise<string> {
    const key = await getPublicKey(userKey, ["encrypt"]);

    // Prepare the message to encryption
    const rawMessage: Uint8Array = utils.textToBytes(message);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(key);

    // The real crypto action
    const rawCiphertext: ArrayBuffer = await crypto.subtle.encrypt(algorithm, key, rawMessage);

    return utils.encodeResult(options, rawCiphertext, false);
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
export async function decrypt(ciphertext: string, userKey: CryptoSecretKey, options?: OutputOptions): Promise<string> {
    // Get hold of the secret key
    const key = await getSecretKey(userKey, ["decrypt"]);

    // Prepare the ciphertext for decryption
    const rawCiphertext = utils.decodeResult(options, ciphertext, false);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(key);

    const rawMessage = await crypto.subtle.decrypt(algorithm, key, rawCiphertext);

    return utils.bytesToText(new Uint8Array(rawMessage));
}
