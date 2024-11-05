import { multikeyToCrypto }               from "npm:multikey-webcrypto";
import { Key, KeyPair, SignatureOptions } from "./types.ts";
import * as utils                         from "./utils.ts";
import * as keys                          from "./keys.ts";
import { base58, base64 }                 from "./encodingMultibase.ts";
// import * as base64Plain                   from "./base64.ts";


const generateFullOptions = (opts: SignatureOptions | undefined): SignatureOptions => {
    const defaultOptions: SignatureOptions = {
        encoding : "base64",
        format   : "plain",
    };
    return (opts === undefined) ? defaultOptions : {...defaultOptions, ...opts};
}

/**
 * Sign a message.
 *
 * @param userKeys - the private/public key pair
 * @param message
 * @param options - choice between base64 or base58 encoding, and between signature result in multibase or plain
 * @returns - either the signature in Multibase format
 */
export async function sign(message: string, userKeys: KeyPair, options?: SignatureOptions): Promise<string> {
    const fullOptions = generateFullOptions(options);

    // Convert the encoded key-pair to crypto keys
    const cryptoKeys: CryptoKeyPair =(utils.isMultikey(userKeys)) ?
        await multikeyToCrypto(userKeys) :
        await keys.JWKKeyPairToCrypto(userKeys);

    // Prepare the message to signature:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // The crypto algorithm to be used with this key:
    const algorithm: utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKeys.privateKey);

    const rawSignature: ArrayBuffer = await crypto.subtle.sign(algorithm, cryptoKeys.privateKey, rawMessage);

    const UintSignature: Uint8Array = new Uint8Array(rawSignature);

    if (fullOptions.format === "plain") {
        // The difference between the two versions of base64 is still to be clarified...
        return ((fullOptions.encoding === "base58") ? base58 : base64).encode(UintSignature);
        // return ((fullOptions.encoding === "base58") ? base58 : base64Plain).encode(UintSignature);
    } else {
        const output = ((fullOptions.encoding === "base58") ? base58 : base64).encode(UintSignature);
        return ((fullOptions.encoding === "base58") ? 'z' : 'u') + output;
    }
}


/**
 * Verify a signature.
 *
 * Note that if the signature option refers to multibase, the values of encoding is ignored (and is deduced from the
 * multibase itself).
 *
 * @param message
 * @param signature
 * @param key
 * @param options - choice between base64 or base58 encoding, and between signature result in multibase or plain.
 */
export async function verify(message: string, signature: string, key: Key, options?: SignatureOptions): Promise<boolean> {
    const fullOptions = generateFullOptions(options);

    const cryptoKey = (utils.isMultibase(key)) ? await multikeyToCrypto(key) : await keys.JWKToCrypto(key)

    // Prepare the message for verification:
    const rawMessage: ArrayBuffer = utils.textToArrayBuffer(message);

    // Decoding the message from the encoded version
    const rawSignature = ((): ArrayBuffer => {
        if (fullOptions.format === "plain") {
            // No Multibase involved
            return ((fullOptions.encoding === "base58") ? base58 : base64).decode(signature);
            // The difference in encoding base64 is still to be understood...
            // return ((fullOptions.encoding === "base58") ? base58 : base64Plain).decode(signature);
        } else {
            // The Multibase encoding dictates
            if (signature[0] === 'z') {
                return base58.decode(signature.slice(1));
            } else if (signature[0] === 'u') {
                return base64.decode(signature.slice(1));
            } else {
                throw new Error(`Invalid multibase value (begins with '${signature[0]}'`);
            }
        }
    })();

    // The crypto algorithm to be used with this key:
    const algorithm : utils.WebCryptoAPIData = utils.algorithmDataCR(cryptoKey);

    // The real crypto meat:
    return crypto.subtle.verify(algorithm, cryptoKey, rawSignature, rawMessage)
}