import { KeyOptions, JWKKeyPair } from './types.ts';
import { WebCryptoAPIData }       from './utils.ts';

/** JWK values for the key types that are relevant for this package */
type Kty = "EC" | "RSA" | "OKP";

/** Crypto identifier values that are relevant for this package */
export type CryptoAlgorithm = "ecdsa" | "eddsa" | "Ed25519" | "rsa";

const DEFAULT_CURVE            = "P-256";
const DEFAULT_MODULUS_LENGTH     = 2048;
const DEFAULT_HASH_ALGORITHM = "SHA-256";

/**
 * Generate a private/public key pair in one of the ecdsa/eddsa/RSA crypto algorithms (the term Ed25519 can also be used
 * for eddsa). The result is the WebCrypto format for keys.
 *
 * Some of the algorithms can be (optionally) parametrized through the key options:
 *
 * * For ecdsa: the `nameCurve` field can be set to `"P-256"` or `"P-384"` to change the EC curve. Default is `"P-256"`
 * * For RSA:
 *     * can be set to the modulus length of the key can be set with `modulusLength`. Value can be 1024, 2048, or 4096;
 *     default is 2048
 *     * the `hash` value can be set to `"SHA-256"` or `"SHA-384"`; default is "SHA-256"`
 *
 *
 * @param algorithm - can be ecdsa, eddsa, Ed25519, or RSA
 * @param options - depends on the algorithm chosen
 * @return a Promise with a CryptoKeyPair
 * @async
 */
export function createNewKeys(algorithm: CryptoAlgorithm, options: KeyOptions): Promise<CryptoKeyPair> {
    const cryptoOptions: WebCryptoAPIData = ((): WebCryptoAPIData => {
        switch(algorithm) {
            case "ecdsa" :
                return {
                    name       : "ECDSA",
                    namedCurve : options?.namedCurve || DEFAULT_CURVE
                }
            case "eddsa" : case "Ed25519" :
                return {
                    name : "Ed25519"
                }
            case "rsa": default: {
                const modulusLength = ((): number => {
                    if (options.modulusLength !== undefined) {
                        if (options.modulusLength === 1024 || options.modulusLength === 2048 || options.modulusLength === 4096) {
                            return options.modulusLength;
                        } else {
                            throw new Error(`Invalid RSA Modulus Length: ${options.modulusLength}`);
                        }
                    }
                    return DEFAULT_MODULUS_LENGTH;
                })();
                return {
                    name: "RSA-PSS",
                    modulusLength,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: options?.hash || DEFAULT_HASH_ALGORITHM
                }
            }
        }
    })();
    return crypto.subtle.generateKey(cryptoOptions, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
}

/**
 * Convert a WebCrypto public/private key pair to JWK.
 *
 * @param pair
 * @return a Promise with a JWK Key Pair
 * @async
 */
export async function cryptoToJWK(pair: CryptoKeyPair): Promise<JWKKeyPair> {
    const publicKeyJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const secretKeyJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    return { publicKeyJwk, secretKeyJwk }
}

/**
 * Convert a JWK key representation of a Key to WebCrypto's representation.
 *
 * @param key
 * @param usage - can be `["verify"]` or `["sign"]` for a public or private key, respectively.
 * @constructor
 * @return - a Promise with a CryptoKey
 * @async
 *
 */
export function JWKToCrypto(key: JsonWebKey, usage: KeyUsage[] = ["verify"]): Promise<CryptoKey> {
    const algorithm = ((): RsaHashedImportParams | EcKeyImportParams => {
        switch (key.kty as Kty) {
            case 'RSA' :
                return {
                    name: "RSA-PSS",
                    hash: key.alg === "PS256" ? "SHA-256" : "SHA-384"
                }
            case 'EC':
                return {
                    name: "ECDSA",
                    namedCurve: key.crv || DEFAULT_CURVE
                }
            case 'OKP':
                return {
                    name: "Ed25519",
                    // This is here to make TS happy and because the WebCrypto type specification did not make this optional
                    namedCurve: ""
                }
            default:
                // In fact, this does not happen; the JWK comes from our own
                // generation, that raises an error earlier in this case.
                // But this keeps typescript happy...
                throw new Error("Unknown kty value for the JWK key");
        }
    })();
    return crypto.subtle.importKey("jwk", key, algorithm, true, usage);
}

/**
 * Convert a public/private key pair in JWK to WebCrypto's binary representation.
 * @param keys
 * @constructor
 * @return a Promise with a CryptoKey pair
 * @async
 */
export async function JWKKeyPairToCrypto(keys: JWKKeyPair ): Promise<CryptoKeyPair> {
    const [ publicKey , privateKey ]: [CryptoKey,CryptoKey] = await Promise.all([
        JWKToCrypto(keys.publicKeyJwk, ["verify"]),
        JWKToCrypto(keys.secretKeyJwk, ["sign"]),
    ]);
    return {
        publicKey, privateKey
    };
}

