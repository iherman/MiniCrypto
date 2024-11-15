/**
 * Key management operations: creation in binary Crypto, JWK, or Multikey formats. Note that Multikeys are only
 * defined for ecdsa and eddsa; it cannot be used for rsa algorithms.
 *
 * The module also includes functions to convert JWK to and from binary crypto. See the separate
 * `multikey-webcrypto` for similar operations with Multikey formats.
 *
 * @module
 */
import type { KeyOptions, JWKeyPair } from './types.ts';
import type { WebCryptoAPIData }      from './utils.ts';

/** JWK values for the key types that are relevant for this package */
type Kty = "EC" | "RSA" | "OKP";

/**
 * Crypto identifier values that are relevant for this package. "rsa" is an alias for "rsa-pss";
 * "ed25519" is an alias for "eddsa".
 *
 * Only "rsa-oaep" can be used for encryption/decryption, but it cannot be used for signatures. All the
 * others can only be used for signature and verification.
 */
export type CryptoAlgorithm = "ecdsa" | "eddsa" | "ed25519" | "rsa-pss" | "rsa" | "rsa-oaep";

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
 * @async
 */
export function generateKeys(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<CryptoKeyPair> {
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

    interface KeyGenerationOptions {
        cryptoDetails: WebCryptoAPIData,
        keyUsages: KeyUsage[],
    }
    const DEFAULT_KEY_USAGES: KeyUsage[] = ["sign", "verify"];

    const cryptoOptions: KeyGenerationOptions = ((): KeyGenerationOptions => {
        switch(algorithm.toLowerCase()) {
            case "rsa-oaep": {
                return {
                    cryptoDetails : {
                        name: "RSA-OAEP",
                        modulusLength,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: options?.hash || DEFAULT_HASH_ALGORITHM
                    },
                    keyUsages: ["encrypt", "decrypt"],
                }
            }
            case "rsa-pss":
            case "rsa": {
                return {
                    cryptoDetails : {
                        name: "RSA-PSS",
                        modulusLength,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: options?.hash || DEFAULT_HASH_ALGORITHM
                    },
                    keyUsages: DEFAULT_KEY_USAGES,
                }
            }
            case "ecdsa" : {
                return {
                    cryptoDetails: {
                        name: "ECDSA",
                        namedCurve: options?.namedCurve || DEFAULT_CURVE
                    },
                    keyUsages: DEFAULT_KEY_USAGES,
                }
            }
            case "eddsa" :
            case "ed25519":
            default:
                return {
                    cryptoDetails : {
                        name : "Ed25519"
                    },
                    keyUsages: DEFAULT_KEY_USAGES,
                }
        }
    })();
    return crypto.subtle.generateKey(cryptoOptions.cryptoDetails, true, cryptoOptions.keyUsages) as Promise<CryptoKeyPair>;
}

/**
 * Convert a JWK key representation of a Key to WebCrypto's representation.
 *
 * @param key
 * @param usage - can be `["verify"]/["encrypt"]` or `["sign"]/["decrypt"]` for a public or private key, respectively
 * @constructor
 * @async
 *
 */
export function JWKeyToCrypto(key: JsonWebKey, usage: KeyUsage[] = ["verify"]): Promise<CryptoKey> {
    const algorithm = ((): RsaHashedImportParams | EcKeyImportParams => {
        switch (key.kty as Kty) {
            // deno-lint-ignore no-fallthrough
            case 'RSA' :
                switch (key.alg) {
                    case "RSA-OAEP-384" :
                        return {
                            name: "RSA-OAEP",
                            hash: "SHA-384",
                        }
                    case "RSA-OAEP-256" :
                        return {
                            name: "RSA-OAEP",
                            hash: "SHA-256",
                        }
                    case "PS384" :
                        return {
                            name: "RSA-PSS",
                            hash: "SHA-384",
                        }
                    case "PS256" :
                    default:
                        return {
                            name: "RSA-PSS",
                            hash: "SHA-256",
                        }
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
                throw new Error("Unknown kty value for the JWK key");
        }
    })();
    return crypto.subtle.importKey("jwk", key, algorithm, true, usage);
}


/**
 * Convert a public/private key pair in JWK to WebCrypto's binary representation.
 *
 * @param keys
 * @constructor
 * @async
 */
export async function JWKeyPairToCrypto(keys: JWKeyPair): Promise<CryptoKeyPair> {
    // We have to separate the RSA OAEP case from the others to specify the "usage" setting.
    const usages: KeyUsage[] = ((): KeyUsage[] => {
            const publicUsage: KeyUsage = keys.publicKeyJwk?.alg?.startsWith("RSA-OAEP") ? "encrypt" : "verify";
            const secretUsage: KeyUsage = keys.secretKeyJwk?.alg?.startsWith("RSA-OAEP") ? "decrypt" : "sign";
            return [publicUsage, secretUsage];
        }
    )();

    const [ publicKey , privateKey ]: [CryptoKey,CryptoKey] = await Promise.all([
        JWKeyToCrypto(keys.publicKeyJwk, [usages[0]]),
        JWKeyToCrypto(keys.secretKeyJwk, [usages[1]]),
    ]);
    return {
        publicKey, privateKey
    };
}

