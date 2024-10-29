import * as multikeys from "npm:multikey-webcrypto";

import { createNewKeys, cryptoToJWK }              from "./lib/keys.ts";
import { CryptoAlgorithm, KeyOptions, JWKKeyPair } from "./lib/types.ts";

export type { HashAlgorithm, CryptoAlgorithm, KeyOptions } from "./lib/types.ts";


// export async function createKey(crypto, options): Promise<KeyPair> {}
// export async function sign(message: string, keypair: KeyPair): Promise<string> {}
// export async function verify(message: string, signature: string, publicKey: key): Promise<boolean> {};

// export async function random(size: number): Promise<string> {};

// export async function hash(message: string, algorithm: HashAlgorithm): Promise<string> {};

// export async function encrypt(message: string, keyPair: KeyPair): Promise<string> {};
// export async function decrypt(encryptedMessage: string, publickey: key): Promise<string> {};

export { calculateHash as hash } from "./lib/hash.ts";

export async function generateKeysJWK(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<JWKKeyPair> {
    const keys: CryptoKeyPair = await createNewKeys(algorithm, options);
    return cryptoToJWK(keys);
}

export async function generateKeysMK(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<multikeys.Multikey> {
    const keys: CryptoKeyPair = await createNewKeys(algorithm, options);
    return multikeys.cryptoToMultikey(keys);
}

export { sign, verify } from "./lib/sign.ts"


