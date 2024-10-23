export type { HashAlgorithm, CryptoAlgorithm, KeyOptions } from "./lib/types.ts";
import { createNewKeys } from "./lib/keys.ts";
import { CryptoAlgorithm, KeyOptions, JWKKeyPair } from "./lib/types.ts";


// export async function createKey(crypto, options): Promise<KeyPair> {}
// export async function sign(message: string, keypair: KeyPair): Promise<string> {}
// export async function verify(message: string, signature: string, publicKey: key): Promise<boolean> {};

// export async function random(size: number): Promise<string> {};

// export async function hash(message: string, algorithm: HashAlgorithm): Promise<string> {};

// export async function encrypt(message: string, keyPair: KeyPair): Promise<string> {};
// export async function decrypt(encryptedMessage: string, publickey: key): Promise<string> {};

export { calculateHash as hash } from "./lib/hash.ts";
// deno-lint-ignore require-await
export async function generateKeys(algorithm: CryptoAlgorithm, options: KeyOptions = {}): Promise<JWKKeyPair> {
    return createNewKeys(algorithm, options);
}
