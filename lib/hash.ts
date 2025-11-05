/**
 * Hashing function; useful for crypto users, though not used by the rest of the package.
 *
 * @module
 */
import type * as types from "./types.ts";
import { textToBytes } from "./utils.ts";

/**
 * Calculate Hash of a string
 *
 * @param input
 * @param sh_func - can be `"SHA-256"` or `"SHA-384"`
 * @result - the hash value in hexadecimal format.
 */
export async function calculateHash(input: string, sh_func: types.HashAlgorithm = "SHA-256"): Promise<string> {
    const data: Uint8Array = textToBytes(input);
    const hashBuffer = await crypto.subtle.digest(sh_func, data.buffer as ArrayBuffer);

    const hashArray = Array.from(new Uint8Array(hashBuffer));

    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
