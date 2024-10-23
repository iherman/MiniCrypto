import * as types from "./types.ts";
/**
 * Calculate Hash
 * @param input 
 * @param sh_func 
 * @returns 
 */
export async function calculateHash(input: string, sh_func: types.HashAlgorithm = "SHA-256"): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await crypto.subtle.digest(sh_func, data);

    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex;
}
