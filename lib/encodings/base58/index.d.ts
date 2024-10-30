
/**
 * Encoder function for base58url, needed for the Multikey encoding
 * 
 * @param input 
 * @returns
 */
export function encode(input: Uint8Array): string;

/**
 * Decoder function for base58url, needed for the Multikey encoding
 * 
 * @param input 
 * @returns
 */
export function decode(input: string): Uint8Array;
