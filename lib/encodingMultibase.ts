/**
 * Base64 and base58 encoding and decoding per the DI Controller Document specification
 * (see {@link https://www.w3.org/TR/controller-document/#multibase-0}). To be fully precise
 * the base64 is base-64-url-no-pad, and base58 is base-58-btc. The alphabets used
 * in this code relies on the aforementioned specification.
 *
 * @module
 */
import { encode as _encode, decode as _decode } from "./js/baseN.js";

/**
 * The simple interface that the world sees...
 */
export interface Encoder {
    encode(message: Uint8Array): string;
    decode(message: string): Uint8Array;
}

/**
 * Top level class which is only seen through it subclasses that
 * set the right alphabet
 */
class Encoding implements Encoder {
    private readonly alphabet: string;

    constructor(alphabet: string) {
        this.alphabet = alphabet;
    }

    encode(message: Uint8Array): string {
        return _encode(message, this.alphabet, 0);
    }

    decode(message: string): Uint8Array {
        return _decode(message, this.alphabet);
    }
}

/**
 * base-64-url-no-pad encoding, with the following alphabet:
 *
 * > ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
 *
 */
class Base64 extends Encoding  {
    constructor() {
        super("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
    }
}

/**
 *  base-58-btc encoding, with the following alphabet:
 *
 *  > 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
 *
 */
class Base58 extends Encoding  {
    constructor() {
        super("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    }
}

/** The base64 encoder/decoder instance seen by the outside world... */
export const base64 = new Base64();

/** The base64 encoder/decoder instance seen by the outside world... */
export const base58 = new Base58();