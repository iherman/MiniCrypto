import { encode as _encode, decode as _decode } from "./js/baseN.js";

export interface Encoder {
    encode(message: Uint8Array): string;
    decode(message: string): Uint8Array;
}

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

class Base64 extends Encoding  {
    constructor() {
        super("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
    }
}

class Base58 extends Encoding  {
    constructor() {
        super("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    }
}

export const base64 = new Base64();
export const base58 = new Base58();