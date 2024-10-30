import { hash, generateKeysJWK, generateKeysMK, sign, verify } from "../index.ts";

const message = "Something about this; ";

const hash_256 = await hash(message)
const hash_384 = await hash(message, "SHA-384");

console.log(`Hash 256: ${hash_256}`);
console.log(`Hash 384: ${hash_384}`);

const keyPairJWK = await generateKeysJWK("ecdsa");
console.log(`New key pair in JWK: ${JSON.stringify(keyPairJWK,null,4)}`)

// const keyPairMK = await generateKeysMK("ecdsa", { namedCurve: "P-384" });
// console.log(`New key pair in Multikeys: ${JSON.stringify(keyPairMK, null, 4)}`);

const signature: string = await sign(message, keyPairJWK, "base58");

const verified: boolean = await verify(message, signature, keyPairJWK.publicKey, "base58");

console.log(`Signature: ${signature} with verification result: ${verified}`);

// const keyPairRSA = await generateKeysJWK("rsa");
// console.log(`New key pair for RSA: ${JSON.stringify(keyPairRSA, null, 4)}`);
//
// const signatureRSA: string = await sign(message, keyPairRSA);
// const verifiedRSA: boolean = await verify(message, signatureRSA, keyPairRSA.publicKey);
// console.log(`RSA Signature: ${signatureRSA} with verification result: ${verifiedRSA}`);


