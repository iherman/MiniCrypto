import { hash, generateKeysJWK, generateKeysMK, sign, verify } from "../index.ts";

const message = "Something about this; ";

const hash_256 = await hash(message)
const hash_384 = await hash(message, "SHA-384");

console.log(`Hash 256: ${hash_256}`);
console.log(`Hash 384: ${hash_384}`);

const keyPairJWK = await generateKeysJWK("ecdsa", { namedCurve : "P-256"});
console.log(`New key pair in JWK: ${JSON.stringify(keyPairJWK,null,4)}`)

// const keyPairMK = await generateKeysMK("ecdsa", { namedCurve: "P-384" });
// console.log(`New key pair in Multikeys: ${JSON.stringify(keyPairMK, null, 4)}`);

const signature: string = await sign(message, keyPairJWK);

const verified: boolean = await verify(message, signature, keyPairJWK.publicKey);

console.log(`Signature: ${signature} with verification result: ${verified}`);

// const keyPairRSA = await generateKeysJWK("rsa");
// console.log(`New key pair for RSA: ${JSON.stringify(keyPairRSA, null, 4)}`);
