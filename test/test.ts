import { hash, generateKeysJWK, generateKeysMK, sign, verify } from "../index.ts";
// import { isMultibase, isMultikey } from "../index.ts";

const message = "Something about this; ";

const hash_256 = await hash(message)
const hash_384 = await hash(message, "SHA-384");

console.log(`Hash 256: ${hash_256}`);
console.log(`Hash 384: ${hash_384}`);

const keyPairJWK = await generateKeysJWK("eddsa");
console.log(`New key pair in JWK: ${JSON.stringify(keyPairJWK,null,4)}`)

const keyPairMK = await generateKeysMK("eddsa");
console.log(`New key pair in Multikeys: ${JSON.stringify(keyPairMK, null, 4)}`);

// Sign/verifiy with JWK
const signatureJWK: string = await sign(message, keyPairJWK, "base58");
const verifiedJWK: boolean = await verify(message, signatureJWK, keyPairJWK.publicKey, "base58");
console.log(`JWK Signature: ${signatureJWK} with verification result: ${verifiedJWK}`);

// Sign/verifiy with MK
const signatureMK: string = await sign(message, keyPairMK, "base58");
const verifiedMK: boolean = await verify(message, signatureMK, keyPairMK.publicKeyMultibase, "base58");
console.log(`MK Signature: ${signatureMK} with verification result: ${verifiedMK}`);

// const keyPairRSA = await generateKeysJWK("rsa");
// console.log(`New key pair for RSA: ${JSON.stringify(keyPairRSA, null, 4)}`);
//
// const signatureRSA: string = await sign(message, keyPairRSA);
// const verifiedRSA: boolean = await verify(message, signatureRSA, keyPairRSA.publicKey);
// console.log(`RSA Signature: ${signatureRSA} with verification result: ${verifiedRSA}`);

// console.log(`Multikey (should be true): ${isMultikey(keyPairMK)}`);
// console.log(`Multikey (should be false): ${isMultikey(keyPairJWK)}`);


