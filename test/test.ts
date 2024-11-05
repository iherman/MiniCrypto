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

// Sign/verify with JWK
const signatureJWK: string = await sign(message, keyPairJWK,{encoding: "base64"});
const verifiedJWK: boolean = await verify(message, signatureJWK, keyPairJWK.publicKeyJwk, {encoding: "base64"});
console.log(`JWK Signature: ${signatureJWK} with verification result: ${verifiedJWK}`);

// Sign/verify with MK
const signatureMK: string = await sign(message, keyPairMK, {encoding: "base58"});
const verifiedMK: boolean = await verify(message, signatureMK, keyPairMK.publicKeyMultibase, {encoding: "base58"});
console.log(`MK Signature with base58, plain: ${signatureMK} with verification result: ${verifiedMK}`);

const signatureMKmb: string = await sign(message, keyPairMK, {encoding: "base58", format: "multibase"});
const verifiedMKmb: boolean = await verify(message, signatureMKmb, keyPairMK.publicKeyMultibase, {encoding: "base58", format: "multibase"});
console.log(`MK Signature with base58, multibase: ${signatureMKmb} with verification result: ${verifiedMKmb}`);



// const keyPairRSA = await generateKeysJWK("rsa");
// console.log(`New key pair for RSA: ${JSON.stringify(keyPairRSA, null, 4)}`);
//
// const signatureRSA: string = await sign(message, keyPairRSA);
// const verifiedRSA: boolean = await verify(message, signatureRSA, keyPairRSA.publicKey);
// console.log(`RSA Signature: ${signatureRSA} with verification result: ${verifiedRSA}`);

// console.log(`Multikey (should be true): ${isMultikey(keyPairMK)}`);
// console.log(`Multikey (should be false): ${isMultikey(keyPairJWK)}`);


