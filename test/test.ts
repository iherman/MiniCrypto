import { hash, generateKeysJWK, generateKeysMK, sign, verify, encrypt, decrypt } from "../index.ts";
// import { isMultibase, isMultikey } from "../index.ts";

const message = "Something about this; ";

const hash_256 = await hash(message)
const hash_384 = await hash(message, "SHA-384");

console.log(`Hash 256: ${hash_256}`);
console.log(`Hash 384: ${hash_384}`);

// const keyPairJWK = await generateKeysJWK("eddsa");
// console.log(`New key pair in JWK: ${JSON.stringify(keyPairJWK,null,4)}`)
//
// const keyPairMK = await generateKeysMK("eddsa");
// console.log(`New key pair in Multikeys: ${JSON.stringify(keyPairMK, null, 4)}`);
//
// // Sign/verify with JWK
// const signatureJWK: string = await sign(message, keyPairJWK,{encoding: "base64"});
// const verifiedJWK: boolean = await verify(message, signatureJWK, keyPairJWK.publicKeyJwk, {encoding: "base64"});
// console.log(`JWK Signature: ${signatureJWK} with verification result: ${verifiedJWK}`);
//
// // Sign/verify with MK
// const signatureMK: string = await sign(message, keyPairMK, {encoding: "base58"});
// const verifiedMK: boolean = await verify(message, signatureMK, keyPairMK.publicKeyMultibase, {encoding: "base58"});
// console.log(`MK Signature with base58, plain: ${signatureMK} with verification result: ${verifiedMK}`);
//
// const signatureMKmb: string = await sign(message, keyPairMK, {encoding: "base58", format: "multibase"});
// const verifiedMKmb: boolean = await verify(message, signatureMKmb, keyPairMK.publicKeyMultibase, {encoding: "base58", format: "multibase"});
// console.log(`MK Signature with base58, multibase: ${signatureMKmb} with verification result: ${verifiedMKmb}`);



// console.log(`Multikey (should be true): ${isMultikey(keyPairMK)}`);
// console.log(`Multikey (should be false): ${isMultikey(keyPairJWK)}`);

// const keyPairRSA = await generateKeysJWK("rsa-pss");
// console.log(`\nNew key pair for RSA PSS: ${JSON.stringify(keyPairRSA, null, 4)}`);
//
// const signatureRSA: string = await sign(message, keyPairRSA);
// const verifiedRSA: boolean = await verify(message, signatureRSA, keyPairRSA.publicKeyJwk);
// console.log(`\nRSA Signature: ${signatureRSA} with verification result: ${verifiedRSA}`);

const keyPairRSA_E = await generateKeysJWK("rsa-oaep", {hash: "SHA-384"});
console.log(`\nNew key pair for RSA OAEP: ${JSON.stringify(keyPairRSA_E, null, 4)}`);

const cipherText = await encrypt(message, keyPairRSA_E.publicKeyJwk, {format: "multibase", encoding: "base58"});
console.log(`Encrypted message: "${cipherText}"`);

const decryptedText = await decrypt(cipherText, keyPairRSA_E.secretKeyJwk);
console.log(`Decrypted message: "${decryptedText}"`);


