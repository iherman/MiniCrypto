import { assertEquals, assert } from "jsr:@std/assert";
import {
    generateKeysJWK, generateKeysMK,
    sign, verify,
    encrypt, decrypt
} from "../index.ts";
import { isMultibase, isMultikey } from "../lib/utils.ts";

/* Putting here a chinese text to see if everything works on non-trivial Unicode text, too: */
const message: string = "This is the basic message used all over the place. 郝易文";

/* *****************************************************************************************
* Tests with ecdsa and eddsa keys in JWK, generating a signature,
* stored in plain + base64 format
****************************************************************************************** */

Deno.test("1.1 Signature test: default JWK with eddsa", async () => {
    const keyPair = await generateKeysJWK("eddsa");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified, "Signature verification failed");
});

Deno.test("1.2 Signature test: default JWK with ed25519 (a.k.a. eddsa)", async () => {
    const keyPair = await generateKeysJWK("ed25519");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified, "Signature verification failed");
});

Deno.test("1.3 Signature test: default JWK with ecdsa", async () => {
    const keyPair = await generateKeysJWK("ecdsa");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified, "Signature verification failed");
});

Deno.test("1.4 Signature test: JWK with ecdsa and P-384 curve", async () => {
    const keyPair = await generateKeysJWK("ecdsa", {namedCurve: "P-384"});
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified, "Signature verification failed");
});

/* *****************************************************************************************
* Tests with ecdsa and eddsa keys in Multikey, generating a signature,
* stored in multibase + base58 format
****************************************************************************************** */

Deno.test("2.1 Signature test: default Multikey with eddsa", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair);
    assert(isMultibase(signature), "The signature is not Multibase")
    assert(signature[0] === 'z', "The signature is not Multibase base58")
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified, "Signature verification failed");
});

Deno.test("2.2 Signature test: default Multikey with ed25519 (a.k.a. eddsa)", async () => {
    const keyPair = await generateKeysMK("ed25519");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified);
});

Deno.test("2.3 Signature test: default Multikey with ecdsa", async () => {
    const keyPair = await generateKeysMK("ecdsa");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified, "Signature verification failed");
});

Deno.test("2.4 Signature test: Multikey with ecdsa and P-384 curve", async () => {
    const keyPair = await generateKeysMK("ecdsa", {namedCurve: "P-384"});
    assert(isMultikey(keyPair),"Key Pair should be Multikey");
    const signature: string = await sign(message, keyPair);
    // assert(!isMultibase(signature), "Signature should be a plain text, base64 encoded");
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified, "Signature verification failed");
});

/* *****************************************************************************************
* Tests with eddsa keys in Multikey, generating a signature,
* stored in different formats format
****************************************************************************************** */

Deno.test("3.1 Signature test: default Multikey with eddsa, signature in plain, base58", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair, {format: "plain", encoding: "base58"});
    assert(isMultibase(signature) === false, "The signature is not plain")
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase, {format: "plain", encoding: "base58"});
    assert(verified, "Signature verification failed");
});

Deno.test("3.2 Signature test: default Multikey with eddsa, signature in multibase, base64", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair, {encoding: "base64"});
    assert(isMultibase(signature), "The signature is not Multibase")
    assert(signature[0] === 'u', "The signature is not Multibase base64")
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase, {encoding: "base64" });
    assert(verified);
});

Deno.test("3.3 Signature test: default Multikey with eddsa, signature in multibase, base64 (recognized automatically)", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair, {format: "multibase", encoding: "base64"});
    assert(isMultibase(signature), "The signature is not Multibase");
    assert(signature[0] === 'u', "The signature is not Multibase base64");
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase, {format: "multibase"});
    assert(verified, "Signature verification failed");
});


/* *****************************************************************************************
* Tests with rsa keys in JWK, generating a signature,
* stored in plain, base64 format
****************************************************************************************** */

Deno.test("4.1 Signature test: JWK with rsa-pss", async () => {
    const keyPair = await generateKeysJWK("rsa-pss");
    const signature: string = await sign(message, keyPair);
    assert(isMultibase(signature) === false, "The signature is not plain")
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified, "Signature verification failed");
});

Deno.test("4.2 Signature test: JWK with rsa (a.k.a. rsa-pss)", async () => {
    const keyPair = await generateKeysJWK("rsa");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified, "Signature verification failed");
});

Deno.test.ignore("4.4 Signature test: JWK with rsa-pss, with modulus length of 4096 (ignored by default, it takes too much time...)", async () => {
    const keyPair = await generateKeysJWK("rsa-pss", {modulusLength: 4096});
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified, "Signature verification failed");
});

/* *****************************************************************************************
* Encryption tests with rsa keys in JWK, generating an encrypted message, decrypting it,
* and compare it with original.
* Encrypted data stored in plain, base64 format
****************************************************************************************** */
Deno.test("10.1 Encryption/decryption test: JWK with rsa-oaep, encrypted text in plain base64", async () => {
    const keyPair = await generateKeysJWK("rsa-oaep");
    const cipherText = await encrypt(message, keyPair.publicKeyJwk);
    assert(isMultibase(cipherText) === false, "The signature is not plain")
    const decryptedText = await decrypt(cipherText, keyPair.secretKeyJwk);
    assertEquals(message, decryptedText, "Decryption verification failed");
});

Deno.test("10.2 Encryption/decryption test: JWK with rsa-oaep, encrypted text in multibase base58", async () => {
    const keyPair = await generateKeysJWK("rsa-oaep");
    const cipherText = await encrypt(message, keyPair.publicKeyJwk, {format: "multibase", encoding: "base58"});
    assert(isMultibase(cipherText), "The cipherText is not Multibase");
    assert(cipherText[0] === 'z', "The cipherText is not encoded in base58");
    const decryptedText = await decrypt(cipherText, keyPair.secretKeyJwk, {format: "multibase"});
    assertEquals(message, decryptedText, "Decryption verification failed");
});

