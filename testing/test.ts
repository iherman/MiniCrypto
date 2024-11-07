import { assertEquals, assert } from "jsr:@std/assert";
import {
    generateKeysJWK, generateKeysMK,
    sign, verify,
    encrypt, decrypt
} from "../index.ts";
import { isMultibase, isMultikey } from "../lib/utils.ts";

/* Putting here some chinese text to see if comparison works: */
const message: string = "This is the basic message used all over the place.  郝易文";

/* *****************************************************************************************
* Tests with ecdsa and eddsa keys in JWK, generating a signature,
* stored in plain, base64 format
****************************************************************************************** */

Deno.test("1.1 Signature test: default JWK with eddsa", async () => {
    const keyPair = await generateKeysJWK("eddsa");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified);
});

Deno.test("1.2 Signature test: default JWK with ed25519 (a.k.a. eddsa)", async () => {
    const keyPair = await generateKeysJWK("ed25519");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified);
});

Deno.test("1.3 Signature test: default JWK with ecdsa", async () => {
    const keyPair = await generateKeysJWK("ecdsa");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified);
});

Deno.test("1.4 Signature test: JWK with ecdsa and P-384 curve", async () => {
    const keyPair = await generateKeysJWK("ecdsa", {namedCurve: "P-384"});
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified);
});

/* *****************************************************************************************
* Tests with ecdsa and eddsa keys in Multikey, generating a signature,
* stored in plain, base64 format
****************************************************************************************** */

Deno.test("2.1 Signature test: default Multikey with eddsa", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified);
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
    assert(verified);
});

Deno.test("2.4 Signature test: Multikey with ecdsa and P-384 curve", async () => {
    const keyPair = await generateKeysMK("ecdsa", {namedCurve: "P-384"});
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified);
});

/* *****************************************************************************************
* Tests with eddsa keys in Multikey, generating a signature,
* stored in different formats format
****************************************************************************************** */

Deno.test("3.1 Signature test: default Multikey with eddsa, signature in plain, base58", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair, {encoding: "base58"});
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase, {encoding: "base58"});
    assert(verified);
});

Deno.test("3.2 Signature test: default Multikey with eddsa, signature in multibase, base58", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair, {format: "multibase", encoding: "base58"});
    assert(isMultibase(signature))
    assert(signature[0] === 'z')
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified);
});

Deno.test("3.3 Signature test: default Multikey with eddsa, signature in multibase, base64", async () => {
    const keyPair = await generateKeysMK("eddsa");
    const signature: string = await sign(message, keyPair, {format: "multibase", encoding: "base64"});
    assert(isMultibase(signature))
    assert(signature[0] === 'u')
    const verified: boolean = await verify(message, signature, keyPair.publicKeyMultibase);
    assert(verified);
});


/* *****************************************************************************************
* Tests with rsa keys in JWK, generating a signature,
* stored in plain, base64 format
****************************************************************************************** */

Deno.test("4.1 Signature test: JWK with rsa-pss", async () => {
    const keyPair = await generateKeysJWK("rsa-pss");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified);
});

Deno.test("4.2 Signature test: JWK with rsa (a.k.a. rsa-pss)", async () => {
    const keyPair = await generateKeysJWK("rsa-pss");
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified);
});

Deno.test.ignore("4.4 Signature test: JWK with rsa-pss, with modulus length of 4096", async () => {
    const keyPair = await generateKeysJWK("rsa-pss", {modulusLength: 4096});
    const signature: string = await sign(message, keyPair);
    const verified: boolean = await verify(message, signature, keyPair.publicKeyJwk);
    assert(verified);
});

/* *****************************************************************************************
* Encryption tests with rsa keys in JWK, generating an encrypted message, decrypting it,
* and compare it with original.
* Encrypted data stored in plain, base64 format
****************************************************************************************** */
Deno.test("10.1 Encryption/decryption test: JWK with rsa-oaep, encrypted text in plain base64", async () => {
    const keyPair = await generateKeysJWK("rsa-oaep");
    const cipherText = await encrypt(message, keyPair.publicKeyJwk);
    const decryptedText = await decrypt(cipherText, keyPair.secretKeyJwk);
    assertEquals(message, decryptedText);
});

Deno.test("10.2 Encryption/decryption test: JWK with rsa-oaep, encrypted text in multibase base58", async () => {
    const keyPair = await generateKeysJWK("rsa-oaep");
    const cipherText = await encrypt(message, keyPair.publicKeyJwk, {format: "multibase", encoding: "base58"});
    assert(isMultibase(cipherText));
    assert(cipherText[0] === 'z');
    const decryptedText = await decrypt(cipherText, keyPair.secretKeyJwk, {format: "multibase"});
    assertEquals(message, decryptedText);
})

