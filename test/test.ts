import {hash, generateKeys } from "../index.ts";

const message = "Something about this; ";

const hash_256 = await hash(message)
const hash_512 = await hash(message, "SHA-512");

console.log(`Hash 256: ${hash_256}`);
console.log(`Hash 512: ${hash_512}`);

const keyPairJWK = await generateKeys("ecdsa", { namedCurve : "P-384"});
console.log(`New key pair in JWK: ${JSON.stringify(keyPairJWK,null,4)}`)

const keyPairMK = await generateKeys("ecdsa", { namedCurve: "P-384", encoding: "Multikey" });
console.log(`New key pair in Multikeys: ${JSON.stringify(keyPairMK, null, 4)}`);
