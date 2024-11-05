import { base64 }   from "../lib/encodingMultibase.ts";
import * as bOld    from "../.Attic/encodings/base64.ts";

const message: string = "This is just a simple text message.";
const rawMessage: ArrayBuffer = (new TextEncoder()).encode(message).buffer;
const UintMessage : Uint8Array = new Uint8Array(rawMessage);

const base64Old = bOld.encode(UintMessage);
const base64New: string = base64.encode(UintMessage);

console.log(`Old base64 encoding: "${base64Old}"`);
console.log(`New base64 encoding: "${base64New}"`);


