(function () {
  window.DENO_DOC_SEARCH_INDEX = {"nodes":[{"kind":[{"kind":"TypeAlias","char":"T","title":"Type Alias","title_lowercase":"type alias","title_plural":"Type Aliases"}],"name":"BaseEncoding","file":".","doc":"Base encoding alternatives","location":{"filename":"","line":16,"col":0,"byteIndex":381},"url":"././~/BaseEncoding.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"TypeAlias","char":"T","title":"Type Alias","title_lowercase":"type alias","title_plural":"Type Aliases"}],"name":"CryptoAlgorithm","file":".","doc":"Crypto identifier values that are relevant for this package","location":{"filename":"","line":11,"col":0,"byteIndex":361},"url":"././~/CryptoAlgorithm.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"TypeAlias","char":"T","title":"Type Alias","title_lowercase":"type alias","title_plural":"Type Aliases"}],"name":"HashAlgorithm","file":".","doc":"Crypto hash values that are relevant for this package","location":{"filename":"","line":13,"col":0,"byteIndex":294},"url":"././~/HashAlgorithm.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Interface","char":"I","title":"Interface","title_lowercase":"interface","title_plural":"Interfaces"}],"name":"KeyOptions","file":".","doc":"","location":{"filename":"","line":18,"col":0,"byteIndex":430},"url":"././~/KeyOptions.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Property","char":"p","title":"Property","title_lowercase":"property","title_plural":"Properties"}],"name":"KeyOptions.namedCurve","file":".","doc":"","location":{"filename":"","line":19,"col":4,"byteIndex":464},"url":"././~/KeyOptions.namedCurve.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Property","char":"p","title":"Property","title_lowercase":"property","title_plural":"Properties"}],"name":"KeyOptions.hash","file":".","doc":"","location":{"filename":"","line":20,"col":4,"byteIndex":490},"url":"././~/KeyOptions.hash.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Property","char":"p","title":"Property","title_lowercase":"property","title_plural":"Properties"}],"name":"KeyOptions.saltLength","file":".","doc":"","location":{"filename":"","line":21,"col":4,"byteIndex":526},"url":"././~/KeyOptions.saltLength.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Property","char":"p","title":"Property","title_lowercase":"property","title_plural":"Properties"}],"name":"KeyOptions.modulusLength","file":".","doc":"","location":{"filename":"","line":22,"col":4,"byteIndex":555},"url":"././~/KeyOptions.modulusLength.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Interface","char":"I","title":"Interface","title_lowercase":"interface","title_plural":"Interfaces"}],"name":"OutputOptions","file":".","doc":"Options for the output of signing/verifying and for encryption/decryption","location":{"filename":"","line":37,"col":0,"byteIndex":885},"url":"././~/OutputOptions.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Property","char":"p","title":"Property","title_lowercase":"property","title_plural":"Properties"}],"name":"OutputOptions.encoding","file":".","doc":"Base encoding choice for the generated signature","location":{"filename":"","line":39,"col":4,"byteIndex":982},"url":"././~/OutputOptions.encoding.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Property","char":"p","title":"Property","title_lowercase":"property","title_plural":"Properties"}],"name":"OutputOptions.format","file":".","doc":"Format of the final signature: plain encoded text, or Multibase","location":{"filename":"","line":41,"col":4,"byteIndex":1087},"url":"././~/OutputOptions.format.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Function","char":"f","title":"Function","title_lowercase":"function","title_plural":"Functions"}],"name":"decrypt","file":".","doc":"Decrypt a ciphertext.\n","location":{"filename":"","line":103,"col":0,"byteIndex":3702},"url":"././~/decrypt.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Function","char":"f","title":"Function","title_lowercase":"function","title_plural":"Functions"}],"name":"encrypt","file":".","doc":"Encrypt a message.\n","location":{"filename":"","line":76,"col":0,"byteIndex":2739},"url":"././~/encrypt.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Function","char":"f","title":"Function","title_lowercase":"function","title_plural":"Functions"}],"name":"generateKeysJWK","file":".","doc":"Generate a new public/private key pair in one of the ecdsa/eddsa/RSA crypto algorithms\n(the term Ed25519 can also be used for eddsa). The result is a pair or JWK format for keys.\n\nSome of the algorithms can be (optionally) parametrized through the key options:\n\n* For ecdsa: the `nameCurve` field can be set to `\"P-256\"` or `\"P-384\"` to change the EC curve. Default is `\"P-256\"`\n* For RSA:\n    * can be set to the modulus length of the key can be set with `modulusLength`. Value can be 1024, 2048, or 4096;\n    default is 2048\n    * the `hash` value can be set to `\"SHA-256\"` or `\"SHA-384\"`; default is \"SHA-256\"`\n","location":{"filename":"default","line":25,"col":0,"byteIndex":1282},"url":"././~/generateKeysJWK.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Function","char":"f","title":"Function","title_lowercase":"function","title_plural":"Functions"}],"name":"generateKeysMK","file":".","doc":"Generate a new public/private key pair in one of the ecdsa or eddsa crypto algorithms\n(the term Ed25519 can also be used for eddsa). The result is a pair or Multibase formatted keys, i.e., in Multikey.\n\nEcdsa can be (optionally) parametrized through the key options: the `nameCurve` field can be set to `\"P-256\"`\nor `\"P-384\"` to change the EC curve. Default is `\"P-256\"`\n","location":{"filename":"default","line":40,"col":0,"byteIndex":2002},"url":"././~/generateKeysMK.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Function","char":"f","title":"Function","title_lowercase":"function","title_plural":"Functions"}],"name":"hash","file":".","doc":"Calculate Hash of a string\n","location":{"filename":"","line":16,"col":0,"byteIndex":368},"url":"././~/hash.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Function","char":"f","title":"Function","title_lowercase":"function","title_plural":"Functions"}],"name":"sign","file":".","doc":"Sign a message.\n","location":{"filename":"","line":21,"col":0,"byteIndex":673},"url":"././~/sign.html","category":"","declarationKind":"export","deprecated":false},{"kind":[{"kind":"Function","char":"f","title":"Function","title_lowercase":"function","title_plural":"Functions"}],"name":"verify","file":".","doc":"Verify a signature.\n\nNote that if the signature option refers to multibase, the values of encoding is ignored (and is deduced from the\nmultibase itself).\n","location":{"filename":"","line":52,"col":0,"byteIndex":1792},"url":"././~/verify.html","category":"","declarationKind":"export","deprecated":false}]};
})()