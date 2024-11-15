import { build, emptyDir } from "jsr:@deno/dnt";

await emptyDir("./.npm");

await build({
    entryPoints: ["./index.ts"],
    outDir: "./.npm",
    shims: {
        // see JS docs for overview and more options
        deno: true,
    },
    importMap: "deno.json",
    package: {
        // package.json properties
        name: "minicrypto",
        version: "0.5.0",
        description: "Set of functions that can be used to perform basic cryptographic functions hiding all the intricacies of WebCrypto.",
        license: "W3C-20150513",
        repository: {
            type: "git",
            url: "git+https://github.com/iherman/MiniCrypto.git",
        },
        bugs: {
            url: "https://github.com/iherman/MiniCrypto/issues",
        },
    },
    postBuild() {
        // steps to run after building and before running the tests
        Deno.copyFileSync("LICENSE.md", ".npm/LICENSE.md");
        Deno.copyFileSync("README.md", ".npm/README.md");
    },
});