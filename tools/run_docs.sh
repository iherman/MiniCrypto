#!/usr/bin/env sh
# shellcheck disable=SC2164
cp index.ts multikey_webcrypto.ts
deno run -A tools/copy_readme.ts
deno doc --html --name="Mini Crypto API" index.ts lib/*
mv multikey_webcrypto.ts index.ts
(cd docs; touch .nojekyll)
