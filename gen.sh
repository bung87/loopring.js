#!/usr/bin/env bash

browserify  -r ./src/keystore.js:keystore  > ./dist/keystore.js
browserify  -r ./src/wallet.js:wallet  > ./dist/wallet.js
browserify  -r ./src/validator.js:validator  > ./dist/validator.js
browserify  -r ./src/signer.js:signer  > ./dist/signer.js
browserify -r ethereumjs-util -r ./src/relay.js:relay  > ./dist/relay.js
