# TinyPKI ClientSideCertReq Library

A part of TinyPKI project, with the intention to facilitate higher adoption of mTLS.

## Features
* Client-side PKCS#10 Certificate Signing Request (CSR) generation using Web Crypto API key pairs (supported: RSA/ECDSA/Ed25519);
* Bundling PEM certificate chain and private key together into PKCS#12 container (`.P12` or `.PFX` file);

## Demo

See the **[library demo](https://icedevml.github.io/tinypki-client-side-cert-req/)** for further reference.

## Installation

This library is distributed in two formats.

### ESM library
Suitable for SPA frameworks (like React.js), available on NPM Registry as [@icedevml/tinypki-client-side-cert-req](https://www.npmjs.com/package/@icedevml/tinypki-client-side-cert-req).

```bash
npm install --save @icedevml/tinypki-client-side-cert-req
yarn add @icedevml/tinypki-client-side-cert-req
```

### Single-file JavaScript bundle
Suitable for usage on classic HTML5 web pages, without requiring any external dependencies.
The entire bundle is approximately 500 kB.

Download: **[tinypki-client-side-cert-req-lib.js](https://github.com/icedevml/tinypki-client-side-cert-req/releases)**

## Usage

See [`demo/`](https://github.com/icedevml/tinypki-client-side-cert-req/tree/master/demo) directory for usage examples.

## Manual building

After cloning the repository, run the following commands:
```
yarn
yarn build
```
