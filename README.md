# TinyPKI ClientSideCertReq Library

A part of TinyPKI project, with the intention to facilitate higher adoption of mTLS.

## Features
* Client-side PKCS#10 Certificate Signing Request (CSR) generation using Web Crypto API key pairs (RSA/ECDSA/Ed25519);
* Bundling PEM certificate chain and private key together into PKCS#12 container (`.P12` or `.PFX` file);

## Installation

This library is distributed in two formats:
* ESM library installable from NPM Registry:
  ```
  npm install --save @icedevml/tinypki-client-side-cert-req
  # or
  yarn add @icedevml/tinypki-client-side-cert-req
  ```
* Single-file JavaScript bundle (approx 500 kB) suitable for including on any HTML5 web page without any external
  dependencies (see [GitHub Releases](https://github.com/icedevml/tinypki-client-side-cert-req/releases) for pre-built files)

## Manual building

```
yarn
yarn build
```

## Usage

See `demo/` directory for example usage.
