/**
 * TinyPKI ClientSideCertReq Library
 *
 * Single-file JavaScript library for classic HTML web applications. Features client-side CSR generation
 * for RSA/ECDSA key pairs from Web Crypto API, after the certificate is issued, also allows to bundle
 * the certificate chain and the private key together into a locally-generated PKCS#12 container
 * that is easily installable in most operating systems and browsers.
 */

import type {IGenerateCSRParams} from "./api/generateCSR";
import type {IGeneratePKCS12Params} from "./api/generatePKCS12";
import type {IGenerateSelfSignedCertParams} from "./api/generateSelfSignedCert";

import {exportKeyDERB64} from "./api/exportKeyDERB64";
import {generateCSR} from "./api/generateCSR";
import {generatePKCS12} from "./api/generatePKCS12";
import {savePKCS12BufferAsFile} from "./api/savePKCS12BufferAsFile";
import {base64ToBuffer} from "./api/base64ToBuffer";
import {generateSelfSignedCert} from "./api/generateSelfSignedCert";

export type {
    IGenerateCSRParams,
    IGeneratePKCS12Params,
    IGenerateSelfSignedCertParams,
};

export {
    generateCSR,
    generatePKCS12,

    // helpers
    exportKeyDERB64,
    base64ToBuffer,
    savePKCS12BufferAsFile,

    // helper for the demo purposes
    generateSelfSignedCert,
};
