/**
 * The toPkcs12Asn1Generic() function was derived from the node-forge (digitalbazaar/forge) library:
 * https://github.com/digitalbazaar/forge/blob/1cea0aff4901589ae86e314f25782bbe312f9f69/lib/pkcs12.js#L800
 * I've hacked it around to support embedding arbitrary DER-encoded certificates and private keys
 * regardless of their algorithm, as the original library was only accepting RSA certificates/keys.
 *
 * Original license: dual-licensed under BSD-3 Clause License and GPL Version 2, depending on the user's choice.
 * This project opts to use the library on the terms of BSD-3 Claude License.
 * Full license statement is available here:
 * https://github.com/digitalbazaar/forge/blob/1cea0aff4901589ae86e314f25782bbe312f9f69/LICENSE
 *
 * Original author/copyright:
 *   @author Dave Longley
 *   @author Stefan Siegl <stesie@brokenpipe.de>
 *
 *   Copyright (c) 2010-2014 Digital Bazaar, Inc.
 *   Copyright (c) 2012 Stefan Siegl <stesie@brokenpipe.de>
 */

import {Buffer} from "buffer";
import * as forge from "node-forge";

const asn1 = forge.asn1;
const pki = forge.pki;
const p12 = forge.pkcs12;


const asn1FromDERB64 = function (data: string) {
    const buf = forge.util.createBuffer(Buffer.from(data, "base64"))
    return asn1.fromDer(buf, true);
}

export const toPkcs12Asn1Generic = function (key: string, cert: string | string[], password: string, options: any) {
    // set default options
    options = options || {};
    options.saltSize = options.saltSize || 8;
    options.count = options.count || 2048;
    options.algorithm = options.algorithm || options.encAlgorithm || 'aes128';
    if (!('useMac' in options)) {
        options.useMac = true;
    }
    if (!('localKeyId' in options)) {
        options.localKeyId = null;
    }
    if (!('generateLocalKeyId' in options)) {
        options.generateLocalKeyId = true;
    }

    var localKeyId = options.localKeyId;
    var bagAttrs;
    if (localKeyId !== null) {
        localKeyId = forge.util.hexToBytes(localKeyId);
    } else if (options.generateLocalKeyId) {
        // use SHA-1 of paired cert, if available
        if (cert) {
            var pairedCert = forge.util.isArray(cert) ? cert[0] : cert;
            if (typeof pairedCert === 'string') {
                // @ts-ignore
                pairedCert = asn1FromDERB64(pairedCert);
            }
            var sha1 = forge.md.sha1.create();
            // @ts-ignore
            sha1.update(asn1.toDer(pairedCert).getBytes());
            localKeyId = sha1.digest().getBytes();
        } else {
            // FIXME: consider using SHA-1 of public key (which can be generated
            // from private key components), see: cert.generateSubjectKeyIdentifier
            // generate random bytes
            localKeyId = forge.random.getBytes(20);
        }
    }

    var attrs = [];
    if (localKeyId !== null) {
        attrs.push(
            // localKeyID
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // attrId
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(pki.oids.localKeyId).getBytes()),
                // attrValues
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                        localKeyId)
                ])
            ]));
    }
    if ('friendlyName' in options) {
        attrs.push(
            // friendlyName
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // attrId
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(pki.oids.friendlyName).getBytes()),
                // attrValues
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BMPSTRING, false,
                        options.friendlyName)
                ])
            ]));
    }

    if (attrs.length > 0) {
        bagAttrs = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, attrs);
    }

    // collect contents for AuthenticatedSafe
    var contents = [];

    // create safe bag(s) for certificate chain
    var chain = [];
    if (cert !== null) {
        if (forge.util.isArray(cert)) {
            // @ts-ignore
            chain = cert;
        } else {
            chain = [cert];
        }
    }

    var certSafeBags = [];
    for (var i = 0; i < chain.length; ++i) {
        // convert cert from PEM as necessary
        cert = chain[i];
        if (typeof cert === 'string') {
            // @ts-ignore
            cert = asn1FromDERB64(cert);
        }

        // SafeBag
        var certBagAttrs = (i === 0) ? bagAttrs : undefined;
        // @ts-ignore
        var certAsn1 = cert;
        var certSafeBag =
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // bagId
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(pki.oids.certBag).getBytes()),
                // bagValue
                asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                    // CertBag
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                        // certId
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                            asn1.oidToDer(pki.oids.x509Certificate).getBytes()),
                        // certValue (x509Certificate)
                        asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                            asn1.create(
                                asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                                // @ts-ignore
                                asn1.toDer(certAsn1).getBytes())
                        ])])]),
                // bagAttributes (OPTIONAL)
                // @ts-ignore
                certBagAttrs
            ]);
        certSafeBags.push(certSafeBag);
    }

    if (certSafeBags.length > 0) {
        // SafeContents
        var certSafeContents = asn1.create(
            asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, certSafeBags);

        // ContentInfo
        var certCI =
            // PKCS#7 ContentInfo
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // contentType
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    // OID for the content type is 'data'
                    asn1.oidToDer(pki.oids.data).getBytes()),
                // content
                asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                    asn1.create(
                        asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                        asn1.toDer(certSafeContents).getBytes())
                ])
            ]);
        contents.push(certCI);
    }

    // create safe contents for private key
    var keyBag = null;
    if (key !== null) {
        // SafeBag
        var pkAsn1 = asn1FromDERB64(key);
        if (password === null) {
            // no encryption
            keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // bagId
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(pki.oids.keyBag).getBytes()),
                // bagValue
                asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                    // PrivateKeyInfo
                    pkAsn1
                ]),
                // bagAttributes (OPTIONAL)
                // @ts-ignore
                bagAttrs
            ]);
        } else {
            // encrypted PrivateKeyInfo
            keyBag = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // bagId
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(pki.oids.pkcs8ShroudedKeyBag).getBytes()),
                // bagValue
                asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                    // EncryptedPrivateKeyInfo
                    pki.encryptPrivateKeyInfo(pkAsn1, password, options)
                ]),
                // bagAttributes (OPTIONAL)
                // @ts-ignore
                bagAttrs
            ]);
        }

        // SafeContents
        var keySafeContents =
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [keyBag]);

        // ContentInfo
        var keyCI =
            // PKCS#7 ContentInfo
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // contentType
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    // OID for the content type is 'data'
                    asn1.oidToDer(pki.oids.data).getBytes()),
                // content
                asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                    asn1.create(
                        asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                        asn1.toDer(keySafeContents).getBytes())
                ])
            ]);
        contents.push(keyCI);
    }

    // create AuthenticatedSafe by stringing together the contents
    var safe = asn1.create(
        asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, contents);

    var macData;
    if (options.useMac) {
        // MacData
        var sha1 = forge.md.sha1.create();
        // @ts-ignore
        var macSalt = new forge.util.ByteBuffer(
            forge.random.getBytes(options.saltSize));
        var count = options.count;
        // 160-bit key
        // @ts-ignore
        var key = p12.generateKey(password, macSalt, 3, count, 20);
        var mac = forge.hmac.create();
        mac.start(sha1, key);
        mac.update(asn1.toDer(safe).getBytes());
        var macValue = mac.getMac();
        macData = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // mac DigestInfo
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // digestAlgorithm
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // algorithm = SHA-1
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        asn1.oidToDer(pki.oids.sha1).getBytes()),
                    // parameters = Null
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
                ]),
                // digest
                asn1.create(
                    asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING,
                    false, macValue.getBytes())
            ]),
            // macSalt OCTET STRING
            asn1.create(
                asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, macSalt.getBytes()),
            // iterations INTEGER (XXX: Only support count < 65536)
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                asn1.integerToDer(count).getBytes()
            )
        ]);
    }

    // PFX
    return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        // version (3)
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
            asn1.integerToDer(3).getBytes()),
        // PKCS#7 ContentInfo
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
            // contentType
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                // OID for the content type is 'data'
                asn1.oidToDer(pki.oids.data).getBytes()),
            // content
            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                asn1.create(
                    asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                    asn1.toDer(safe).getBytes())
            ])
        ]),
        // @ts-ignore
        macData
    ]);
};
