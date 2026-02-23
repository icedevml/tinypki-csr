import * as x509 from "@peculiar/x509";

export interface IGenerateSelfSignedCertParams {
    keys: CryptoKeyPair
    algorithm: RsaHashedKeyGenParams | RsaPssParams | EcKeyGenParams | EcdsaParams
}

export async function generateSelfSignedCert({algorithm, keys}: IGenerateSelfSignedCertParams): Promise<string> {
    // notBefore: -1 minute relatively to the issuance time
    const notBefore = new Date(+new Date() - (1000 * 60));
    // notAfter: +7 days relatively to the issuance time
    const notAfter = new Date(+new Date() + (1000 * 60 * 60 * 24 * 30));

    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: "CN=TinyPKI clientSideCertReqLib Demo",
        notBefore: notBefore,
        notAfter: notAfter,
        signingAlgorithm: algorithm,
        keys,
        extensions: [
            new x509.BasicConstraintsExtension(true, 2, true),
            new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        ]
    });

    return cert.toString("pem");
}
