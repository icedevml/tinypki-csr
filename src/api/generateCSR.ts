import * as x509 from "@peculiar/x509";
import {JsonGeneralName} from "@peculiar/x509";

export interface IGenerateCSRParams {
    keys: CryptoKeyPair
    algorithm: RsaHashedKeyGenParams | RsaPssParams | EcKeyGenParams | EcdsaParams
    commonName: string
    subjectAltNames: string[]
}

type PEMString = string;

export async function generateCSR({
                                      keys,
                                      algorithm,
                                      commonName,
                                      subjectAltNames
                                  }: IGenerateCSRParams): Promise<PEMString> {
    const ALLOWED_PREFIXES = [
        "dns", "dn", "email", "ip", "url", "guid", "upn", "id"
    ];

    const sansExtValues: JsonGeneralName[] = [];

    for (const san of subjectAltNames) {
        const throwTypeError = () => {
            throw TypeError("Invalid subject alternative name: " + san + ". " +
                "Does not contain one of the supported prefixes: " + JSON.stringify(ALLOWED_PREFIXES) + ".");
        };

        const ndx = san.indexOf(":");

        if (ndx === -1) {
            throwTypeError();
        }

        const type = san.substring(0, ndx);
        const val = san.substring(ndx + 1);

        if (ALLOWED_PREFIXES.indexOf(type) === -1) {
            throwTypeError();
        }

        sansExtValues.push({
            "type": type,
            "value": val
        } as JsonGeneralName);
    }

    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: [{"CN": [commonName]}],
        keys,
        signingAlgorithm: algorithm,
        extensions: [
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
            new x509.SubjectAlternativeNameExtension(sansExtValues)
        ],
        attributes: []
    });

    return csr.toString("pem");
}
