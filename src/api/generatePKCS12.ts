import * as forge from "node-forge";

import {toPkcs12Asn1Generic} from "../internal/toPkcs12Asn1Generic";
import {pemChainToDERB64Array} from "../internal/pemChainToDERB64Array";

type PEMString = string;
type Base64EncodedDER = string;

type PKCS12Algorithm = "3des" | "aes128" | "aes192" | "aes256";

export interface IGeneratePKCS12Params {
    algorithm: RsaHashedKeyGenParams | EcKeyGenParams
    certChainPEM: PEMString
    privKeyDERB64: Base64EncodedDER
    pkcs12Password: string
    pkcs12Algorithm?: PKCS12Algorithm | null
    allowWeakPassword?: boolean
}

export async function generatePKCS12({
                                         certChainPEM,
                                         privKeyDERB64,
                                         pkcs12Password,
                                         pkcs12Algorithm,
                                         allowWeakPassword,
                                     }: IGeneratePKCS12Params): Promise<Base64EncodedDER> {
    let p12Asn1;

    // 3DES encryption for PKCS#12 was intentionally chosen in favor of other (more secure) algorithms
    // as of 2026 there is still a plenty of modern OSes that don't support strong encryption for PKCS#12
    // it's not a big security deal since the file is generated locally
    // though, please make sure to set a strong password
    let usePkcs12Alg: PKCS12Algorithm = "3des";

    if (pkcs12Algorithm) {
        // use stronger PKCS#12 algorithm if explicitly requested by the user
        usePkcs12Alg = pkcs12Algorithm;
    }

    const requiredLength = (usePkcs12Alg === "3des" ? 12 : 8);

    if (!allowWeakPassword) {
        if (!pkcs12Password || pkcs12Password.length < requiredLength) {
            throw TypeError("Parameter pkcs12Password must be at least " + requiredLength + " characters long " +
                "(for " + usePkcs12Alg + ")! Please set a strong password since PKCS#12 file passwords may be easily " +
                "brute-forced offline. Set allowWeakPassword=true to skip this check (unrecommended).");
        }
    }

    const certDERB64Arr = pemChainToDERB64Array(certChainPEM);

    p12Asn1 = toPkcs12Asn1Generic(privKeyDERB64, certDERB64Arr, pkcs12Password, {
        algorithm: usePkcs12Alg,
    });

    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    return forge.util.encode64(p12Der);
}
