let lastAlg = null;
let lastKeys = null;

async function demoGenerateCSR(alg) {
    document.getElementById("btnSelfSignCert").disabled = true;
    document.getElementById("btnPKCS12").disabled = true;
    document.getElementById("certChainPEM").value = '';
    document.getElementById("pkcs12B64").value = '';

    // keys are explicitly generated using native browser's API to ensure cryptographic soundness
    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    const privKeyDERB64 = await TinyPKIClientSideCertReqLib.exportKeyDERB64(keys.privateKey);
    const csrPEM = await TinyPKIClientSideCertReqLib.generateCSR({
        commonName: "example.com",
        subjectAltNames: ["email:test@example.com", "dns:example.com"],
        keys: keys,
        algorithm: alg,
    });

    lastKeys = keys;
    lastAlg = alg;

    document.getElementById("csrPrivateKey").value = privKeyDERB64;
    document.getElementById("csrCSRPEM").value = csrPEM;
    document.getElementById("btnSelfSignCert").disabled = false;
}

async function btnGenerateCSR() {
    document.getElementById("btnCSR").disabled = true;

    try {
        const algStr = document.getElementById("csrAlgorithm").value;
        const [algFamily, algParam, algHash] = algStr.split("/");

        if (algFamily === "Ed25519") {
            await demoGenerateCSR({
                name: "Ed25519",
            });
        } else if (algFamily === "ECDSA") {
            await demoGenerateCSR({
                name: "ECDSA",
                namedCurve: algParam,
                hash: algHash,
            });
        } else if (algFamily === "RSASSA-PKCS1-v1_5" || algFamily === "RSA-PSS") {
            await demoGenerateCSR({
                name: algFamily,
                modulusLength: parseInt(algParam),
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
                hash: algHash,
                saltLength: 32,
            });
        } else {
            throw Error("Unsupported algFamily: " + algFamily);
        }
    } finally {
        document.getElementById("btnCSR").disabled = false;
    }
}

async function btnSelfSignCertificate() {
    const certChainPEM = await TinyPKIClientSideCertReqLib.generateSelfSignedCert({
        algorithm: lastAlg,
        keys: lastKeys,
    });

    document.getElementById("certChainPEM").value = certChainPEM;
    document.getElementById("btnPKCS12").disabled = false;
}

async function btnGeneratePKCS12() {
    const privKeyDERB64 = document.getElementById("csrPrivateKey").value;
    const certChainPEM = document.getElementById("certChainPEM").value;
    const pkcs12Password = document.getElementById("pkcs12Password").value;
    const pkcs12Algorithm = document.getElementById("pkcs12Algorithm").value;

    if (certChainPEM.trim().length === 0) {
        throw Error("Signed certificate chain is missing. Either paste the signed certificate into the field " +
            "or use 'Generate self-signed certificate button' to make a demo self-signed certificate.");
    }

    const pkcs12B64 = await TinyPKIClientSideCertReqLib.generatePKCS12({
        algorithm: lastAlg,
        certChainPEM: certChainPEM,
        privKeyDERB64: privKeyDERB64,
        pkcs12Password: pkcs12Password,
        pkcs12Algorithm: pkcs12Algorithm,
    });

    document.getElementById("pkcs12B64").value = pkcs12B64;

    TinyPKIClientSideCertReqLib.savePKCS12BufferAsFile({
        buffer: TinyPKIClientSideCertReqLib.base64ToBuffer(pkcs12B64),
        targetName: "bundle.p12"
    });
}

async function wrapHandleErrors(callback) {
    try {
        await callback();
    } catch (e) {
        console.error(e);
        document.getElementById("errorText").innerText = e.stack.toString();
        const myModal = new bootstrap.Modal('#errorModal')
        myModal.show();
    }
}

document.addEventListener("DOMContentLoaded", () => {
    wrapHandleErrors(async () => {
        if (typeof TinyPKIClientSideCertReqLib === "undefined") {
            throw Error("TinyPKIClientSideCertReqLib is not available. Make sure that you've built the library first, " +
                "and that it was correctly included on the web page.");
        }
    });

    const btnPKCS12 = document.getElementById("btnPKCS12");

    document.getElementById("certChainPEM").addEventListener("input", function(event) {
        if (event.target.value.length > 0 && event.target.value.trim().length > 0) {
            btnPKCS12.disabled = false;
        } else {
            btnPKCS12.disabled = true;
        }
    }, false);
});
