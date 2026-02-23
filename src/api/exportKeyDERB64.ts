function ab2str(buf: ArrayBuffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buf) as unknown as number[]);
}

export async function exportKeyDERB64(key: CryptoKey) {
    const exported = await window.crypto.subtle.exportKey("pkcs8", key);
    const exportedAsString = ab2str(exported);
    return window.btoa(exportedAsString);
}
