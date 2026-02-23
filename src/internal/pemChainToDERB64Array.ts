export function pemChainToDERB64Array(pemChain: string): string[] {
    const beginMarker = '-----BEGIN CERTIFICATE-----';
    const endMarker = '-----END CERTIFICATE-----';
    const certs: string[] = [];

    let remaining = pemChain;

    while (true) {
        const beginIdx = remaining.indexOf(beginMarker);
        const endIdx = remaining.indexOf(endMarker);
        if (beginIdx === -1 || endIdx === -1) break;

        const body = remaining
            .slice(beginIdx + beginMarker.length, endIdx)
            .replace(/\s+/g, '');

        certs.push(body);
        remaining = remaining.slice(endIdx + endMarker.length);
    }

    return certs;
}
