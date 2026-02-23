import {Buffer} from "buffer";

export function base64ToBuffer(dataB64: string) {
    return Buffer.from(dataB64, "base64");
}
