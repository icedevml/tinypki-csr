/**
 * The saveBufferAsFile() was derived from the pkijs (PeculiarVentures/PKI.js) library:
 * https://github.com/PeculiarVentures/PKI.js/blob/1bb60c22567a8608f296a2d06ddc06bd2da7125e/examples/PKCS12SimpleExample/es6.ts#L9
 *
 * Original license: BSD-3 Clause License
 * Full license statement is available here:
 * https://github.com/PeculiarVentures/PKI.js/blob/1bb60c22567a8608f296a2d06ddc06bd2da7125e/LICENSE
 *
 * Original author/copyright:
 *   Author 2014-2019, Yury Strozhevsky
 *
 *   Copyright (c) 2014, GlobalSign
 *   Copyright (c) 2015-2019, Peculiar Ventures
 *   All rights reserved.
 */

interface ISavePKCS12BufferAsFileParams {
    buffer: ArrayBuffer
    targetName: string
}

interface ISaveBufferAsFileParams {
    buffer: ArrayBuffer
    targetName: string
    mimeType: string
}

function destroyClickedElement(event: any) {
    document.body.removeChild(event.target);
}

function saveBufferAsFile({buffer, targetName, mimeType}: ISaveBufferAsFileParams) {
    const pkcs12AsBlob = new Blob([buffer], {type: mimeType});
    const downloadLink = document.createElement("a");
    downloadLink.download = targetName;
    downloadLink.innerHTML = "Download File";

    downloadLink.href = window.URL.createObjectURL(pkcs12AsBlob);
    downloadLink.onclick = destroyClickedElement;
    downloadLink.style.display = "none";
    document.body.appendChild(downloadLink);

    downloadLink.click();
}

export function savePKCS12BufferAsFile({buffer, targetName}: ISavePKCS12BufferAsFileParams) {
    return saveBufferAsFile({
        buffer,
        targetName,
        mimeType: "application/x-pkcs12"
    })
}
