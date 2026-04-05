const crypto = require('crypto');

// 1. Hàm tạo cặp khóa RSA 2048-bit
function generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

// 2. Hàm tạo chữ ký số (Băm bằng SHA256)
function signDocument(documentBuffer, privateKeyPem) {
    const sign = crypto.createSign('SHA256');
    sign.update(documentBuffer);
    sign.end();
    return sign.sign(privateKeyPem, 'base64');
}

// 3. Hàm xác minh chữ ký
function verifySignature(documentBuffer, signatureBase64, publicKeyPem) {
    const verify = crypto.createVerify('SHA256');
    verify.update(documentBuffer);
    verify.end();
    return verify.verify(publicKeyPem, signatureBase64, 'base64');
}

// Xuất 3 hàm này ra ngoài để Server sử dụng
module.exports = {
    generateKeys,
    signDocument,
    verifySignature
};