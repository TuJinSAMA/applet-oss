const Base64 = require('./Base64.js');
require('./hmac.js');
require('./sha1.js');
const Crypto = require('./crypto.js');
// 计算签名。
function computeSignature(accessKeySecret, canonicalString) {
  const bytes = Crypto.HMAC(Crypto.SHA1, canonicalString, accessKeySecret, {
    asBytes: true,
  });
  return Crypto.util.bytesToBase64(bytes);
}

const date = new Date();
date.setHours(date.getHours() + 1);
const policyText = {
  expiration: date.toISOString(), // 设置policy过期时间。
  conditions: [
    // 限制上传大小。
    ['content-length-range', 0, 50 * 1024 * 1024], //限制大小 50M
  ],
};

export function getFormDataParams(credentials) {
  const policy = Base64.encode(JSON.stringify(policyText)); // policy必须为base64的string。
  const signature = computeSignature(credentials.AccessKeySecret, policy);
  const formData = {
    OSSAccessKeyId: credentials.AccessKeyId,
    signature,
    policy,
    'x-oss-security-token': credentials.SecurityToken,
  };
  return formData;
}
