var md5;
try {
  md5 = require('md5');
} catch (err) {
  console.log('md5 support is disabled!');
}

var crypto;
try {
  crypto = require('crypto');
} catch (err) {
  console.log('crypto support is disabled!');
}

class Secure {
  constructor(cid, openid, secret) {
    this.cid = cid;
    this.openid = openid;
    this.secret = secret
  }

  // 解密数据
  decrypt(json) {
    if (json.crypto && json.crypto.length > 0) {
      const ALGORITHM = 'aes-256-cbc';
      const BLOCK_SIZE = 16;

      let CIPHER_KEY = json.crypto
      let cipherText = json.data

      // Decrypts cipher text into plain text
      const contents = Buffer.from(cipherText, 'hex');
      const iv = contents.slice(0, BLOCK_SIZE);
      const textBytes = contents.slice(BLOCK_SIZE);

      const decipher = crypto.createDecipheriv(ALGORITHM, CIPHER_KEY, iv);
      let decrypted = decipher.update(textBytes, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      json.data = JSON.parse(decrypted)
    }
    return json
  }

  checkBase64(data) {
    try {
      return JSON.parse(window.atob(data))
    } catch (e) {
      return data
    }
  }

  // 获取签名后的地址
  getSign(url) {
    let uri = new URL(url)
    const search = uri.search
    var searchParams = new URLSearchParams(search)

    let keys = []
    for (var value of searchParams.keys()) {  // @@iterator is used
      keys.push(value)
    }
    keys.push("nonce_str");
    keys.push("nonce_time");
    keys = keys.sort()

    let params = []
    for (const element of keys) {
      if (element == "nonce_str") {
        params.push(element + "=" + this._generateNonceString(8))
      } else if (element == "nonce_time") {
        params.push(element + "=" + this._generateNonceDateline())
      } else {
        params.push(element + "=" + searchParams.get(element))
      }
    }

    let stringA = params.join("&")
    let stringSignTemp = stringA + "&key=" + this.secret
    let sign = md5(stringSignTemp).toLocaleUpperCase()
    params.push("sign=" + sign)

    uri = uri.origin + uri.pathname + "?" + params.join("&")
    return uri
  }

  _generateNonceDateline() {
    return Date.parse(new Date()) / 1000
  }

  // 获取一次性字符串
  _generateNonceString(length) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var maxPos = chars.length;
    var noceStr = "";
    for (var i = 0; i < (length || 32); i++) {
      noceStr += chars.charAt(Math.floor(Math.random() * maxPos));
    }
    return noceStr;
  }
}

module.exports.Secure = Secure;