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
    let debug = localStorage['env'] == "local" ? "true" : "false"
    let data = {
      debug: debug,
      nonce_str: this._generateNonceString(8),
      nonce_time: this._generateNonceDateline()
    }
    return this._generateSign(url, data)
  }

  getSignWithCidOpenId(url) {
    let debug = localStorage['env'] == "local" ? "true" : "false"
    let data = {
      debug: debug,
      cid: this.cid,
      openid: this.openid,
      nonce_str: this._generateNonceString(8),
      nonce_time: this._generateNonceDateline()
    }
    return this._generateSign(url, data)
  }

  // data = { "nonce_str": "nonce_str=xxx", "nonce_time": "nonce_time="xxx"}
  _generateSign(url, data) {
    let uri = new URL(url)
    const search = uri.search
    var searchParams = new URLSearchParams(search)

    let keys = []

    // keys for url
    for (var value of searchParams.keys()) { // @@iterator is used
      keys.push(value)
    }

    // keys for input
    let inputKeys = Object.keys(data)
    for (let i = 0; i < inputKeys.length; i++) {
      keys.push(inputKeys[i]);
    }

    // sort keys
    keys = keys.sort()

    // get url params
    let params = []
    for (const element of keys) {
      if (searchParams.get(element)) {
        params.push(element + "=" + searchParams.get(element))
      } else {
        params.push(element + "=" + data[element])
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