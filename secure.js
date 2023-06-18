var md5;
try {
  md5 = require('md5');
} catch (err) {
  console.log('md5 support is disabled!');
}

var parseuri;
try {
  parseuri = require('./parseuri');
} catch (err) {
  console.log('parseuri support is disabled!');
}

var crypto;
try {
  crypto = require('crypto');
} catch (err) {
  console.log('crypto support is disabled!');
}

class Secure {
  constructor(appid, cid, openid, secret, version, device = "ios_1.0.0", platform = "app") {
    this.appid = appid;
    this.cid = cid;
    this.openid = openid;
    this.secret = secret

    this.version = version
    this.device = device
    this.platform = platform
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
    let debug = "false"
    try {
      debug = localStorage && localStorage['env'] == "local" ? "true" : "false"
    } catch (e) {
    }

    let data = {
      debug: debug,
      appid: this.appid,
      cid: this.cid,
      openid: this.openid,
      version: this.version,
      device: this.device,
      platform: this.platform,
      nonce_str: this._generateNonceString(8),
      nonce_time: this._generateNonceDateline()
    }
    if (debug == "false") {
      delete (data.debug)
    }
    return this._generateSign(url, data)
  }

  // data = { "nonce_str": "nonce_str=xxx", "nonce_time": "nonce_time="xxx"}
  _generateSign(url, data) {

    var parseurl = parseuri(url)
    let keys = []

    // keys for url
    for (var value in parseurl.queryKey) {
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
      if (parseurl.queryKey[element]) {
        params.push(element + "=" + parseurl.queryKey[element])
      } else {
        params.push(element + "=" + data[element])
      }
    }

    let stringA = params.join("&")
    let stringSignTemp = stringA + "&key=" + this.secret
    let sign = md5(stringSignTemp).toLocaleUpperCase()
    params.push("sign=" + sign)

    if (parseurl.protocol.length > 2) {
      return parseurl.protocol + "://" + parseurl.authority + parseurl.path + "?" + params.join("&")
    } else {
      return parseurl.host + parseurl.path + "?" + params.join("&")
    }
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