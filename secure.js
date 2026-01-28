import CryptoJS from 'crypto-js';
// 确保 parseuri 也是 ESM 格式，或者通过构建工具处理
import parseuri from './parseuri';

// --- MD5 部分 ---
const md5 = data => CryptoJS.MD5(data).toString();

export class Secure {
  constructor(appid, cid, openid, secret, version, device = "ios_1.0.0", platform = "app") {
    this.appid = appid;
    this.cid = cid;
    this.openid = openid;
    this.secret = secret;
    this.version = version;
    this.device = device;
    this.platform = platform;
  }

  // 解密数据 (AES-256-CBC)
  decrypt(json) {
    if (json.crypto && json.crypto.length > 0) {
      const BLOCK_SIZE_BYTES = 16;
      const key = CryptoJS.enc.Hex.parse(json.crypto);
      const fullCipher = CryptoJS.enc.Hex.parse(json.data);

      const iv = CryptoJS.lib.WordArray.create(fullCipher.words.slice(0, 4), BLOCK_SIZE_BYTES);
      const cipherText = CryptoJS.lib.WordArray.create(fullCipher.words.slice(4));

      const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: cipherText },
        key,
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }
      );

      const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);
      if (!decryptedStr) throw new Error("解密失败");

      json.data = JSON.parse(decryptedStr);
    }
    return json;
  }

  checkBase64(data) {
    try {
      // MV3 中直接使用全局 atob，不要加 window.
      return JSON.parse(atob(data));
    } catch (e) {
      return data;
    }
  }

  // 获取签名后的地址
  getSign(url) {
    let debug = "false";
    try {
      // Service Worker 不支持 localStorage，这里增加回退逻辑
      // 如果是在 Content Script 运行则正常，Background 运行需注意
      if (typeof localStorage !== 'undefined') {
        debug = localStorage['env'] === "local" ? "true" : "false";
      }
    } catch (e) {
      console.warn("LocalStorage unavailable");
    }

    let data = {
      appid: this.appid,
      cid: this.cid,
      openid: this.openid,
      version: this.version,
      device: this.device,
      platform: this.platform,
      nonce_str: this._generateNonceString(8),
      nonce_time: this._generateNonceDateline()
    };

    if (debug === "true") data.debug = "true";

    return this._generateSign(url, data);
  }

  _generateSign(url, data) {
    const parseurl = parseuri(url);
    let keys = [];

    for (let value in parseurl.queryKey) {
      keys.push(value);
    }

    let inputKeys = Object.keys(data);
    for (let i = 0; i < inputKeys.length; i++) {
      keys.push(inputKeys[i]);
    }

    keys = keys.sort();
    let params = [];
    for (const element of keys) {
      if (parseurl.queryKey[element]) {
        params.push(element + "=" + parseurl.queryKey[element]);
      } else {
        params.push(element + "=" + data[element]);
      }
    }

    let stringA = params.join("&");
    let stringSignTemp = stringA + "&key=" + this.secret;

    // CryptoJS 默认输出小写，后端通常要求大写
    let sign = md5(stringSignTemp).toUpperCase();
    params.push("sign=" + sign);

    // 适配协议头
    const protocol = parseurl.protocol ? parseurl.protocol + "://" : "";
    const authority = parseurl.authority || "";
    return protocol + authority + parseurl.path + "?" + params.join("&");
  }

  _generateNonceDateline() {
    return Math.floor(Date.now() / 1000);
  }

  _generateNonceString(length) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let noceStr = "";
    for (let i = 0; i < (length || 32); i++) {
      noceStr += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return noceStr;
  }
}
