import CryptoJS from 'crypto-js';
import parseuri from './parseuri';

// --- MD5 部分 ---
const md5 = data => CryptoJS.MD5(data).toString();

// --- Base64 → Uint8Array（兼容浏览器 / Node / Service Worker）---
function base64ToBytes(base64) {
  if (typeof atob === 'function') {
    try {
      const bin = atob(base64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    } catch (_) {}
  }
  // Node.js fallback
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

// --- UTF-8 bytes → string（兼容 Service Worker 无 TextDecoder 环境）---
function bytesToString(bytes) {
  if (typeof TextDecoder !== 'undefined') {
    try { return new TextDecoder().decode(bytes); } catch (_) {}
  }
  // 纯 JS fallback
  let out = '', i = 0;
  const len = bytes.length;
  while (i < len) {
    const c = bytes[i++];
    if (c >> 4 <= 7) {
      out += String.fromCharCode(c);
    } else if (c >> 4 === 12 || c >> 4 === 13) {
      out += String.fromCharCode(((c & 0x1f) << 6) | (bytes[i++] & 0x3f));
    } else if (c >> 4 === 14) {
      const c2 = bytes[i++], c3 = bytes[i++];
      out += String.fromCharCode(((c & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f));
    } else if (c >> 4 === 15) {
      const c2 = bytes[i++], c3 = bytes[i++], c4 = bytes[i++];
      let cp = (((c & 0x07) << 18) | ((c2 & 0x3f) << 12) | ((c3 & 0x3f) << 6) | (c4 & 0x3f)) - 0x10000;
      out += String.fromCharCode((cp >> 10) + 0xd800, (cp & 0x3ff) + 0xdc00);
    }
  }
  return out;
}

// --- string → UTF-8 Uint8Array ---
function stringToBytes(str) {
  if (typeof TextEncoder !== 'undefined') {
    try { return new TextEncoder().encode(str); } catch (_) {}
  }
  const utf8 = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) { utf8.push(c); }
    else if (c < 0x800) { utf8.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else if (c < 0xd800 || c >= 0xe000) {
      utf8.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      i++;
      c = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return new Uint8Array(utf8);
}

// --- AES-GCM 解密（模式 3）---
// 优先 Web Crypto API（浏览器 / Service Worker / Node 18+），fallback 使用 @noble/ciphers
async function decryptAesGcm(keyBytes, rawBytes) {
  const nonce = rawBytes.subarray(0, 12);
  const ciphertextWithTag = rawBytes.subarray(12);

  // 1. Web Crypto API (浏览器 / MV3 Service Worker / Node 18+)
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
      );
      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce }, cryptoKey, ciphertextWithTag
      );
      return bytesToString(new Uint8Array(plainBuf));
    } catch (e) {
      throw e;
    }
  }

  // 2. Node.js crypto fallback (Node < 18)
  if (typeof require !== 'undefined') {
    try {
      const nodeCrypto = require('crypto');
      const tagLen = 16;
      const ct = ciphertextWithTag.subarray(0, ciphertextWithTag.length - tagLen);
      const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - tagLen);
      const decipher = nodeCrypto.createDecipheriv('aes-128-gcm', keyBytes, nonce);
      decipher.setAuthTag(tag);
      const dec = Buffer.concat([decipher.update(ct), decipher.final()]);
      return dec.toString('utf8');
    } catch (e) {
      throw e;
    }
  }

  throw new Error('No AES-GCM implementation available');
}

export class Secure {
  /**
   * @param {string} appid
   * @param {string|number} cid
   * @param {string} openid
   * @param {string} secret     签名密钥
   * @param {string} version
   * @param {string} device
   * @param {string} platform
   * @param {string} cryptoKey  响应解密密钥（与服务端 crypto_key 一致）
   */
  constructor(
    appid,
    cid,
    openid,
    secret,
    version,
    device = 'ios_1.0.0',
    platform = 'app',
    cryptoKey = ''
  ) {
    this.appid = appid;
    this.cid = cid;
    this.openid = openid;
    this.secret = secret;
    this.version = version;
    this.device = device;
    this.platform = platform;
    this.cryptoKey = cryptoKey;
  }

  /**
   * 解密响应数据，自动识别加密模式：
   *   模式 3 (AES-GCM): json.data = randomKey(16) + Base64(nonce12 + ciphertext + tag16)
   *   模式旧 (AES-CBC): json.crypto(hex key) + json.data(hex iv+cipher)
   *
   * ⚠ 模式 3 为异步（使用 Web Crypto API），返回 Promise<json>。
   *    建议始终 await decrypt(json)，兼容同步旧格式（Promise 也可 await）。
   */
  async decrypt(json) {
    if (!json || typeof json !== 'object') return json;

    // --- 模式 3: AES-GCM（新格式，服务端 cryptoType=3）---
    // 特征：json.data 是字符串，长度 > 16，且构造时传入了 cryptoKey
    if (
      typeof json.data === 'string' &&
      json.data.length > 16 &&
      this.cryptoKey &&
      !json.crypto  // 旧格式有 json.crypto 字段，新格式没有
    ) {
      try {
        const randomKey = json.data.substring(0, 16);
        const base64Cipher = json.data.substring(16);
        const fullKeyStr = this.cryptoKey + randomKey;
        const keyBytes = stringToBytes(fullKeyStr);

        const rawBytes = base64ToBytes(base64Cipher);
        // 至少需要 12B nonce + 16B tag = 28 字节
        if (rawBytes.length >= 28) {
          const decryptedStr = await decryptAesGcm(keyBytes, rawBytes);
          json.data = JSON.parse(decryptedStr);
          return json;
        }
      } catch (err) {
        console.warn('[mali-secure] AES-GCM 解密失败，保留原始数据:', err);
      }
    }

    // --- 旧格式兼容：AES-CBC（json.crypto hex key + json.data hex iv+cipher）---
    if (json.crypto && json.crypto.length > 0 && typeof json.data === 'string') {
      try {
        const BLOCK_SIZE_BYTES = 16;
        const key = CryptoJS.enc.Hex.parse(json.crypto);
        const fullCipher = CryptoJS.enc.Hex.parse(json.data);

        const iv = CryptoJS.lib.WordArray.create(fullCipher.words.slice(0, 4), BLOCK_SIZE_BYTES);
        const cipherText = CryptoJS.lib.WordArray.create(fullCipher.words.slice(4));

        const decrypted = CryptoJS.AES.decrypt(
          { ciphertext: cipherText },
          key,
          { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
        );

        const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);
        if (decryptedStr) json.data = JSON.parse(decryptedStr);
      } catch (err) {
        console.warn('[mali-secure] AES-CBC 解密失败:', err);
      }
    }

    return json;
  }

  checkBase64(data) {
    try {
      return JSON.parse(atob(data));
    } catch (e) {
      return data;
    }
  }

  /**
   * 获取签名后的请求地址
   * @param {string} url
   * @param {Record<string,any>} extraParams 额外参数
   */
  getSign(url, extraParams = {}) {
    let debug = 'false';
    try {
      if (typeof localStorage !== 'undefined') {
        debug = localStorage['env'] === 'local' ? 'true' : 'false';
      }
    } catch (e) {
      // Service Worker 无 localStorage，忽略
    }

    const data = {
      appid:      this.appid,
      cid:        this.cid,
      openid:     this.openid,
      version:    this.version,
      device:     this.device,
      platform:   this.platform,
      crypto:     '3',  // 告知服务端返回 AES-GCM 加密（模式 3）
      nonce_str:  this._generateNonceString(8),
      nonce_time: this._generateNonceDateline(),
      ...extraParams,
    };

    if (debug === 'true') data.debug = 'true';

    return this._generateSign(url, data);
  }

  _generateSign(url, data) {
    const parseurl = parseuri(url);
    const keySet = new Set();

    if (parseurl.queryKey) {
      for (const k in parseurl.queryKey) {
        if (k !== 'sign') keySet.add(k);
      }
    }
    for (const k in data) {
      if (k !== 'sign') keySet.add(k);
    }

    const sortedKeys = Array.from(keySet).sort();
    const params = [];

    for (const key of sortedKeys) {
      if (parseurl.queryKey && parseurl.queryKey[key] !== undefined) {
        params.push(key + '=' + parseurl.queryKey[key]);
      } else if (data[key] !== undefined) {
        params.push(key + '=' + data[key]);
      }
    }

    const stringA = params.join('&');
    const stringSignTemp = stringA + '&key=' + this.secret;
    const sign = md5(stringSignTemp).toUpperCase();
    params.push('sign=' + sign);

    const protocol  = parseurl.protocol ? parseurl.protocol + '://' : '';
    const authority = parseurl.authority || '';
    const path      = parseurl.path || '';
    return protocol + authority + path + '?' + params.join('&');
  }

  _generateNonceDateline() {
    return Math.floor(Date.now() / 1000);
  }

  _generateNonceString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let str = '';
    for (let i = 0; i < (length || 32); i++) {
      str += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return str;
  }
}
