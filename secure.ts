import CryptoJS from 'crypto-js'
import { gcm } from '@noble/ciphers/aes'
import parseuri from './parseuri'

// ─────────────────────────────────────────────
// 内部工具函数
// ─────────────────────────────────────────────

const md5 = (data: string): string => CryptoJS.MD5(data).toString()

/** Base64 → Uint8Array（浏览器 / Node / Service Worker / 小程序） */
function base64ToBytes(base64: string): Uint8Array {
  if (typeof atob === 'function') {
    try {
      const bin = atob(base64)
      const bytes = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
      return bytes
    } catch (_) {}
  }
  // Node.js fallback
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'))
  }
  // CryptoJS fallback（最后兜底）
  const parsed = CryptoJS.enc.Base64.parse(base64)
  const bytes = new Uint8Array(parsed.sigBytes)
  for (let i = 0; i < parsed.sigBytes; i++) {
    bytes[i] = (parsed.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
  }
  return bytes
}

/** UTF-8 Uint8Array → string（无 TextDecoder 时纯 JS 实现，覆盖小程序真机） */
function bytesToString(bytes: Uint8Array): string {
  if (typeof TextDecoder !== 'undefined') {
    try { return new TextDecoder().decode(bytes) } catch (_) {}
  }
  let out = '', i = 0
  const len = bytes.length
  while (i < len) {
    const c = bytes[i++]
    if (c >> 4 <= 7) {
      out += String.fromCharCode(c)
    } else if (c >> 4 === 12 || c >> 4 === 13) {
      out += String.fromCharCode(((c & 0x1f) << 6) | (bytes[i++] & 0x3f))
    } else if (c >> 4 === 14) {
      const c2 = bytes[i++], c3 = bytes[i++]
      out += String.fromCharCode(((c & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f))
    } else if (c >> 4 === 15) {
      const c2 = bytes[i++], c3 = bytes[i++], c4 = bytes[i++]
      const cp = (((c & 0x07) << 18) | ((c2 & 0x3f) << 12) | ((c3 & 0x3f) << 6) | (c4 & 0x3f)) - 0x10000
      out += String.fromCharCode((cp >> 10) + 0xd800, (cp & 0x3ff) + 0xdc00)
    }
  }
  return out
}

/** string → UTF-8 Uint8Array */
function stringToBytes(str: string): Uint8Array {
  if (typeof TextEncoder !== 'undefined') {
    try { return new TextEncoder().encode(str) } catch (_) {}
  }
  const utf8: number[] = []
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i)
    if (c < 0x80) { utf8.push(c) }
    else if (c < 0x800) { utf8.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)) }
    else if (c < 0xd800 || c >= 0xe000) {
      utf8.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    } else {
      i++
      c = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff))
      utf8.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    }
  }
  return new Uint8Array(utf8)
}

/**
 * AES-GCM 解密，按环境自动选择实现：
 *
 * 1. Web Crypto API  — 浏览器 / MV3 Service Worker / Node 18+
 * 2. Node.js crypto  — Node < 18
 * 3. @noble/ciphers  — 微信小程序 / 无 Web Crypto 的纯 JS 环境（静态打包，零平台依赖）
 */
async function decryptAesGcm(keyBytes: Uint8Array, rawBytes: Uint8Array): Promise<string> {
  const nonce           = rawBytes.subarray(0, 12)
  const ciphertextWithTag = rawBytes.subarray(12)

  // 1. Web Crypto API
  if (typeof crypto !== 'undefined' && (crypto as any).subtle) {
    try {
      const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes.buffer as ArrayBuffer, { name: 'AES-GCM' }, false, ['decrypt']
      )
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce as any }, cryptoKey, ciphertextWithTag.buffer as ArrayBuffer
      )
      return bytesToString(new Uint8Array(plain))
    } catch (e) {
      // 不抛出，继续 fallback（某些沙箱环境 subtle 存在但受限）
      console.warn('[mali-secure] Web Crypto failed, trying fallback:', e)
    }
  }

  // 2. Node.js crypto (Node < 18 无 globalThis.crypto)
  if (typeof process !== 'undefined' && process.versions?.node) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require('crypto') as typeof import('crypto')
      const tagLen  = 16
      const ct  = ciphertextWithTag.subarray(0, ciphertextWithTag.length - tagLen)
      const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - tagLen)
      const decipher = nodeCrypto.createDecipheriv('aes-128-gcm', keyBytes, nonce)
      decipher.setAuthTag(Buffer.from(tag))
      return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')
    } catch (e) {
      console.warn('[mali-secure] Node crypto failed, trying @noble/ciphers:', e)
    }
  }

  // 3. @noble/ciphers — 纯 JS，微信小程序 / 任何缺少前两者的环境
  const aesGcm = gcm(keyBytes, nonce)
  const decryptedBytes = aesGcm.decrypt(ciphertextWithTag)
  return bytesToString(decryptedBytes)
}

// ─────────────────────────────────────────────
// 公开类型
// ─────────────────────────────────────────────

/** 服务端响应通用结构 */
export interface ApiResponse<T = unknown> {
  code:    number
  msg:     string
  /** 加密时为字符串，解密后为业务数据 */
  data:    string | T
  /** 旧 AES-CBC 格式才有此字段 */
  crypto?: string
  [key: string]: unknown
}

// ─────────────────────────────────────────────
// 主类
// ─────────────────────────────────────────────

export class Secure {
  appid:     string
  cid:       string | number
  openid:    string
  secret:    string
  version:   string
  device:    string
  platform:  string
  /** 响应解密密钥，与服务端 `crypto_key` 配置一致 */
  cryptoKey: string

  /**
   * @param appid      应用 ID
   * @param cid        渠道 / 商户 ID
   * @param openid     用户 openid
   * @param secret     签名密钥（服务端 key）
   * @param version    客户端版本号
   * @param device     设备标识，默认 `ios_1.0.0`
   * @param platform   平台标识，默认 `app`
   * @param cryptoKey  **新加密**响应解密密钥；不传则只支持旧 CBC 格式
   */
  constructor(
    appid:     string,
    cid:       string | number,
    openid:    string,
    secret:    string,
    version:   string,
    device:    string = 'ios_1.0.0',
    platform:  string = 'app',
    cryptoKey: string = ''
  ) {
    this.appid     = appid
    this.cid       = cid
    this.openid    = openid
    this.secret    = secret
    this.version   = version
    this.device    = device
    this.platform  = platform
    this.cryptoKey = cryptoKey
  }

  /**
   * 解密服务端响应，自动识别加密模式：
   *
   * - **模式 3 (AES-GCM)**（新）`data = randomKey(16) + Base64(nonce12 + ciphertext + tag16)`
   *   需在构造时传入 `cryptoKey`。
   * - **旧格式 (AES-CBC)**（兼容）`json.crypto`(hex key) + `json.data`(hex iv+cipher)
   *
   * @returns `Promise<ApiResponse<T>>`，请始终 `await`。
   */
  async decrypt<T = unknown>(json: ApiResponse<T>): Promise<ApiResponse<T>> {
    if (!json || typeof json !== 'object') return json

    // ── 模式 3: AES-GCM ────────────────────────────────────
    // 特征：data 是字符串 & 长度 > 16 & 有 cryptoKey & 无旧格式 crypto 字段
    if (
      typeof json.data === 'string' &&
      (json.data as string).length > 16 &&
      this.cryptoKey &&
      !json.crypto
    ) {
      try {
        const raw          = json.data as string
        const randomKey    = raw.substring(0, 16)
        const base64Cipher = raw.substring(16)
        const keyBytes     = stringToBytes(this.cryptoKey + randomKey)
        const rawBytes     = base64ToBytes(base64Cipher)

        if (rawBytes.length >= 28) { // 12B nonce + ≥1B cipher + 16B tag
          const str = await decryptAesGcm(keyBytes, rawBytes)
          json.data = JSON.parse(str) as T
          return json
        }
      } catch (err) {
        console.warn('[mali-secure] AES-GCM 解密失败，保留原始数据:', err)
      }
    }

    // ── 旧格式: AES-CBC ────────────────────────────────────
    if (json.crypto && json.crypto.length > 0 && typeof json.data === 'string') {
      try {
        const key        = CryptoJS.enc.Hex.parse(json.crypto)
        const fullCipher = CryptoJS.enc.Hex.parse(json.data as string)
        const iv         = CryptoJS.lib.WordArray.create(fullCipher.words.slice(0, 4), 16)
        const cipherText = CryptoJS.lib.WordArray.create(fullCipher.words.slice(4))

        const decrypted = CryptoJS.AES.decrypt(
          { ciphertext: cipherText } as any,
          key,
          { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
        )
        const str = decrypted.toString(CryptoJS.enc.Utf8)
        if (str) json.data = JSON.parse(str) as T
      } catch (err) {
        console.warn('[mali-secure] AES-CBC 解密失败:', err)
      }
    }

    return json
  }

  /** 尝试将字符串从 Base64 解析为 JSON，失败则原样返回 */
  checkBase64(data: string): unknown {
    try { return JSON.parse(atob(data)) } catch (_) { return data }
  }

  /**
   * 生成带签名的完整请求 URL。
   * 自动附加 `crypto=3` 参数，告知服务端使用 AES-GCM 加密响应。
   *
   * @param url         原始 URL（可含已有 query 参数）
   * @param extraParams 附加参数（会覆盖同名默认参数）
   */
  getSign(url: string, extraParams: Record<string, unknown> = {}): string {
    let debug = 'false'
    try {
      if (typeof localStorage !== 'undefined') {
        debug = localStorage['env'] === 'local' ? 'true' : 'false'
      }
    } catch (_) { /* Service Worker / 小程序无 localStorage */ }

    const data: Record<string, unknown> = {
      appid:      this.appid,
      cid:        this.cid,
      openid:     this.openid,
      version:    this.version,
      device:     this.device,
      platform:   this.platform,
      crypto:     '3',   // 告知服务端返回 AES-GCM 加密
      nonce_str:  this._generateNonceString(8),
      nonce_time: this._generateNonceDateline(),
      ...extraParams,
    }
    if (debug === 'true') data['debug'] = 'true'
    return this._generateSign(url, data)
  }

  _generateSign(url: string, data: Record<string, unknown>): string {
    const parseurl = parseuri(url)
    const keySet   = new Set<string>()

    if (parseurl.queryKey) {
      for (const k in parseurl.queryKey) if (k !== 'sign') keySet.add(k)
    }
    for (const k in data) if (k !== 'sign') keySet.add(k)

    const params: string[] = []
    for (const key of Array.from(keySet).sort()) {
      if (parseurl.queryKey?.[key] !== undefined) {
        params.push(`${key}=${parseurl.queryKey[key]}`)
      } else if (data[key] !== undefined) {
        params.push(`${key}=${data[key]}`)
      }
    }

    const sign = md5(params.join('&') + '&key=' + this.secret).toUpperCase()
    params.push('sign=' + sign)

    const protocol  = parseurl.protocol ? parseurl.protocol + '://' : ''
    const authority = parseurl.authority || ''
    const path      = parseurl.path || ''
    return `${protocol}${authority}${path}?${params.join('&')}`
  }

  _generateNonceDateline(): number {
    return Math.floor(Date.now() / 1000)
  }

  _generateNonceString(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    let str = ''
    for (let i = 0; i < length; i++) str += chars.charAt(Math.floor(Math.random() * chars.length))
    return str
  }
}
