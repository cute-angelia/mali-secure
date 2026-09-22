# mali-secure

请求签名 + 响应解密库，适用于 mali 系列 API。

支持：
- **AES-GCM（模式 3）**：新版加密，服务端 `cryptoType=3` 时使用
- **AES-CBC（旧格式）**：向后兼容，自动识别
- **全平台覆盖**：浏览器 · Node.js · MV3 Service Worker · 微信小程序

---

## 安装

```bash
npm install mali-secure
```

---

## 快速上手

```ts
import { Secure } from 'mali-secure'

const s = new Secure(
  'wx89e9e3a0ca35f58e',  // appid
  '1',                   // cid（渠道/商户 ID）
  'user-openid',         // openid
  'your-sign-secret',    // 签名密钥（服务端 key）
  '1.0.0',               // 版本号
  'mp-weixin',           // device
  'wx_app',              // platform
  'your-crypto-key'      // 响应解密密钥（服务端 crypto_key，新加密必填）
)

// 1. 生成带签名的请求地址（自动附加 crypto=3 参数）
const signedUrl = s.getSign('https://api.example.com/categories/tree?cid=1')
// → https://api.example.com/categories/tree?appid=...&cid=...&crypto=3&sign=XXX

// 2. 请求后解密响应（始终 await）
const res = await fetch(signedUrl).then(r => r.json())
const decrypted = await s.decrypt(res)
console.log(decrypted.data) // 解密后的业务数据
```

---

## 各环境兼容性

| 环境 | AES-GCM 实现 |
|---|---|
| 浏览器 / MV3 Service Worker | `crypto.subtle`（Web Crypto API） |
| Node.js 18+ | `crypto.subtle`（内置 Web Crypto） |
| Node.js < 18 | `node:crypto`（createDecipheriv） |
| 微信小程序 / uniapp | `@noble/ciphers`（纯 JS，无平台依赖） |

---

## API

### `new Secure(appid, cid, openid, secret, version, device?, platform?, cryptoKey?)`

| 参数 | 类型 | 说明 |
|---|---|---|
| `appid` | `string` | 应用 ID |
| `cid` | `string \| number` | 渠道 / 商户 ID |
| `openid` | `string` | 用户 openid |
| `secret` | `string` | 签名密钥（服务端 `key`） |
| `version` | `string` | 客户端版本号 |
| `device` | `string` | 设备标识，默认 `ios_1.0.0` |
| `platform` | `string` | 平台标识，默认 `app` |
| `cryptoKey` | `string` | **新加密**响应解密密钥，与服务端 `crypto_key` 一致；不传则仅支持旧 CBC 格式 |

---

### `s.getSign(url, extraParams?)`

生成带签名的完整请求 URL，自动追加以下参数：

- 所有构造参数（appid / cid / openid / version / device / platform）
- `crypto=3`：告知服务端使用 AES-GCM 加密响应
- `nonce_str` / `nonce_time`：防重放随机串和时间戳
- `sign`：MD5 签名（大写）

```ts
const url = s.getSign('https://api.example.com/user/info', { type: 1 })
```

---

### `await s.decrypt<T>(json)`

自动识别并解密服务端响应：

```ts
// 新格式（AES-GCM，服务端 cryptoType=3）
// json.data = randomKey(16位) + Base64(nonce + ciphertext + tag)

// 旧格式（AES-CBC，向后兼容）
// json.crypto = hex密钥，json.data = hex(iv + ciphertext)

const result = await s.decrypt<{ list: Item[] }>(json)
console.log(result.data.list)
```

> ⚠ **decrypt 是异步的**，请始终 `await`。

---

### `s.checkBase64(data)`

尝试将字符串从 Base64 解析为 JSON，失败则原样返回。

---

## 在微信小程序 / uniapp 中使用

```ts
// src/utils/request.ts
import { Secure } from 'mali-secure'

export const secure = new Secure(
  'wx89e9e3a0ca35f58e',
  uni.getStorageSync('cid') || '1',
  uni.getStorageSync('openid') || '',
  'your-sign-secret',
  '1.0.0',
  'mp-weixin',
  'wx_app',
  'your-crypto-key'
)

// 发起请求
export async function request<T>(url: string, params = {}) {
  const signedUrl = secure.getSign(url, params)
  return new Promise<T>((resolve, reject) => {
    uni.request({
      url: signedUrl,
      success: async (res) => {
        const decrypted = await secure.decrypt(res.data as any)
        resolve(decrypted.data as T)
      },
      fail: reject,
    })
  })
}
```

> 小程序需在 `project.config.json` 中开启 `packNpmManually` 或使用 uniapp 的 npm 支持。

---

## 构建（开发者）

```bash
# 安装依赖
npm install

# 构建（输出 dist/secure.js + dist/secure.cjs + dist/secure.d.ts）
npm run build

# 监听模式
npm run dev

# 类型检查
npm run typecheck
```

---

## 解密格式说明

### 新格式（AES-GCM，模式 3）

```
json.data = randomKey(16 chars) + Base64(
  nonce(12 bytes) + ciphertext + tag(16 bytes)
)
```

服务端对应实现：`go-xutils/utils/http/apiV3`，`cryptoType = CryptoTypeAESGCM(3)`

### 旧格式（AES-CBC，向后兼容）

```
json.crypto = hex 编码的 AES 密钥
json.data   = hex 编码的 IV(16B) + ciphertext
```

---

## License

ISC
