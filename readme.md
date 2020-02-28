## mali-secure

1. 微信支付签名

2. 解密后端数据

## some example

```
const { Secure } = new require("mali-secure")

// cid   :商户 id
// openid:三方用户 id
// secret:秘钥
let s = new Secure("cid", "123456", "192006250b4c09247ec02edce69f6a2d")

// 获取微信支付公共签名后的地址
let uri = s.getSign("https://mp.weixin.qq.com/wxamp/devprofile/get_profile?token=1515154505&lang=zh_CN")

// 输出加密后的地址
console.log(uri);

// == 解密数据 ==
let jsonstr = { "code": 0, "crypto": "ZZwNjmEiGwTCeyYpsqKoSVMfGyUmtCGx", "data": "6f39a22554351a8ce2ea06c733d47233bee6fd2891850a38e7d55d52aee53971b129561ba3186c8ca5e3090719909cef2d03785e829e38ca76da0051fac5bf64", "msg": "成功!" }

// 获取解密数据
let decryptJson = s.decrypt(jsonstr)
console.log(decryptJson);

// 检查 data 是否是 base64，是的话解压 base64
console.log(s.checkBase64(decryptJson.data));
```
