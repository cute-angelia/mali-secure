const { Secure } = new require("./secure")

// cid 商户 id
// openid 三方用户 id
let s = new Secure("cid123456", "123456", "192006250b4c09247ec02edce69f6a2d")

// 获取微信支付公共签名后的地址
let uri = s.getSign("https://mp.weixin.qq.com/wxamp/devprofile/get_profile?token=1515154505&lang=zh_CN")
let uri2 = s.getSign("/get_profile?token=1515154505&lang=zh_CN")
let uri3 = s.getSign("www.baidu.com/get_profile?token=1515154505&lang=zh_CN")

let uri4 = s.getSign("http://127.0.0.1:3223?token=1515154505&lang=zh_CN")

console.log(uri);
console.log(uri2);
console.log(uri3);
console.log(uri4);

let jsonstr = { "code": 0, "crypto": "ZZwNjmEiGwTCeyYpsqKoSVMfGyUmtCGx", "data": "6f39a22554351a8ce2ea06c733d47233bee6fd2891850a38e7d55d52aee53971b129561ba3186c8ca5e3090719909cef2d03785e829e38ca76da0051fac5bf64", "msg": "成功!" }

// 获取解密数据
let decryptJson = s.decrypt(jsonstr)
console.log(decryptJson);

// 检查 data 是否是 base64，是的话解压 base64
console.log(s.checkBase64(decryptJson.data));