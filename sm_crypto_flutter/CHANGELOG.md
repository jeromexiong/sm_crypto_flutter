## 0.1.1

* 新增可运行示例 `example/example.dart`（SM3 杂凑/HMAC、SM4 ECB/CBC、SM2 加解密与签名验签）
* 发布链路改为 GitHub Actions tag 触发（pub.dev automated publishing + OIDC）；无 API 变更

## 0.1.0

* 初始版本发布，API 与 sm-crypto-js 对齐并保持互操作
* SM2: 椭圆曲线公钥密码算法
  * 密钥对生成（支持自定义随机数）
  * 公钥压缩 / 比较 / 验证
  * 加密/解密（支持 C1C2C3 和 C1C3C2 格式，字符串/字节数组输入输出）
  * 数字签名/验签（SM3 杂凑/纯签名、DER 严格规范编码、userId、点池加速）
* SM3: 密码杂凑算法（256 位哈希 + HMAC-SM3）
* SM4: 分组密码算法（ECB/CBC、pkcs#5/pkcs#7/none 填充）
