#!/usr/bin/env node
/**
 * 用 sm-crypto-js（参考实现）生成互操作测试向量，写入 tool/interop_vectors.json。
 *
 * 用法：node tool/gen_vectors.cjs   （需先在 sm-crypto-js/ 下 npm install）
 * test/interop_test.dart 会读取该 JSON 并断言 Dart 实现输出/验证一致。
 */
const fs = require('fs')
const path = require('path')
const sm2 = require('../../sm-crypto-js/src/index').sm2
const sm3 = require('../../sm-crypto-js/src/index').sm3
const sm4 = require('../../sm-crypto-js/src/index').sm4

const msg = 'absasdagfadgadsfdfdsf'
const bytesMsg = [0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66]

// 1. 确定性密钥对（自定义随机数走 jsbn BigInteger 构造器，十进制字符串）
const keypair = sm2.generateKeyPairHex('123123123123123')
const compressed = sm2.compressPublicKeyHex(keypair.publicKey)

// 2. js 加密 → dart 解密（两种密文格式）
const cipherC1C3C2 = sm2.doEncrypt(msg, keypair.publicKey, 1)
const cipherC1C2C3 = sm2.doEncrypt(msg, keypair.publicKey, 0)
const cipherCompressedKey = sm2.doEncrypt(msg, compressed, 1)
const cipherBytes = sm2.doEncrypt(bytesMsg, keypair.publicKey, 1)

// 3. js 签名 → dart 验签（多种选项组合）
const sigOpts = [
  {},
  {hash: true},
  {hash: false},
  {der: true},
  {hash: false, der: true},
  {publicKey: keypair.publicKey},
  {userId: 'testUserId', publicKey: keypair.publicKey},
  {userId: '', publicKey: keypair.publicKey},
]
const signatures = sigOpts.map(opts => ({opts, sig: sm2.doSignature(msg, keypair.privateKey, opts)}))

// 4. sm3 / hmac 固定向量
const sm3Vectors = [
  {input: 'abc'},
  {input: 'abcdefghABCDEFGH12345678'},
  {input: '你好'},
  {input: '今天天气真是不错'},
  {input: '🇨🇳𠮷😀😃😄😁😆😅'},
  {input: 'hello world! 我是 juneandgreen.'},
  {bytes: bytesMsg},
  {input: '丧丙上䠉䰋不亐乑'},
  {input: '鱏8fpT肙腳荧HNQ'},
].map(v => ({...v, hash: sm3(v.bytes || v.input)}))

const hmacVectors = [
  {input: 'abc', key: 'daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9'},
  {bytes: [0x31, 0x32, 0x33, 0x34, 0x35, 0x36], key: '31323334353637383930'},
  {bytes: [...Array(8).keys()].map(i => i + 1), key: '0102030405060708'},
].map(v => ({...v, hash: sm3(v.bytes || v.input, {key: v.key})}))

// 5. sm4 向量（ECB / CBC）
const keyHex = '0123456789abcdeffedcba9876543210'
const ivHex = 'fedcba98765432100123456789abcdef'
const sm4Vectors = [
  {msg: 'hello world! 我是 juneandgreen.', key: keyHex, ct: sm4.encrypt('hello world! 我是 juneandgreen.', keyHex)},
  {msg: 'hello world! 我是 juneandgreen.', key: keyHex, mode: 'cbc', iv: ivHex, ct: sm4.encrypt('hello world! 我是 juneandgreen.', keyHex, {mode: 'cbc', iv: ivHex})},
  {msg: '🇨🇳𠮷😀😃😄😁😆😅', key: keyHex, ct: sm4.encrypt('🇨🇳𠮷😀😃😄😁😆😅', keyHex)},
  {bytes: bytesMsg, key: keyHex, ct: sm4.encrypt(bytesMsg, keyHex)},
  {bytes: bytesMsg, key: keyHex, mode: 'cbc', iv: ivHex, ct: sm4.encrypt(bytesMsg, keyHex, {mode: 'cbc', iv: ivHex})},
]

const vectors = {
  generatedBy: 'sm-crypto-js ' + require('../../sm-crypto-js/package.json').version,
  keypair: {...keypair, compressed},
  msg,
  bytesMsg,
  cipherC1C3C2,
  cipherC1C2C3,
  cipherCompressedKey,
  cipherBytes,
  signatures,
  sm3Vectors,
  hmacVectors,
  sm4Vectors,
}

const out = path.join(__dirname, 'interop_vectors.json')
fs.writeFileSync(out, JSON.stringify(vectors, null, 2) + '\n')
console.log('written:', out)
