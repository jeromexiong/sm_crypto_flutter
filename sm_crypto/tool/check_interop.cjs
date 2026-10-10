#!/usr/bin/env node
/**
 * 用 sm-crypto-js 验证 Dart 实现产出的签名/密文（dart -> js 方向互操作）。
 *
 * 用法：dart run tool/gen_dart_vectors.dart && node tool/check_interop.cjs
 */
const fs = require('fs')
const path = require('path')
const sm2 = require('../../sm-crypto-js/src/index').sm2

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'dart_vectors.json'), 'utf8'))
const {msg, publicKey, privateKey, cipherC1C3C2, cipherC1C2C3, signatures} = vectors

let failed = 0
function check(name, ok) {
  console.log((ok ? 'PASS' : 'FAIL') + '  ' + name)
  if (!ok) failed++
}

// js 解密 dart 密文
check('js decrypt dart cipher (C1C3C2)', sm2.doDecrypt(cipherC1C3C2, privateKey, 1) === msg)
check('js decrypt dart cipher (C1C2C3)', sm2.doDecrypt(cipherC1C2C3, privateKey, 0) === msg)

// js 验证 dart 签名
for (const s of signatures) {
  const opts = {hash: s.hash, der: s.der}
  if (s.userId !== undefined) opts.userId = s.userId
  const name = `js verify dart signature (hash:${s.hash} der:${s.der} userId:${s.userId === undefined ? 'default' : JSON.stringify(s.userId)})`
  check(name, sm2.doVerifySignature(msg, s.sig, publicKey, opts) === true)
}

console.log(failed === 0 ? 'ALL PASS' : failed + ' FAILED')
process.exit(failed === 0 ? 0 : 1)
