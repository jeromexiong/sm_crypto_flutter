import 'dart:convert';

import 'package:sm_crypto_flutter/sm_crypto_flutter.dart';
import 'package:test/test.dart';

/// 移植自 sm-crypto-js/test/sm3.test.js 的固定向量。
void main() {
  group('sm3: must match the result', () {
    test('single byte / ascii', () {
      expect(
        SM3.hash('abc'),
        '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
      );
      expect(
        SM3.hash('abcdefghABCDEFGH12345678'),
        'd670c7f027fd5f9f0c163f4bfe98f9003fe597d3f52dbab0885ec2ca8dd23e9b',
      );
      expect(
        SM3.hash('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefgh'),
        '1cf3bafec325d7d9102cd67ba46b09195af4e613b6c2b898122363d810308b11',
      );
      expect(
        SM3.hash(
          'abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCD',
        ),
        'b8ac4203969bde27434ce667b0adbf3439ee97e416e73cb96f4431f478a531fe',
      );
      expect(
        SM3.hash(
          'abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDEFGH',
        ),
        '5ef0cdbe0d54426eea7f5c8b44385bb1003548735feaa59137c3dfe608aa9567',
      );
      expect(
        SM3.hash(
          'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
        ),
        'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732',
      );
    });

    test('two-byte / combining marks', () {
      expect(
        SM3.hash(
          'ÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĀāẢảȀȁȂȃẠạẶặẬậḀḁȺⱥᶏẚɐɑᶐɒᴀÆæǼǽǢǣᴂᴁ',
        ),
        '175c329c05aa9e2ce3ad49551d404f670bc7fd59dfa51c748871ffd1a6b179a6',
      );
      expect(
        SM3.hash(
          'ḂḃḄḅḆḇɃƀƁɓƂƃᵬᶀʙᴃĆćĈĉČčC̱c̱ĊċÇçḈḉȻȼƇƈɕↃↄᴄĎďḊḋḐḑḌḍḒḓḎḏÐðĐđƉɖƊɗᶑƋƌᵭȸȡᴅᴆƍʣʥʤÉéÈèĔĕÊêẾếỀềỄễỂểĚěËëẼẽĖėȨȩḜḝĘęĒēḖḗḔḕẺẻȄȅȆȇẸẹỆệḘḙḚḛɆɇᶒƎǝƏəᶕɚƐɛᶓᴈɘɜᶔɝɞʚɤᴇḞḟ',
        ),
        '42da89d385fa8b62bb531cccffe5a4115d3069cd3ad5f9f42f86fa8875308d2a',
      );
      expect(
        SM3.hash(
          'ƑƒᵮᶂⅎʩǴǵĞğĜĝǦǧĠġĢģḠḡǤǥƓɠɡᶃᵹɢʛᵷƔɣƢƣĤĥȞȟḦḧḢḣḨḩḤḥḪḫH̠ẖĦħⱧⱨǶƕⱵⱶʜɦɧÍíÌìĬĭÎîǏǐÏïḮḯĨĩĮįĪīỈỉȈȉȊȋỊịḬḭƗɨĲĳɪƗᵻᶖİıƖɩᵼᴉɿĴĵɈɉJ̌ǰȷʝɟʄᴊḰḱǨǩĶķḲḳḴḵƘƙⱩⱪᶄĸʞᴋ',
        ),
        '323d957e0426bb388bdf83149aa99f5b80447adb27fb4514d1ffffd9c2e9f1f2',
      );
    });

    test('chinese', () {
      expect(
        SM3.hash('你好'),
        '78e5c78c5322ca174089e58dc7790acf8ce9d542bee6ae4a5a0797d5e356be61',
      );
      expect(
        SM3.hash('今天天气真是不错'),
        'fff6e05118c782f5a2cea8bc2efec8819d0dc6d7d09cb9aa5c4ef14e673fa043',
      );
      expect(
        SM3.hash('今天天气真是糟透了'),
        'f2e417f09f99ee7a08fa6c8fd75f87b7969b20a60e80b04154a5aae7220c87d8',
      );
    });

    test('four-byte code points', () {
      expect(
        SM3.hash('🇨🇳𠮷😀😃😄😁😆😅'),
        'b6d217a24511ddb7593f13b74519038618cbb5b947fee20da3f0cd5503152c23',
      );
    });

    test('byte array equals utf8 string', () {
      const text = 'hello world! 我是 juneandgreen.';
      const hex =
          'ef1cc8e36012c1f1bc18034ab778ef800e8bb1b40c7a4c7177186f6fd521110e';
      expect(SM3.hash(utf8.encode(text)), hex);
      expect(SM3.hash(text), hex);
    });

    test('collision cases stay distinct', () {
      expect(
        SM3.hash('丧丙上䠉䰋不亐乑'),
        '382f78a3065187c40152d2f5ca283f8f4bf148909c763cfbdfa7efb943016552',
      );
      expect(
        SM3.hash('鱏8fpT肙腳荧HNQ'),
        'b67a77a89564b7be13fccf456e0ec39ad564eb46f4c54c6946b1d548efc4078d',
      );
      expect(SM3.hash('丧丙上䠉䰋不亐乑'), isNot(SM3.hash('鱏8fpT肙腳荧HNQ')));
    });

    test('long text (multi-block, 960 bytes)', () {
      // js 的 'sm3: long text' 用例依赖 test.jpg（未随仓库分发），
      // 这里用等价的多分组输入替代，期望值由 sm-crypto-js 0.5.7 生成。
      final long = List.filled(40, 'abcdefghABCDEFGH12345678').join();
      expect(
        SM3.hash(long),
        'fbc81fe9a6b3a8212f271c417c8b4cc0f2e6926041904ec60288d3b550c0db5c',
      );
    });
  });

  group('sm3: hmac', () {
    test('hex key', () {
      expect(
        SM3.hash(
          'abc',
          key:
              'daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9',
        ),
        '5c690e2b822a514017f1ccb9a61b6738714dbd17dbd6fdbc2fa662d122b6885d',
      );
    });

    test('byte key and byte message', () {
      expect(
        SM3.hash([
          0x31,
          0x32,
          0x33,
          0x34,
          0x35,
          0x36,
        ], key: '31323334353637383930'),
        'bc1f71eef901223ae7a9718e3ae1dbf97353c81acb429b491bbdbefd2195b95e',
      );
    });

    test('key length boundaries (32/64/128 bytes)', () {
      final bytes8 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
      final bytes32 = [...bytes8, ...bytes8, ...bytes8, ...bytes8];
      final bytes64 = [...bytes32, ...bytes32];
      final bytes128 = [...bytes64, ...bytes64];

      expect(
        SM3.hash(bytes32, key: bytes32),
        '41e6589cde89b4f8c810a820c2fb6f0ad86bf2c136a19cfb3a5c0835f598e07b',
      );
      expect(
        SM3.hash(bytes64, key: bytes64),
        'd6fb17c240930a21996373aa9fc0b1092931b016640809297911cd3f8cc9dcdd',
      );
      expect(
        SM3.hash(bytes128, key: bytes128),
        'd374f8adb0e9d1f12de94c1406fe8b2d53f84129e033f0d269400de8e8e7ca1a',
      );
    });

    test('empty key string throws (js invalid key)', () {
      expect(() => SM3.hash('abc', key: ''), throwsArgumentError);
    });
  });
}
