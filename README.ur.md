<div dir="rtl" lang="ur">

# Wazuh RuleGuard (اردو)

[English README](README.md)

**Wazuh RuleGuard ایک اوپن سورس کمانڈ لائن ٹول ہے (Python 3.10 یا نیا) جو Wazuh 4.x کے ڈیٹیکشن رولز کو نمونے کے لاگز پر آزماتا ہے، اور بتاتا ہے کہ رول بدلنے یا مینیجر اپ گریڈ کرنے کے بعد کون سی ڈیٹیکشنز بدل گئیں۔** یہ ایک آزاد پروجیکٹ ہے، اور Wazuh Inc کے ساتھ اس کا کوئی تعلق یا منظوری نہیں۔

## یہ کس مسئلے کو حل کرتا ہے؟

Wazuh میں رولز کی غلطیاں اکثر خاموش ہوتی ہیں۔ رول ٹھیک لوڈ ہو جاتا ہے، دیکھنے میں درست لگتا ہے، مگر کبھی میچ نہیں کرتا۔ یا کوئی استثنا (exception) ایسا الرٹ بھی دبا دیتا ہے جو آپ کو چاہیے تھا۔ کسی کو پتا نہیں چلتا۔ RuleGuard آپ کو پہلے سے طے شدہ نمونوں کی ایک فہرست دیتا ہے: "اس لاگ پر یہ الرٹ آنا چاہیے، اور اس پر نہیں آنا چاہیے"۔ ہر تبدیلی کے بعد وہی فہرست دوبارہ چلائیں اور فرق دیکھیں۔

## کیا کیا کر سکتا ہے

| کام | کمانڈ |
|---|---|
| نمونے کا ٹیسٹ سیٹ (suite) بنانا | `ruleguard init suite.json` |
| سیٹ کی ساخت جانچنا | `ruleguard validate suite.json` |
| ٹیسٹ چلانا (مینیجر کے logtest API پر، یا آف لائن replay) | `ruleguard run suite.json --api https://test-manager:55000 --json result.json` |
| دو رنز کا موازنہ (پہلے اور بعد) | `ruleguard compare baseline.json candidate.json --json changes.json --html changes.html` |
| رولز کی XML فائلوں کی جانچ | `ruleguard lint rules/` |
| دیکھنا کہ کون سی ATT&CK تکنیکیں ٹیسٹ ہو رہی ہیں | `ruleguard coverage suite.json --want T1110` |

رپورٹیں JSON، JUnit XML، ایک آف لائن HTML صفحہ، اور CI کے لیے Markdown خلاصے کی شکل میں ملتی ہیں۔

## فوری آغاز (بغیر Wazuh کے)

کسی انسٹال کے بغیر، ریپوزٹری کے فولڈر میں:

```sh
python -m ruleguard validate examples/suite.json
python -m ruleguard run examples/suite.json --replay examples/synthetic-before.json --json result.json --html result.html
python -m ruleguard compare examples/synthetic-before.json examples/synthetic-after.json --json diff.json --html diff.html
```

`compare` کا نتیجہ 1 ہوگا، کیونکہ ڈیمو میں ایک "healthcheck exception" جان بوجھ کر ٹوٹا ہوا ہے۔ آپ Docker سے بھی چلا سکتے ہیں: `docker run --rm ghcr.io/farhan6667/wazuh-ruleguard --help`۔

## رولز کی خاموش غلطیاں پکڑنا

`ruleguard lint` وہ رولز پکڑتا ہے جو لوڈ ہو جاتے ہیں مگر خاموشی سے کبھی میچ نہیں کرتے: مثلاً `type="pcre2"` کے بغیر `[a-z]` جیسا PCRE والا سنٹیکس، ایسا XML ٹیگ جو رولز کے لیے دستاویزی نہیں ہے، دہرائی گئی آئی ڈی، اور کسی ایک ایڈریس سے بندھے ہوئے رولز جو مشین دوبارہ بننے پر بے اثر ہو جاتے ہیں۔ تفصیل [docs/wazuh-gotchas.md](docs/wazuh-gotchas.md) میں ہے۔

## اہم حدود، سچ بتانا ضروری ہے

- یہ **ابھی پروٹوٹائپ** ہے۔ ڈیمو کا ڈیٹا مصنوعی (synthetic) ہے، اور اصلی Wazuh مینیجر پر مکمل جانچ باقی ہے۔
- یہ Wazuh 4.x کے لیے ہے۔ Wazuh 5.x کے لیے الگ adapter چاہیے ہوگا۔
- logtest ثابت نہیں کرتا کہ پروڈکشن میں لاگ جمع ہوں گے یا الرٹ پہنچیں گے۔ اسے ایک اشارہ سمجھیں، حتمی ثبوت نہیں۔
- ٹیسٹ صرف ایسے مینیجر پر چلائیں جس کی آپ کو اجازت ہو، پروڈکشن پر نہیں۔ ٹوکن کو `WAZUH_API_TOKEN` میں رکھیں، کمانڈ میں کبھی نہیں۔
- رپورٹوں میں خام لاگ اور ٹوکن شامل نہیں ہوتے، لیکن کیس کے نام اور رول کی معلومات پھر بھی حساس ہو سکتی ہیں۔ شیئر کرنے سے پہلے دیکھ لیں۔

## آپ کیسے مدد کر سکتے ہیں

سب سے قیمتی چیز **اصلی Wazuh 4.x پر آزما کر بتانا** ہے کہ کیا چلا اور کیا ٹوٹا۔ اس کے علاوہ مصنوعی مثالیں، دستاویزات کی بہتری، اور کوئی بھی چھوٹی اصلاح۔ [CONTRIBUTING.md](CONTRIBUTING.md) دو منٹ کی سیٹ اپ گائیڈ دیتی ہے، اور [good first issue](https://github.com/farhan6667/wazuh-ruleguard/labels/good%20first%20issue) سے آغاز کیا جا سکتا ہے۔ کوئی بھی اصلی لاگ، پاس ورڈ، ہوسٹ نام یا ٹوکن کبھی نہ بھیجیں۔

## لائسنس اور رابطہ

Apache-2.0۔ ڈویلپر: سید فرحان احمد (SFA)، [NexaForge](https://nexaforge.eu.cc/)۔ ای میل: nexaforge.services@gmail.com

</div>
