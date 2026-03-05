# LINE Account Registration Client (linejs)

LINE の **PrimaryAccountInitService (PAIS)** API を使用して、電話番号ベースのアカウント登録を行う Node.js スクリプトです。  
Python の [CHRLINE](https://github.com/DeachSword/CHRLINE) ライブラリで書かれた `test_register.py` を、JavaScript / [@evex/linejs](https://jsr.io/@evex/linejs) に移植したものです。

---

## 目次

- [概要](#概要)
- [動作フロー](#動作フロー)
- [技術スタック](#技術スタック)
- [LEGY 暗号化レイヤー](#legy-暗号化レイヤー)
- [パスワード暗号化 (ECDH)](#パスワード暗号化-ecdh)
- [Thrift プロトコル](#thrift-プロトコル)
- [PrimaryToken 生成](#primarytoken-生成)
- [ディレクトリ構成](#ディレクトリ構成)
- [セットアップ](#セットアップ)
- [使い方](#使い方)
- [設定項目](#設定項目)
- [エラーハンドリング](#エラーハンドリング)
- [注意事項](#注意事項)

---

## 概要

LINE のモバイルアプリ (Android) が内部で行っている新規アカウント登録プロセスを再現します。  
すべての通信は LINE の **LEGY (LINE Event Gateway)** プロキシを経由し、AES-128-CBC で暗号化されたうえで送受信されます。

### 主な機能

- LEGY 暗号化トランスポートの完全実装 (AES-128-CBC + RSA-OAEP + xxHash32 HMAC)
- Curve25519 ECDH によるパスワードの E2E 暗号化
- Thrift Binary Protocol (TBinary) によるシリアライゼーション
- PrimaryToken (v1 トークン) の生成
- 登録後のプロフィール名更新 (TalkService `/S3`)

---

## 動作フロー

```
Client                                LEGY Proxy                         LINE Server
  │                                  (gf.line.naver.jp/enc)             (PAIS API)
  │                                       │                                 │
  │  1. openSession ─────────────────────►│──────────────────────────────►  │
  │  ◄─────────────── authSessionId ──────│◄──────────────────────────────  │
  │                                       │                                 │
  │  2. getCountryInfo ──────────────────►│──────────────────────────────►  │
  │  ◄──────────── countryCode, GDPR ─────│◄──────────────────────────────  │
  │                                       │                                 │
  │  [User: input phone & region]         │                                 │
  │                                       │                                 │
  │  3. getPhoneVerifMethodV2 ───────────►│──────────────────────────────►  │
  │  ◄───────── formattedPhone, methods ──│◄──────────────────────────────  │
  │                                       │                                 │
  │  4. requestToSendPhonePinCode ───────►│──────────────────────────────►  │
  │  ◄──────────────── (PIN sent) ────────│◄──────────────────────────────  │
  │                                       │                                 │
  │  [User: input PIN code]               │                                 │
  │                                       │                                 │
  │  5. verifyPhonePinCode ──────────────►│──────────────────────────────►  │
  │  ◄──────── accountExist, etc. ────────│◄──────────────────────────────  │
  │                                       │                                 │
  │  6. validateProfile ─────────────────►│──────────────────────────────►  │
  │  ◄──────────────── OK ────────────────│◄──────────────────────────────  │
  │                                       │                                 │
  │  7. exchangeEncryptionKey ───────────►│──────────────────────────────►  │
  │  ◄──────── serverKey, serverNonce ────│◄──────────────────────────────  │
  │                                       │                                 │
  │  [ECDH: derive shared secret]         │                                 │
  │  [AES-CBC encrypt password]           │                                 │
  │                                       │                                 │
  │  8. setPassword ─────────────────────►│──────────────────────────────►  │
  │  ◄──────────────── OK ────────────────│◄──────────────────────────────  │
  │                                       │                                 │
  │  9. registerPrimaryWithTokenV3 ──────►│──────────────────────────────►  │
  │  ◄─── authKey, tokenV3, mid ──────────│◄──────────────────────────────  │
  │                                       │                                 │
  │  [Generate PrimaryToken from authKey] │                                 │
  │                                       │                                 │
  │  10. updateProfileAttribute ─────────►│──────────── (/S3) ──────────►  │
  │  ◄──────────────── OK ────────────────│◄──────────────────────────────  │
```

---

## 技術スタック

### ランタイム

| 項目 | 詳細 |
|------|------|
| **Node.js** | >= 18.0.0 (ESM modules, `node:crypto`, `node:https` 必須) |
| **モジュールシステム** | ES Modules (`"type": "module"` in package.json) |

### 依存パッケージ

| パッケージ | バージョン | 用途 |
|-----------|-----------|------|
| **@evex/linejs** | ^2.3.7 (JSR) | LINE Thrift 構造体定義 (`LINEStruct`) 、Thrift シリアライザ (`writeThrift`/`readThrift`)、プロトコル定義 (`Protocols`) |
| **tweetnacl** | ^1.0.3 | NaCl暗号ライブラリ。Curve25519 鍵ペア生成 (`box.keyPair.fromSecretKey`) |
| **curve25519-js** | ^0.0.4 | Curve25519 ECDH 共有鍵計算 (`sharedKey`) |
| **xxhash-wasm** | ^1.1.0 | xxHash32 の WebAssembly 実装。LEGY HMAC 計算に使用 |

### 組み込みモジュール (Node.js)

| モジュール | 用途 |
|-----------|------|
| `node:crypto` | AES-128-CBC 暗号化/復号、RSA-OAEP 暗号化、SHA-256 ハッシュ、HMAC-SHA1/SHA256、乱数生成 |
| `node:https` | HTTP/S リクエスト送信 (tab 文字を含むヘッダーの正確な送信のため `fetch` ではなく直接使用) |
| `node:readline` | CLI 対話入力 (電話番号、PIN コード) |

### なぜ `fetch` ではなく `node:https` を使うのか

LINE の `x-line-application` ヘッダーにはタブ文字 (`\t`) が含まれています：

```
ANDROID\t26.2.0\tAndroid OS\t15
```

Node.js の `fetch` 実装 (undici) はヘッダー値のバリデーションが厳密で、タブ文字を含むヘッダーを拒否またはエスケープする場合があります。  
`node:https` モジュールではバイト列がそのまま送信されるため、こちらを採用しています。

---

## LEGY 暗号化レイヤー

LINE のすべての API リクエストは LEGY (LINE Event Gateway) プロキシ経由で送信されます。  
LEGY はリクエスト/レスポンスの暗号化を行うトランスポートレイヤーです。

### エンドポイント

```
POST https://gf.line.naver.jp/enc
```

### 暗号化パラメータ

| パラメータ | 値 | 説明 |
|-----------|-----|------|
| `x-le` | `7` | LEGY バージョン。ビットフラグで動作を制御 |
| `x-lcs` | `0008` + RSA暗号化AES鍵 | セッション鍵のネゴシエーション |
| `x-lpv` | `1` | プロトコルバージョン |
| `x-lap` | `5` | 認証パラメータ |

### LEGY バージョン 7 のビットフラグ

```
le = 7 (binary: 0111)

bit 2 (& 4 = 4): ✓ → 暗号化前にリクエストボディ先頭にle値バイトを挿入
                     レスポンス復号後に先頭1バイトを除去
bit 1 (& 2 = 2): ✓ → 暗号化後にxxHash32 HMACを末尾に付加
```

### リクエスト暗号化フロー

```
1. 内部ヘッダーのシリアライズ
   { "x-lpqs": "/acct/pais/v1" }  →  バイナリ形式

2. Thrift ボディのシリアライズ
   LINEStruct → writeThrift() → バイナリ

3. 結合
   plaintext = encHeaders(inner) + thriftBody

4. le バイト挿入 (le & 4)
   toEncrypt = [0x07] + plaintext

5. AES-128-CBC 暗号化
   encrypted = AES_CBC(key, IV, toEncrypt)

6. HMAC 付加 (le & 2)
   payload = encrypted + xxHash32_HMAC(key, encrypted)
```

### AES-128-CBC 鍵交換

```
1. クライアント: 16バイトのランダム AES 鍵を生成
2. RSA-OAEP (SHA-1) でサーバー公開鍵を使い AES 鍵を暗号化
3. Base64 エンコード → "0008" プレフィックス付加 → x-lcs ヘッダーに設定
4. 以降の全通信でこの AES 鍵と固定 IV で暗号化/復号
```

### xxHash32 HMAC

LEGY の HMAC は標準的な HMAC とは異なり、xxHash32 ベースの独自実装です：

```
function leGyHmac(key, data):
    opad = key XOR 0x5c (16 bytes)
    ipad = key XOR 0x36 (16 bytes)
    inner = xxh32(ipad || data)
    outer = xxh32(opad || bytes(inner))
    return outer (4 bytes)
```

### レスポンス復号フロー

```
1. AES-128-CBC 復号 (PKCS7 パディング処理付き)
2. le バイト除去 (先頭1バイト)
3. 内部ヘッダー解析 (x-lc ステータスコード等)
4. Thrift ボディ解析 → readThrift()
```

---

## パスワード暗号化 (ECDH)

パスワードは Curve25519 ECDH を使って E2E 暗号化されます。

### 鍵交換プロセス

```
[ クライアント ]                              [ サーバー ]
     │                                           │
     │  1. Curve25519 鍵ペア生成                  │
     │     secretKey (32 bytes, random)           │
     │     publicKey = curve25519(secretKey)       │
     │     nonce (16 bytes, random)               │
     │                                           │
     │  exchangeEncryptionKey ──────────────────► │
     │  (publicKey, nonce, version=1)             │
     │                                           │
     │  ◄─────────────── (serverKey, serverNonce) │
     │                                           │
     │  2. 共有鍵計算                              │
     │     shared = ECDH(secretKey, serverKey)    │
     │                                           │
     │  3. 鍵導出 (HKDF-like)                     │
     │     masterKey = SHA256("master_key" || shared || nonce || serverNonce)
     │     aesKey    = SHA256("aes_key" || masterKey)
     │     hmacKey   = SHA256("hmac_key" || masterKey)
     │                                           │
     │  4. パスワード暗号化                        │
     │     encKey = aesKey[0:16]                  │
     │     encIV  = aesKey[16:32]                 │
     │     encrypted = AES_CBC(encKey, encIV, password)
     │     hmac = HMAC_SHA256(hmacKey, encrypted) │
     │     encPwd = Base64(encrypted + hmac)      │
```

---

## Thrift プロトコル

LINE の内部 API は Apache Thrift の **TBinary Protocol** を使用しています。

### プロトコルタイプ

| ID | 名前 | 用途 |
|----|------|------|
| 3 | TBinary | PAIS 登録 API (`/acct/pais/v1`) |
| 4 | TCompact | TalkService (`/S3`) |

### LINEStruct の利用

`@evex/linejs` の `LINEStruct` は LINE の Thrift IDL 定義から生成された構造体です。  
以下のメソッドで自動的に正しい Thrift フィールド番号・型にシリアライズされます：

```javascript
// LINEStruct を使える場合
LINEStruct.openSession_args({ request: { metaData: {} } })
LINEStruct.getCountryInfo_args({ authSessionId })
LINEStruct.getPhoneVerifMethodV2_args({ request: { ... } })

// LINEStruct に定義がない場合 → raw thrift 配列
// [type, fieldId, value]
[
  [11, 1, authSessionId],     // string, field 1
  [12, 2, [                   // struct, field 2
    [8, 1, 1],                //   i32, field 1
    [11, 2, b64PublicKey],     //   string, field 2
  ]],
]
```

### Thrift 型 ID

| ID | 型 |
|----|----|
| 2 | bool |
| 3 | byte |
| 6 | i16 |
| 8 | i32 |
| 10 | i64 |
| 11 | string |
| 12 | struct |
| 13 | map |
| 14 | set |
| 15 | list |

---

## PrimaryToken 生成

登録成功後に返される `authKey` から PrimaryToken (v1) を生成します。  
このトークンは TalkService (`/S3`) への認証に使用されます。

```
authKey 形式: "{mid}:{base64_secret_key}"

PrimaryToken = "{mid}:{iat}.{digest}"
  iat    = Base64("iat: {unix_timestamp * 60}\n") + "."
  digest = Base64(HMAC-SHA1(secret_key, iat))
```

> **注**: PrimaryToken は v1 トークンであり、`/S3` エンドポイントで使用します。  
> `/S4` (v3 token) には `AccessTokenV3` を直接使用してください。

---

## ディレクトリ構成

```
accountCreate/
├── main.js           # メインスクリプト (JavaScript / ESM)
├── register.py       # 元の Python 実装 (CHRLINE ベース、参考用)
├── package.json      # npm 設定 (type: module)
├── .npmrc            # JSR レジストリ設定
├── node_modules/     # 依存パッケージ
└── CHRLINE_0/        # Python CHRLINE ライブラリ (参考用)
```

---

## セットアップ

### 前提条件

- **Node.js** v18 以上
- **npm** v8 以上

### インストール

```bash
# リポジトリをクローン
git clone <repository-url>
cd accountCreate

# 依存パッケージをインストール
npm install

# linejs (JSR パッケージ) をインストール
npx jsr add @evex/linejs

# その他の依存パッケージ
npm install tweetnacl curve25519-js xxhash-wasm
```

### package.json の確認

```json
{
  "type": "module",
  "dependencies": {
    "@evex/linejs": "npm:@jsr/evex__linejs@^2.3.7",
    "xxhash-wasm": "^1.1.0"
  }
}
```

> `tweetnacl` と `curve25519-js` は `@evex/linejs` の依存関係として自動インストールされる場合がありますが、  
> 明示的にインストールすることを推奨します。

---

## 使い方

### 1. 設定を編集

`main.js` の先頭にある Config セクションを編集します：

```javascript
const UPDATE_NAME = true;           // 登録後に表示名を更新するか
const DISPLAY_NAME = "your_name";   // 表示名
const PASSWORD = "your_password";   // アカウントのパスワード
const DEVICE_MODEL = "SM-N950F";    // デバイスモデル名
```

### 2. 実行

```bash
node main.js
```

### 3. 対話的な入力

1. **電話番号**: 国番号なしで入力 (例: `09012345678`)
2. **地域コード**: 2文字の国コード (例: `JP`, `TH`, `TW`)
3. **PIN コード**: SMS で受信した6桁のコード

### 実行例

```
  Session ID: 7lWXRwdoRTRJ8n7EB196XhOrRLvvCd1D
  Country: JP, GDPR restricted: false
Phone number (e.g. 09012345678): 09012345678
Region code (e.g. JP, TH, TW): JP
  Formatted: +81 90-1234-5678  Methods: [1,2]
  PIN sent. Available methods: [1,2]
PIN code: 123456
  accountExist=false, sameUdidExist=false, allowToRegister=true
  Profile OK: "your_name"
  Key exchange complete.
  Password encrypted.
  Password set.

===== Registration Complete =====
MID:            u0123456789abcdef0123456789abcdef
AuthKey:        u0123456789abcdef...:base64key
PrimaryToken:   u0123456789abcdef...:iat.digest
AccessTokenV3:  eyJ...
RefreshToken:   eyJ...
DurationSec:    274755
LoginSessionId: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
=================================

Updating display name to "your_name"...
  Display name updated.
Done!
```

---

## 設定項目

| 変数 | デフォルト値 | 説明 |
|------|------------|------|
| `UPDATE_NAME` | `true` | 登録後に表示名を更新するかどうか |
| `DISPLAY_NAME` | `"moyashi_example"` | LINE 上の表示名 |
| `PASSWORD` | `"@moyashi0171R"` | アカウントのパスワード |
| `DEVICE_MODEL` | `"SM-N950F"` | エミュレートするデバイスモデル |

### 変更が必要な場合がある定数

| 定数 | 現在の値 | 説明 |
|------|---------|------|
| `X_LINE_APP` | `"ANDROID\t26.2.0\tAndroid OS\t15"` | LINE アプリバージョン。古いとHTTP 403を返す |
| `USER_AGENT` | `"Line/26.2.0 A2342 15"` | HTTP User-Agent |
| `LEGY_LE` | `"7"` | LEGY バージョン。暗号化方式を決定 |
| `LINE_PUBLIC_KEY` | RSA-2048 公開鍵 | LEGY の鍵交換用。サーバー側で変更される可能性あり |

---

## エラーハンドリング

### エラー種別

| エラークラス | 発生箇所 | 説明 |
|------------|---------|------|
| `PaisError` | Thrift レスポンス | PAIS API がエラーを返した場合。`code` と `message` を含む |
| `LeGyTransportError` | LEGY トランスポート | HTTP エラー、復号失敗、LEGY ステータスエラー |

### よくあるエラー

| コード | メッセージ | 原因・対処法 |
|--------|----------|------------|
| HTTP 403 | `x-lcr: 386` | LINE アプリバージョンが古い。`X_LINE_APP` を最新版に更新 |
| code=100 | セッションがタイムアウト | セッション ID の取得に失敗しているか、時間が経過しすぎ |
| code=5 | HUMAN_VERIFICATION_REQUIRED | CAPTCHA 認証が必要。自動化による検知の可能性 |
| Empty response | `Empty response body` | サーバーに接続できたがレスポンスなし |
| Decryption failed | - | AES 鍵が不正、または LEGY プロトコル変更の可能性 |

### Human Verification (code=5)

`verifyPhonePinCode` で code=5 が返された場合、CAPTCHA 解決が必要です。  
エラーの `metadata` フィールドに CAPTCHA URL が含まれます。  
現在のスクリプトでは自動解決には対応していません。

---

## 注意事項

- このスクリプトは**教育・研究目的**で作成されています
- LINE の利用規約に違反する使用は自己責任で行ってください
- LINE のサーバー側の変更により、将来的に動作しなくなる可能性があります
- 特に `LINE_PUBLIC_KEY` (RSA 公開鍵) と `X_LINE_APP` (アプリバージョン) は定期的に更新が必要です
