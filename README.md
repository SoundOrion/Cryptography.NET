# Cryptography.NET

`Cryptography.NET`は、安全なデータ暗号化と復号化を提供するC#ライブラリです。このライブラリは、AES（Advanced Encryption Standard）とHMAC（Hash-based Message Authentication Code）を使用して、データの暗号化と整合性検証を行います。AES-CBC（Cipher Block Chaining）およびAES-GCM（Galois/Counter Mode）の2つの暗号化アルゴリズムをサポートしています。

## 特徴

- **AES-CBC**: 古典的なブロック暗号モード。
- **AES-GCM**: より新しいモードで、暗号化と認証を同時に行います。
- **HMAC**: データの整合性と認証を保証するためのハッシュベースのメッセージ認証コード。CBCモードでのみ使用されます。

## 使用方法

### 初期化

`EncryptionAlgorithm`クラスを使用して、暗号化と復号化を行います。サポートされている暗号化アルゴリズムには、AES-CBCとAES-GCMがあります。

```csharp
using Cryptography.NET.Algorithm;

string[] passwords = { "password1", "password2" };
string hmacKey = "your-hmac-key";

// AES-CBCで暗号化
string encryptedText = EncryptionAlgorithm.Encrypt("Hello, World!", passwords, hmacKey, EncryptionSettings.EncryptionAlgorithm.AesCbc);

// AES-GCMで暗号化
string encryptedTextGcm = EncryptionAlgorithm.Encrypt("Hello, World!", passwords, hmacKey, EncryptionSettings.EncryptionAlgorithm.AesGcm);

// AES-CBCで復号化
string decryptedText = EncryptionAlgorithm.Decrypt(encryptedText, passwords, hmacKey, EncryptionSettings.EncryptionAlgorithm.AesCbc);

// AES-GCMで復号化
string decryptedTextGcm = EncryptionAlgorithm.Decrypt(encryptedTextGcm, passwords, hmacKey, EncryptionSettings.EncryptionAlgorithm.AesGcm);
```

## クラスとメソッド

### `EncryptionAlgorithm`

- `string Encrypt(string plainText, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default, EncryptionSettings.EncryptionAlgorithm algorithm = EncryptionSettings.EncryptionAlgorithm.AesCbc)`
  - 指定された平文を暗号化します。HMACはAES-CBCモードでのみ使用されます。
  
- `string Decrypt(string cipherTextWithMac, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default, EncryptionSettings.EncryptionAlgorithm algorithm = EncryptionSettings.EncryptionAlgorithm.AesCbc)`
  - 指定された暗号文を復号化します。HMACはAES-CBCモードでのみ使用されます。

### `EncryptionSettings`

- `EncryptionAlgorithm` (列挙型)
  - `AesCbc` - AES-CBCモード
  - `AesGcm` - AES-GCMモード

### `EncryptionUtility`

- `byte[] GenerateSalt(int size)`
  - 指定されたサイズのソルトを生成します。

- `byte[] GenerateIV(int size)`
  - 指定されたサイズの初期化ベクター（IV）を生成します。

### `AesCbcEncryption`

- AES-CBCモードの暗号化と復号化をサポートします。

### `AesGcmEncryption`

- AES-GCMモードの暗号化と復号化をサポートします。

## 例

```csharp
// AES-CBC例
var aesCbc = new AesCbcEncryption(passwords, hmacKey);
string encryptedTextCbc = aesCbc.Encrypt("Sample text");
string decryptedTextCbc = aesCbc.Decrypt(encryptedTextCbc);

// AES-GCM例
var aesGcm = new AesGcmEncryption(passwords);
string encryptedTextGcm = aesGcm.Encrypt("Sample text");
string decryptedTextGcm = aesGcm.Decrypt(encryptedTextGcm);
```

## 注意事項

- パスワードは十分に複雑で長いものを使用してください。
- HMACキーも適切に管理してください。
- HMACはAES-CBCモードでのみ使用されることに注意してください。

## 依存関係

- .NET 6.0 以上

## ライセンス

このプロジェクトは [Unlicense](LICENSE) の下でライセンスされています。

## コントリビューション

貢献を歓迎します！バグ報告、機能追加の提案、プルリクエストをお待ちしています。