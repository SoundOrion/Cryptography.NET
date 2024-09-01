# Cryptography.NET

`Cryptography.NET`は、AES暗号化とHMAC-SHA256およびHMAC-SHA512メッセージ認証コードを使用した強力な暗号化および復号化機能を提供するC#ライブラリです。このライブラリは、複数のパスワードによる二重暗号化とMAC（メッセージ認証コード）の検証をサポートしています。

## 特徴

- **AES暗号化**: AES-256を使用してデータを暗号化します。
- **PBKDF2**: パスワードベースのキー導出関数（PBKDF2）を使用してキーを生成します。
- **HMAC-SHA256/SHA512**: メッセージ認証コード（MAC）を生成し、データの整合性を確認します。
- **複数パスワードのサポート**: 複数のパスワードでデータを二重暗号化します。
- **アナグラム処理**: 暗号化中に文字列をアナグラム処理（前半と後半を入れ替え）します。

## 使用方法

### 暗号化

```csharp
using Cryptography.NET;

// データを暗号化する例
string plainText = "This is a secret message.";
string[] passwords = { "password1", "password2" };
string hmacKey = "hmac-secret-key";

string encryptedText = AesEncryptionHelper.Encrypt(plainText, passwords, hmacKey);
Console.WriteLine($"Encrypted: {encryptedText}");
```

### 復号化

```csharp
using Cryptography.NET;

// データを復号化する例
string cipherTextWithMac = "Base64EncodedCipherTextWithMac";
string[] passwords = { "password1", "password2" };
string hmacKey = "hmac-secret-key";

try
{
    string decryptedText = AesEncryptionHelper.Decrypt(cipherTextWithMac, passwords, hmacKey);
    Console.WriteLine($"Decrypted: {decryptedText}");
}
catch (CryptographicException e)
{
    Console.WriteLine($"Decryption failed: {e.Message}");
}
```

## クラスとメソッド

### `AesEncryptionHelper`

- `Encrypt(string plainText, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default)`:
  - 平文を複数のパスワードとHMACキーを用いて暗号化します。

- `Decrypt(string cipherTextWithMac, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default)`:
  - 暗号化された文字列を複数のパスワードとHMACキーを用いて復号化します。

### `AnagramHelper`

- `AnagramSwap(string input)`:
  - 文字列をアナグラム処理により変換します（前半と後半を入れ替え）。

- `AnagramRestore(string input)`:
  - 前半と後半の入れ替えを元に戻します。

### `HmacHelper`

- `GenerateHmac(byte[] data, string hmacKey, HashAlgorithmName hashAlgorithm)`:
  - 指定されたデータに対してHMACを生成します。

- `VerifyHmac(byte[] data, byte[] mac, string hmacKey, HashAlgorithmName hashAlgorithm)`:
  - データのMAC（メッセージ認証コード）を検証します。

## 依存関係

- .NET 6.0 以上

## ライセンス

このプロジェクトは [Unlicense](LICENSE) の下でライセンスされています。

## コントリビューション

貢献を歓迎します！バグ報告、機能追加の提案、プルリクエストをお待ちしています。