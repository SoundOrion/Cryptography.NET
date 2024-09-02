using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography.NET;

public class AesEncryptionHelper
{
    private static readonly HashAlgorithmName[] AllowedHashAlgorithms = { HashAlgorithmName.SHA256, HashAlgorithmName.SHA512 };

    /// <summary>
    /// PBKDF2の繰り返し回数
    /// </summary>
    private static readonly int IterationCount = 10000;

    /// <summary>
    /// 暗号化に使用するソルトのサイズ（バイト単位）。
    /// 通常、16バイトのソルトを使用して暗号化キーを強化します。
    /// </summary>
    private static readonly int SaltSize = 16;

    /// <summary>
    /// AES暗号化に使用する初期化ベクター（IV）のサイズ（バイト単位）。
    /// AES-128およびAES-256の標準的なIVサイズは16バイトです。
    /// </summary>
    private static readonly int IvSize = 16;

    /// <summary>
    /// AES暗号化で使用するキーのサイズ（バイト単位）。
    /// ここでは256ビットのキー（32バイト）を使用しています。
    /// </summary>
    private static readonly int KeySize = 32;

    /// <summary>
    /// HMAC-SHA256のメッセージ認証コード（MAC）のサイズ（バイト単位）。
    /// HMAC-SHA256は256ビット（32バイト）のMACを生成します。
    /// </summary>
    private static readonly int HmacSha256Size = 32; // 32バイト (256ビット)

    /// <summary>
    /// HMAC-SHA512のメッセージ認証コード（MAC）のサイズ（バイト単位）。
    /// HMAC-SHA512は512ビット（64バイト）のMACを生成します。
    /// </summary>
    private static readonly int HmacSha512Size = 64; // 64バイト (512ビット)

    /// <summary>
    /// 文字列を複数のパスワードとHMACキーを用いて二重暗号化します。
    /// </summary>
    /// <param name="plainText">暗号化する平文。</param>
    /// <param name="passwords">暗号化に使用するパスワードの配列。</param>
    /// <param name="hmacKey">HMACのキー。</param>
    /// <returns>暗号化された文字列（Base64エンコード）。</returns>
    public static string Encrypt(string plainText, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default)
    {
        hashAlgorithm = ValidateHashAlgorithm(hashAlgorithm);

        byte[] salt = GenerateSalt(SaltSize);
        byte[] iv = GenerateIV(IvSize);

        // 最初のラウンドの暗号化
        byte[] key1 = DeriveKey(passwords[0], salt, hashAlgorithm);
        var encryptedData = EncryptAes(plainText, key1, iv);

        // 二番目のラウンド以降の暗号化
        for (int i = 1; i < passwords.Length; i++)
        {
            var encryptedText = Convert.ToBase64String(encryptedData);

            // アナグラム処理
            encryptedText = AnagramHelper.AnagramSwap(encryptedText);

            byte[] key = DeriveKey(passwords[i], salt, hashAlgorithm);
            encryptedData = EncryptAes(encryptedText, key, iv);
        }

        // MAC生成
        byte[] mac = HmacHelper.GenerateHmac(encryptedData, hmacKey, hashAlgorithm);

        // Salt、IV、暗号化データ、MACを結合
        byte[] combinedData = CombineData(salt, iv, encryptedData, mac, hmacKey);

        // Base64エンコードして返す
        return Convert.ToBase64String(combinedData);
    }

    /// <summary>
    /// 暗号化された文字列を複数のパスワードとHMACキーを用いて復号化します。
    /// </summary>
    /// <param name="cipherTextWithMac">暗号化された文字列（Base64エンコード）、MAC付き。</param>
    /// <param name="passwords">暗号化に使用したパスワードの配列。</param>
    /// <param name="hmacKey">HMACのキー。</param>
    /// <returns>復号化された平文。</returns>
    /// <exception cref="CryptographicException">MAC検証に失敗した場合。</exception>
    public static string Decrypt(string cipherTextWithMac, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default)
    {
        hashAlgorithm = ValidateHashAlgorithm(hashAlgorithm);

        // Base64デコード
        byte[] combinedData = Convert.FromBase64String(cipherTextWithMac);

        // Salt、IV、暗号化データ、MACを抽出
        byte[] salt = ExtractSalt(combinedData);
        byte[] iv = ExtractIv(combinedData);
        byte[] encryptedData = ExtractEncryptedData(combinedData, hmacKey, hashAlgorithm);
        byte[] mac = ExtractMac(combinedData, hmacKey, hashAlgorithm);

        // MAC検証
        if (!HmacHelper.VerifyHmac(encryptedData, mac, hmacKey, hashAlgorithm))
        {
            throw new CryptographicException("データの整合性が確認できません。");
        }

        // 復号化（最後のラウンドから順に解く）
        for (int i = passwords.Length - 1; i >= 1; i--)
        {
            var password = passwords[i];
            byte[] key = DeriveKey(password, salt, hashAlgorithm);
            string decryptedIntermediate = DecryptAes(encryptedData, key, iv);

            // アナグラム処理
            decryptedIntermediate = AnagramHelper.AnagramRestore(decryptedIntermediate);

            encryptedData = Convert.FromBase64String(decryptedIntermediate);
        }

        // 最終的な平文を返す
        string decryptedText = DecryptAes(encryptedData, DeriveKey(passwords[0], salt, hashAlgorithm), iv);
        return decryptedText;
    }

    /// <summary>
    /// AESを使用して平文を暗号化します。
    /// </summary>
    /// <param name="plainText">暗号化する平文。</param>
    /// <param name="key">暗号化に使用するキー。</param>
    /// <param name="iv">初期化ベクター（IV）。</param>
    /// <returns>暗号化されたバイト配列。</returns>
    private static byte[] EncryptAes(string plainText, byte[] key, byte[] iv)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.IV = iv;

        using var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        return msEncrypt.ToArray();
    }

    /// <summary>
    /// AESを使用して暗号化されたバイト配列を復号化します。
    /// </summary>
    /// <param name="cipherBytes">暗号化されたバイト配列。</param>
    /// <param name="key">復号化に使用するキー。</param>
    /// <param name="iv">初期化ベクター（IV）。</param>
    /// <returns>復号化された平文。</returns>
    private static string DecryptAes(byte[] cipherBytes, byte[] key, byte[] iv)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = key;
        aesAlg.IV = iv;

        using var msDecrypt = new MemoryStream(cipherBytes);
        using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return srDecrypt.ReadToEnd();
    }

    private static HashAlgorithmName ValidateHashAlgorithm(HashAlgorithmName hashAlgorithm)
    {
        // デフォルト値が指定されていない場合、SHA256を使用
        if (hashAlgorithm == default)
        {
            hashAlgorithm = HashAlgorithmName.SHA256;
        }

        foreach (var allowedAlg in AllowedHashAlgorithms)
        {
            if (hashAlgorithm.Equals(allowedAlg))
            {
                return hashAlgorithm;
            }
        }

        throw new ArgumentException($"Unsupported HashAlgorithmName. Only SHA256 and SHA512 are supported. Provided: {hashAlgorithm.Name}");
    }

    /// <summary>
    /// パスワードとSaltを用いてキーを派生させます。
    /// </summary>
    /// <param name="password">パスワード。</param>
    /// <param name="salt">Salt。</param>
    /// <param name="hashAlgorithm">使用するハッシュアルゴリズム（SHA256 または SHA512）。</param>
    /// <returns>派生されたキー。</returns>
    private static byte[] DeriveKey(string password, byte[] salt, HashAlgorithmName hashAlgorithm)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            IterationCount,
            hashAlgorithm,
            KeySize);
    }

    /// <summary>
    /// 指定された長さのSaltを生成します。
    /// </summary>
    /// <param name="length">Saltの長さ。</param>
    /// <returns>生成されたSaltのバイト配列。</returns>
    private static byte[] GenerateSalt(int length)
    {
        return RandomNumberGenerator.GetBytes(length);
    }

    /// <summary>
    /// 指定された長さのIV（初期化ベクター）を生成します。
    /// </summary>
    /// <param name="length">IVの長さ。</param>
    /// <returns>生成されたIVのバイト配列。</returns>
    private static byte[] GenerateIV(int length)
    {
        return RandomNumberGenerator.GetBytes(length);
    }

    /// <summary>
    /// Salt、IV、データ、MACを結合して1つのバイト配列にします。
    /// </summary>
    /// <param name="salt">Salt。</param>
    /// <param name="iv">IV。</param>
    /// <param name="data">データ。</param>
    /// <param name="mac">MAC。</param>
    /// <returns>結合されたバイト配列。</returns>
    private static byte[] CombineData(byte[] salt, byte[] iv, byte[] data, byte[] mac, string hmacKey)
    {
        byte[] result = new byte[salt.Length + iv.Length + data.Length + mac.Length];

        // Salt
        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);

        // IV
        Buffer.BlockCopy(iv, 0, result, salt.Length, iv.Length);

        // Data
        Buffer.BlockCopy(data, 0, result, salt.Length + iv.Length, data.Length);

        // MAC
        if (!string.IsNullOrEmpty(hmacKey))
        {
            Buffer.BlockCopy(mac, 0, result, salt.Length + iv.Length + data.Length, mac.Length);
        }

        return result;
    }

    /// <summary>
    /// 結合されたデータからSaltを抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたデータ。</param>
    /// <returns>抽出されたSalt。</returns>
    private static byte[] ExtractSalt(byte[] combinedData)
    {
        byte[] salt = new byte[SaltSize];
        Buffer.BlockCopy(combinedData, 0, salt, 0, SaltSize);
        return salt;
    }

    /// <summary>
    /// 結合されたデータからIVを抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたデータ。</param>
    /// <returns>抽出されたIV。</returns>
    private static byte[] ExtractIv(byte[] combinedData)
    {
        byte[] iv = new byte[IvSize];
        Buffer.BlockCopy(combinedData, SaltSize, iv, 0, IvSize);
        return iv;
    }

    /// <summary>
    /// 結合されたデータから暗号化データを抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたデータ。</param>
    /// <returns>抽出された暗号化データ。</returns>
    private static byte[] ExtractEncryptedData(byte[] combinedData, string hmacKey, HashAlgorithmName hashAlgorithm)
    {
        int macSize = GetMacSize(hmacKey, hashAlgorithm);
        byte[] data = new byte[combinedData.Length - SaltSize - IvSize - macSize];
        Buffer.BlockCopy(combinedData, SaltSize + IvSize, data, 0, data.Length);
        return data;
    }

    /// <summary>
    /// 結合されたデータからMACを抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたデータ。</param>
    /// <returns>抽出されたMAC。</returns>
    private static byte[] ExtractMac(byte[] combinedData, string hmacKey, HashAlgorithmName hashAlgorithm)
    {
        int macSize = GetMacSize(hmacKey, hashAlgorithm);
        byte[] mac = new byte[macSize];
        Buffer.BlockCopy(combinedData, combinedData.Length - macSize, mac, 0, mac.Length);
        return mac;
    }

    /// <summary>
    /// 指定されたHMACキーとハッシュアルゴリズムに基づいて、MAC（メッセージ認証コード）のサイズを取得します。
    /// </summary>
    /// <param name="hmacKey">HMACのキー。空または空白の場合、MACのサイズは0として扱います。</param>
    /// <param name="hashAlgorithm">使用するハッシュアルゴリズム。サポートされているのはSHA256またはSHA512です。</param>
    /// <returns>指定されたハッシュアルゴリズムに基づくMACのサイズ（バイト単位）。HMACキーが空または空白の場合は0。</returns>
    /// <exception cref="ArgumentException">指定されたハッシュアルゴリズムがサポートされていない場合。</exception>
    private static int GetMacSize(string hmacKey, HashAlgorithmName hashAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(hmacKey))
        {
            return 0;
        }

        return hashAlgorithm switch
        {
            var alg when alg == HashAlgorithmName.SHA256 => HmacSha256Size,
            var alg when alg == HashAlgorithmName.SHA512 => HmacSha512Size,
            _ => throw new ArgumentException("Unsupported HMAC algorithm specified.")
        };
    }
}