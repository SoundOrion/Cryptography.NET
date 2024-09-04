using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography.NET.Helper;

/// <summary>
/// RSAおよびAES暗号化のためのヘルパークラス。
/// </summary>
public class RsaAesEncryption
{
    /// <summary>
    /// RSA暗号化用の公開鍵と秘密鍵のペアを生成します。
    /// </summary>
    /// <param name="keySize">RSA鍵のサイズ（ビット単位）。</param>
    /// <returns>公開鍵と秘密鍵のペア。</returns>
    public static (RSAParameters publicKey, RSAParameters privateKey) GenerateRsaKeyPair(int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        return (rsa.ExportParameters(false), rsa.ExportParameters(true));
    }

    /// <summary>
    /// AESキーをRSAの公開鍵で暗号化します。
    /// </summary>
    /// <param name="aesKey">AESキー。</param>
    /// <param name="publicKey">RSAの公開鍵。</param>
    /// <returns>暗号化されたAESキー。</returns>
    public static byte[] EncryptAesKey(byte[] aesKey, RSAParameters publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(publicKey);
        return rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>
    /// AESキーをRSAの秘密鍵で復号化します。
    /// </summary>
    /// <param name="encryptedAesKey">暗号化されたAESキー。</param>
    /// <param name="privateKey">RSAの秘密鍵。</param>
    /// <returns>復号化されたAESキー。</returns>
    public static byte[] DecryptAesKey(byte[] encryptedAesKey, RSAParameters privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(privateKey);
        return rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>
    /// 平文をAESで暗号化します。
    /// </summary>
    /// <param name="plainText">暗号化する平文。</param>
    /// <param name="key">AESキー。</param>
    /// <param name="iv">初期化ベクター（IV）。</param>
    /// <returns>暗号化されたバイト配列。</returns>
    public static byte[] EncryptAes(string plainText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        return msEncrypt.ToArray();
    }

    /// <summary>
    /// AESで暗号化されたバイト配列を復号化します。
    /// </summary>
    /// <param name="cipherBytes">暗号化されたバイト配列。</param>
    /// <param name="key">AESキー。</param>
    /// <param name="iv">初期化ベクター（IV）。</param>
    /// <returns>復号化された平文。</returns>
    public static string DecryptAes(byte[] cipherBytes, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var msDecrypt = new MemoryStream(cipherBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return srDecrypt.ReadToEnd();
    }

    /// <summary>
    /// 平文をRSAとAESで二重暗号化します。
    /// </summary>
    /// <param name="plainText">暗号化する平文。</param>
    /// <param name="publicKey">RSAの公開鍵。</param>
    /// <returns>暗号化された文字列（Base64エンコード）。</returns>
    public static string Encrypt(string plainText, RSAParameters publicKey)
    {
        // AESキーとIVを生成
        using var aes = Aes.Create();
        byte[] aesKey = aes.Key;
        byte[] iv = aes.IV;

        // AESキーをRSA公開鍵で暗号化
        byte[] encryptedAesKey = EncryptAesKey(aesKey, publicKey);

        // AESで平文を暗号化
        byte[] encryptedData = EncryptAes(plainText, aesKey, iv);

        // IVと暗号化データを結合
        byte[] combinedData = CombineData(encryptedAesKey, iv, encryptedData);

        // Base64エンコードして返す
        return Convert.ToBase64String(combinedData);
    }

    /// <summary>
    /// RSAとAESで暗号化されたデータを復号化します。
    /// </summary>
    /// <param name="cipherTextWithMac">暗号化された文字列（Base64エンコード）。</param>
    /// <param name="privateKey">RSAの秘密鍵。</param>
    /// <returns>復号化された平文。</returns>
    public static string Decrypt(string cipherTextWithMac, RSAParameters privateKey)
    {
        // Base64デコード
        byte[] combinedData = Convert.FromBase64String(cipherTextWithMac);

        // AESキー、IV、暗号化データを抽出
        byte[] encryptedAesKey = ExtractEncryptedAesKey(combinedData);
        byte[] iv = ExtractIv(combinedData);
        byte[] encryptedData = ExtractEncryptedData(combinedData);

        // RSA秘密鍵でAESキーを復号化
        byte[] aesKey = DecryptAesKey(encryptedAesKey, privateKey);

        // AESでデータを復号化
        return DecryptAes(encryptedData, aesKey, iv);
    }

    /// <summary>
    /// AESキー、IV、暗号化データを結合します。
    /// </summary>
    /// <param name="encryptedAesKey">暗号化されたAESキー。</param>
    /// <param name="iv">初期化ベクター（IV）。</param>
    /// <param name="encryptedData">暗号化されたデータ。</param>
    /// <returns>結合されたバイト配列。</returns>
    private static byte[] CombineData(byte[] encryptedAesKey, byte[] iv, byte[] encryptedData)
    {
        byte[] result = new byte[encryptedAesKey.Length + iv.Length + encryptedData.Length];

        // Encrypted AES Key
        Buffer.BlockCopy(encryptedAesKey, 0, result, 0, encryptedAesKey.Length);

        // IV
        Buffer.BlockCopy(iv, 0, result, encryptedAesKey.Length, iv.Length);

        // Data
        Buffer.BlockCopy(encryptedData, 0, result, encryptedAesKey.Length + iv.Length, encryptedData.Length);

        return result;
    }

    /// <summary>
    /// 結合されたバイト配列から暗号化されたAESキーを抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたバイト配列。</param>
    /// <returns>抽出された暗号化されたAESキー。</returns>
    private static byte[] ExtractEncryptedAesKey(byte[] combinedData)
    {
        int aesKeySize = 256 / 8; // 256ビットのAESキー
        byte[] aesKey = new byte[aesKeySize];
        Buffer.BlockCopy(combinedData, 0, aesKey, 0, aesKey.Length);
        return aesKey;
    }

    /// <summary>
    /// 結合されたバイト配列から初期化ベクター（IV）を抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたバイト配列。</param>
    /// <returns>抽出されたIV。</returns>
    private static byte[] ExtractIv(byte[] combinedData)
    {
        int aesKeySize = 256 / 8; // 256ビットのAESキー
        byte[] iv = new byte[16]; // IVは16バイト
        Buffer.BlockCopy(combinedData, aesKeySize, iv, 0, iv.Length);
        return iv;
    }

    /// <summary>
    /// 結合されたバイト配列から暗号化されたデータを抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたバイト配列。</param>
    /// <returns>抽出された暗号化データ。</returns>
    private static byte[] ExtractEncryptedData(byte[] combinedData)
    {
        int aesKeySize = 256 / 8; // 256ビットのAESキー
        int ivSize = 16; // IVは16バイト
        byte[] encryptedData = new byte[combinedData.Length - aesKeySize - ivSize];
        Buffer.BlockCopy(combinedData, aesKeySize + ivSize, encryptedData, 0, encryptedData.Length);
        return encryptedData;
    }
}
