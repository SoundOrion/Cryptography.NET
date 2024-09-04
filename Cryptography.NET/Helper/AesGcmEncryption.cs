using Cryptography.NET.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.Helper;

public class AesGcmEncryption : IEncryptionAlgorithm
{
    /// <summary>
    /// サポートされているハッシュアルゴリズム。
    /// </summary>
    public static readonly HashAlgorithmName[] AllowedHashAlgorithms = { HashAlgorithmName.SHA256, HashAlgorithmName.SHA512 };

    /// <summary>
    /// PBKDF2の繰り返し回数。
    /// </summary>
    public static readonly int IterationCount = 10000;

    /// <summary>
    /// AesGcmでは128ビット（16バイト）、192ビット（24バイト）、または256ビット（32バイト）の鍵が使用できます。
    /// </summary>
    public static readonly int SaltSize = 16;

    /// <summary>
    /// 通常12バイト（96ビット）のランダムな初期化ベクトルが使われます
    /// </summary>
    public static readonly int IvSize = 12;

    /// <summary>
    /// AES暗号化で使用するキーのサイズ（バイト単位）。
    /// ここでは256ビットのキー（32バイト）を使用しています。
    /// </summary>
    public static readonly int KeySize = 32;

    //public static readonly int TagSize = 16;

    private readonly string[] _passwords;
    private readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;

    public AesGcmEncryption(string[] passwords, HashAlgorithmName hashAlgorithm = default)
    {
        _passwords = passwords;
        _hashAlgorithm = ValidateHashAlgorithm(hashAlgorithm);
    }

    public string Encrypt(string plainText)
    {
        byte[] salt = EncryptionUtility.GenerateSalt(SaltSize);

        // IV (Nonce, 12バイト: 96ビット)
        byte[] iv = EncryptionUtility.GenerateIV(IvSize);

        byte[] key = DeriveKey(_passwords[0], salt, _hashAlgorithm);

        byte[] encryptedData = EncryptAesGcm(plainText, key, iv, out byte[] tag);

        return Convert.ToBase64String(CombineData(salt, iv, encryptedData, tag));
    }

    public string Decrypt(string cipherTextWithMac)
    {
        byte[] combinedData = Convert.FromBase64String(cipherTextWithMac);
        byte[] salt = ExtractSalt(combinedData);
        byte[] iv = ExtractIv(combinedData);
        byte[] encryptedData = ExtractEncryptedData(combinedData);
        byte[] tag = ExtractTag(combinedData);

        string decryptedText = DecryptAesGcm(encryptedData, DeriveKey(_passwords[0], salt, _hashAlgorithm), iv, tag);
        return decryptedText;
    }

    private static byte[] EncryptAesGcm(string plainText, byte[] key, byte[] iv, out byte[] tag)
    {
#if NET6_0
        using var aesGcm = new AesGcm(key);
#elif NET7_0
        using var aesGcm = new AesGcm(key);
#else
        using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
#endif


        // 暗号化するデータ
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

        // 暗号化されたデータの格納先
        byte[] cipherBytes = new byte[plainBytes.Length];

        // 認証タグ (16バイト: 128ビット)
        tag = new byte[AesGcm.TagByteSizes.MaxSize];

        aesGcm.Encrypt(iv, plainBytes, cipherBytes, tag);
        return cipherBytes;
    }

    private static string DecryptAesGcm(byte[] cipherBytes, byte[] key, byte[] iv, byte[] tag)
    {
#if NET6_0
        using var aesGcm = new AesGcm(key);
#elif NET7_0
        using var aesGcm = new AesGcm(key);
#else
        using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
#endif

        byte[] plainBytes = new byte[cipherBytes.Length];
        aesGcm.Decrypt(iv, cipherBytes, tag, plainBytes);
        return Encoding.UTF8.GetString(plainBytes);
    }

    /// <summary>
    /// ハッシュアルゴリズムの有効性を検証し、サポートされていない場合は例外をスローします。
    /// </summary>
    /// <param name="hashAlgorithm">検証するハッシュアルゴリズム。</param>
    /// <returns>有効なハッシュアルゴリズム。</returns>
    /// <exception cref="ArgumentException">サポートされていないハッシュアルゴリズムが指定された場合。</exception>
    private static HashAlgorithmName ValidateHashAlgorithm(HashAlgorithmName hashAlgorithm)
    {
        // デフォルト値の設定
        hashAlgorithm = hashAlgorithm == default ? HashAlgorithmName.SHA256 : hashAlgorithm;

        // 許可されたハッシュアルゴリズムのチェック
        if (AllowedHashAlgorithms.Contains(hashAlgorithm))
        {
            return hashAlgorithm;
        }

        // サポートされていないハッシュアルゴリズムの場合は例外をスロー
        throw new ArgumentException($"Unsupported HashAlgorithmName. Only SHA256 and SHA512 are supported. Provided: {hashAlgorithm.Name}");
    }

    /// <summary>
    /// PBKDF2を使用してキーを導出します。
    /// </summary>
    /// <param name="password">キー導出に使用するパスワード。</param>
    /// <param name="salt">キー導出に使用するソルト。</param>
    /// <param name="hashAlgorithm">ハッシュアルゴリズム。</param>
    /// <returns>導出されたキー。</returns>
    private static byte[] DeriveKey(string password, byte[] salt, HashAlgorithmName hashAlgorithm)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, IterationCount, hashAlgorithm, KeySize);
    }

    private static byte[] CombineData(byte[] salt, byte[] iv, byte[] encryptedData, byte[] tag)
    {
        byte[] result = new byte[salt.Length + iv.Length + encryptedData.Length + tag.Length];

        // Salt
        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);

        // IV
        Buffer.BlockCopy(iv, 0, result, salt.Length, iv.Length);

        // Data
        Buffer.BlockCopy(encryptedData, 0, result, salt.Length + iv.Length, encryptedData.Length);

        // authentication tag
        Buffer.BlockCopy(tag, 0, result, salt.Length + iv.Length + encryptedData.Length, tag.Length);

        return result;
    }

    /// <summary>
    /// 結合されたバイト配列からソルトを抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたバイト配列。</param>
    /// <returns>抽出されたソルト。</returns>
    private static byte[] ExtractSalt(byte[] combinedData)
    {
        byte[] salt = new byte[SaltSize];
        Buffer.BlockCopy(combinedData, 0, salt, 0, SaltSize);
        return salt;
    }

    /// <summary>
    /// 結合されたバイト配列から初期化ベクター（IV）を抽出します。
    /// </summary>
    /// <param name="combinedData">結合されたバイト配列。</param>
    /// <returns>抽出されたIV。</returns>
    private static byte[] ExtractIv(byte[] combinedData)
    {
        byte[] iv = new byte[IvSize];
        Buffer.BlockCopy(combinedData, SaltSize, iv, 0, IvSize);
        return iv;
    }

    private static byte[] ExtractEncryptedData(byte[] combinedData)
    {
        int offset = SaltSize + IvSize;
        int encryptedDataLength = combinedData.Length - offset - AesGcm.TagByteSizes.MaxSize;
        return combinedData.Skip(offset).Take(encryptedDataLength).ToArray();
    }

    private static byte[] ExtractTag(byte[] combinedData)
    {
        byte[] mac = new byte[AesGcm.TagByteSizes.MaxSize];
        Buffer.BlockCopy(combinedData, combinedData.Length - AesGcm.TagByteSizes.MaxSize, mac, 0, AesGcm.TagByteSizes.MaxSize);
        return mac;
    }
}
