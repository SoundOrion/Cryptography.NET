using System.Security.Cryptography;
using Cryptography.NET.Helper;
using Cryptography.NET.Common;

namespace Cryptography.NET.Algorithm;

/// <summary>
/// 様々な暗号化アルゴリズムを使用して暗号化および復号化を提供するクラスです。
/// </summary>
public static class EncryptionAlgorithm
{
    /// <summary>
    /// 指定された暗号化アルゴリズムを使用して、指定したプレーンテキストを暗号化します。
    /// </summary>
    /// <param name="plainText">暗号化するテキスト。</param>
    /// <param name="passwords">暗号化キーの派生に使用するパスワードの配列。</param>
    /// <param name="hmacKey">メッセージ認証に使用するHMACキー。</param>
    /// <param name="hashAlgorithm">キー派生に使用するハッシュアルゴリズム。指定しない場合はプラットフォームのデフォルトが使用されます。</param>
    /// <param name="algorithm">使用する暗号化アルゴリズム。デフォルトはAES-CBCです。</param>
    /// <returns>暗号化されたデータとHMACが付加された文字列。</returns>
    /// <exception cref="ArgumentNullException">plainText、passwords、またはhmacKeyがnullの場合にスローされます。</exception>
    /// <exception cref="CryptographicException">暗号化に失敗した場合にスローされます。</exception>
    public static string Encrypt(string plainText, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default, EncryptionSettings.EncryptionAlgorithm algorithm = EncryptionSettings.EncryptionAlgorithm.AesCbc)
    {
        IEncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithmFactory.GetEncryptionAlgorithm(algorithm, passwords, hmacKey, hashAlgorithm);
        return encryptionAlgorithm.Encrypt(plainText);
    }

    /// <summary>
    /// 与えられた暗号化テキスト（シファーテキスト）を復号化し、HMACを使用して整合性を確認します。
    /// </summary>
    /// <param name="cipherTextWithMac">暗号化されたデータと整合性確認のためのHMAC。</param>
    /// <param name="passwords">暗号化キーの派生に使用するパスワードの配列。</param>
    /// <param name="hmacKey">メッセージの整合性確認に使用するHMACキー。</param>
    /// <param name="hashAlgorithm">キー派生に使用するハッシュアルゴリズム。指定しない場合はプラットフォームのデフォルトが使用されます。</param>
    /// <param name="algorithm">使用する暗号化アルゴリズム。デフォルトはAES-CBCです。</param>
    /// <returns>復号化されたプレーンテキストの文字列。</returns>
    /// <exception cref="ArgumentNullException">cipherTextWithMac、passwords、またはhmacKeyがnullの場合にスローされます。</exception>
    /// <exception cref="CryptographicException">復号化またはHMAC検証に失敗した場合にスローされます。</exception>
    public static string Decrypt(string cipherTextWithMac, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default, EncryptionSettings.EncryptionAlgorithm algorithm = EncryptionSettings.EncryptionAlgorithm.AesCbc)
    {
        IEncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithmFactory.GetEncryptionAlgorithm(algorithm, passwords, hmacKey, hashAlgorithm);
        return encryptionAlgorithm.Decrypt(cipherTextWithMac);
    }
}
