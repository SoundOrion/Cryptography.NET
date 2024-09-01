using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography.NET;

internal static class HmacHelper
{
    /// <summary>
    /// 指定されたデータに対してHMACを生成します。
    /// </summary>
    /// <param name="data">HMACを生成するためのデータ。</param>
    /// <param name="hmacKey">HMACのキー。</param>
    /// <param name="algorithm">HMACのアルゴリズム（SHA256またはSHA512）。</param>
    /// <returns>生成されたHMACのバイト配列。</returns>
    public static byte[] GenerateHmac(byte[] data, string hmacKey, HashAlgorithmName hashAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(hmacKey))
        {
            return Array.Empty<byte>();
        }

        using var hmac = CreateHmacAlgorithm(hashAlgorithm, hmacKey);
        return hmac.ComputeHash(data);
    }

    /// <summary>
    /// 指定されたデータのMAC（メッセージ認証コード）を検証します。
    /// </summary>
    /// <param name="data">MAC検証の対象となるデータ。</param>
    /// <param name="mac">検証するMAC。</param>
    /// <param name="hmacKey">HMACのキー。</param>
    /// <param name="algorithm">HMACのアルゴリズム（SHA256またはSHA512）。</param>
    /// <returns>MACが一致する場合はtrue、それ以外はfalse。</returns>
    public static bool VerifyHmac(byte[] data, byte[] mac, string hmacKey, HashAlgorithmName hashAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(hmacKey))
        {
            return mac.Length == 0;
        }

        using var hmac = CreateHmacAlgorithm(hashAlgorithm, hmacKey);
        byte[] computedMac = hmac.ComputeHash(data);
        return CryptographicOperations.FixedTimeEquals(computedMac, mac);
    }

    /// <summary>
    /// 指定されたアルゴリズムに基づいてHMACアルゴリズムを生成します。
    /// </summary>
    /// <param name="algorithm">HMACのアルゴリズム（SHA256またはSHA512）。</param>
    /// <param name="key">HMACのキー。</param>
    /// <returns>HMACアルゴリズムのインスタンス。</returns>
    /// <exception cref="ArgumentException">無効なアルゴリズムが指定された場合。</exception>
    private static HMAC CreateHmacAlgorithm(HashAlgorithmName hashAlgorithm, string key)
    {
        return hashAlgorithm.ToString().ToUpper() switch
        {
            "SHA256" => new HMACSHA256(Encoding.UTF8.GetBytes(key)),
            "SHA512" => new HMACSHA512(Encoding.UTF8.GetBytes(key)),
            _ => throw new ArgumentException("Unsupported HMAC algorithm specified.")
        };
    }
}

