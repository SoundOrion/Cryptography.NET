using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET;

public static class EncryptionSettings
{
    public enum EncryptionAlgorithm
    {
        AesCbc,
        AesGcm
    }

    /// <summary>
    /// サポートされているハッシュアルゴリズム。
    /// </summary>
    public static readonly HashAlgorithmName[] AllowedHashAlgorithms = { HashAlgorithmName.SHA256, HashAlgorithmName.SHA512 };

    /// <summary>
    /// PBKDF2の繰り返し回数。
    /// </summary>
    public static readonly int IterationCount = 10000;

    /// <summary>
    /// 暗号化に使用するソルトのサイズ（バイト単位）。
    /// 通常、16バイトのソルトを使用して暗号化キーを強化します。
    /// </summary>
    public static readonly int SaltSize = 16;

    /// <summary>
    /// AES暗号化に使用する初期化ベクター（IV）のサイズ（バイト単位）。
    /// AES-128およびAES-256の標準的なIVサイズは16バイトです。
    /// </summary>
    public static readonly int IvSize = 16;

    /// <summary>
    /// AES暗号化で使用するキーのサイズ（バイト単位）。
    /// ここでは256ビットのキー（32バイト）を使用しています。
    /// </summary>
    public static readonly int KeySize = 32;

    /// <summary>
    /// HMAC-SHA256のメッセージ認証コード（MAC）のサイズ（バイト単位）。
    /// HMAC-SHA256は256ビット（32バイト）のMACを生成します。
    /// </summary>
    public static readonly int HmacSha256Size = 32;

    /// <summary>
    /// HMAC-SHA512のメッセージ認証コード（MAC）のサイズ（バイト単位）。
    /// HMAC-SHA512は512ビット（64バイト）のMACを生成します。
    /// </summary>
    public static readonly int HmacSha512Size = 64;
}
