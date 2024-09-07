using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.Common;

public static class EncryptionUtility
{
    /// <summary>
    /// 指定されたサイズのソルトを生成します。
    /// </summary>
    /// <param name="size">ソルトのサイズ（バイト単位）。</param>
    /// <returns>生成されたソルト。</returns>
    public static byte[] GenerateSalt(int size)
    {
        return RandomNumberGenerator.GetBytes(size);
    }

    /// <summary>
    /// 指定されたサイズの初期化ベクター（IV）を生成します。
    /// </summary>
    /// <param name="size">IVのサイズ（バイト単位）。</param>
    /// <returns>生成されたIV。</returns>
    public static byte[] GenerateIV(int size)
    {
        return RandomNumberGenerator.GetBytes(size);
    }

    static byte[] DeriveKey(string password, byte[] salt)
    {
        // Argon2を使用してキーを派生
        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 8, // 並列度
            MemorySize = 65536, // メモリ使用量 (KB)
            Iterations = 4 // 繰り返し回数
        };

        return argon2.GetBytes(32); // 32バイトのキーを生成
    }
}
