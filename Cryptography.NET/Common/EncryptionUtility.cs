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
}
