using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET;

internal static class AnagramHelper
{
    /// <summary>
    /// 文字列をアナグラム処理により変換します（前半と後半を入れ替え）。
    /// </summary>
    /// <param name="input">処理対象の文字列。</param>
    /// <returns>アナグラム処理後の文字列。</returns>
    public static string AnagramSwap(string input)
    {
        ArgumentNullException.ThrowIfNull(input, "入力文字列はnullであってはなりません。");

        // 文字列が1文字以下の場合、アナグラム処理は不要
        if (input.Length < 2) { return input; }

        int mid = input.Length / 2;
        return string.Concat(input.AsSpan(mid), input.AsSpan(0, mid));
    }

    /// <summary>
    /// 前半と後半の入れ替えを元に戻します。
    /// </summary>
    /// <param name="input">アナグラム処理された文字列。</param>
    /// <returns>元の文字列。</returns>
    public static string AnagramRestore(string input) => AnagramSwap(input);
}

