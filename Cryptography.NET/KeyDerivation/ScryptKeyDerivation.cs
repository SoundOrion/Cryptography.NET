using Scrypt;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.KeyDerivation;

//public class ScryptKeyDerivation : IKeyDerivationFunction
//{
//    private readonly int _n; // CPU/メモリコストパラメータ
//    private readonly int _r; // ブロックサイズパラメータ
//    private readonly int _p; // 並列度パラメータ

//    public ScryptKeyDerivation(int n = 16384, int r = 8, int p = 1)
//    {
//        _n = n;  // CPU/メモリコスト
//        _r = r;  // ブロックサイズ
//        _p = p;  // 並列度
//    }

//    public byte[] DeriveKey(string password, byte[] salt, int keyLength)
//    {
//        if (string.IsNullOrWhiteSpace(password))
//            throw new ArgumentException("Password cannot be empty or null.");
//        if (salt == null || salt.Length == 0)
//            throw new ArgumentException("Salt cannot be empty or null.");
//        if (keyLength <= 0)
//            throw new ArgumentException("Key length must be greater than zero.");

//        // Scrypt.NETを使用してキーを導出
//        var encoder = new ScryptEncoder();
//        return ScryptUtil.ComputeDerivedKey(
//            password: password,
//            salt: salt,
//            n: _n,
//            r: _r,
//            p: _p,
//            dkLen: keyLength);
//    }
//}

public class ScryptKeyDerivation : IKeyDerivationFunction
{
    private readonly int _n;
    private readonly int _r;
    private readonly int _p;

    public ScryptKeyDerivation(int n = 16384, int r = 8, int p = 1)
    {
        _n = n;
        _r = r;
        _p = p;
    }

    public byte[] DeriveKey(string password, byte[] salt, int keyLength)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty or null.");
        if (salt == null || salt.Length == 0)
            throw new ArgumentException("Salt cannot be empty or null.");
        if (keyLength <= 0)
            throw new ArgumentException("Key length must be greater than zero.");

        using var scrypt = new Rfc2898DeriveBytes(password, salt, _n, HashAlgorithmName.SHA256);
        return scrypt.GetBytes(keyLength);
    }
}