using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.KeyDerivation;

public class PBKDF2KeyDerivation : IKeyDerivationFunction
{
    private readonly int _iterations;

    public PBKDF2KeyDerivation(int iterations = 10000)
    {
        _iterations = iterations;
    }

    public byte[] DeriveKey(string password, byte[] salt, int keyLength)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, _iterations, HashAlgorithmName.SHA256, keyLength);
    }
}
