using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.KeyDerivation;

public class Argon2KeyDerivation : IKeyDerivationFunction
{
    private readonly int _memorySize;
    private readonly int _iterations;
    private readonly int _parallelism;

    public Argon2KeyDerivation(int memorySize = 65536, int iterations = 3, int parallelism = 2)
    {
        _memorySize = memorySize;
        _iterations = iterations;
        _parallelism = parallelism;
    }

    public byte[] DeriveKey(string password, byte[] salt, int keyLength)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty or null.");
        if (salt == null || salt.Length == 0)
            throw new ArgumentException("Salt cannot be empty or null.");
        if (keyLength <= 0)
            throw new ArgumentException("Key length must be greater than zero.");

        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = _memorySize,
            Iterations = _iterations,
            DegreeOfParallelism = _parallelism
        };

        return argon2.GetBytes(keyLength);
    }
}
