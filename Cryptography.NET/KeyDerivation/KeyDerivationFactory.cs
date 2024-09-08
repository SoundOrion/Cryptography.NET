using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.KeyDerivation;

public enum KeyDerivationAlgorithm
{
    Argon2id,
    PBKDF2,
    Scrypt
}

public class KeyDerivationFactory
{
    public static IKeyDerivationFunction Create(KeyDerivationAlgorithm algorithm, params object[] parameters)
    {
        return algorithm switch
        {
            KeyDerivationAlgorithm.Argon2id => new Argon2KeyDerivation((int)parameters[0], (int)parameters[1], (int)parameters[2]),
            KeyDerivationAlgorithm.PBKDF2 => new PBKDF2KeyDerivation((int)parameters[0]),
            KeyDerivationAlgorithm.Scrypt => new ScryptKeyDerivation((int)parameters[0], (int)parameters[1], (int)parameters[2]),
            _ => throw new NotSupportedException("Unsupported key derivation algorithm."),
        };
    }
}
