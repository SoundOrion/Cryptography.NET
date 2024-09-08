using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.KeyDerivation;

public interface IKeyDerivationFunction
{
    byte[] DeriveKey(string password, byte[] salt, int keyLength);
}
