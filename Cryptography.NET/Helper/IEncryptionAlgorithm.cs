using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.Helper;

public interface IEncryptionAlgorithm
{
    string Encrypt(string plainText);
    string Decrypt(string cipherTextWithMac);
}

