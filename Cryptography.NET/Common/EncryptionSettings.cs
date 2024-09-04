using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.Common;

public static class EncryptionSettings
{
    public enum EncryptionAlgorithm
    {
        AesCbc,
        AesGcm
    }
}
