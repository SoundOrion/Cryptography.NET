using Cryptography.NET.Helper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET;

public class EncryptionAlgorithmFactory
{
    public static IEncryptionAlgorithm GetEncryptionAlgorithm(
        EncryptionSettings.EncryptionAlgorithm algorithm,
        string[] passwords,
        string hmacKey,
        HashAlgorithmName hashAlgorithm = default)
    {
        return algorithm switch
        {
            EncryptionSettings.EncryptionAlgorithm.AesCbc => new AesCbcEncryption(passwords, hmacKey, hashAlgorithm),
            //EncryptionSettings.EncryptionAlgorithm.AesGcm => new AesGcmEncryption(),
            _ => throw new NotSupportedException("指定された暗号化アルゴリズムはサポートされていません。"),
        };
    }
}

