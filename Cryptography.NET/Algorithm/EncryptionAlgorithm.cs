using System.Security.Cryptography;
using Cryptography.NET.Helper;

namespace Cryptography.NET.Algorithm;

public static class EncryptionAlgorithm
{
    public static string Encrypt(string plainText, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default, EncryptionSettings.EncryptionAlgorithm algorithm = EncryptionSettings.EncryptionAlgorithm.AesCbc)
    {
        IEncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithmFactory.GetEncryptionAlgorithm(algorithm, passwords, hmacKey, hashAlgorithm);
        return encryptionAlgorithm.Encrypt(plainText);
    }

    public static string Decrypt(string cipherTextWithMac, string[] passwords, string hmacKey, HashAlgorithmName hashAlgorithm = default, EncryptionSettings.EncryptionAlgorithm algorithm = EncryptionSettings.EncryptionAlgorithm.AesCbc)
    {
        IEncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithmFactory.GetEncryptionAlgorithm(algorithm, passwords, hmacKey, hashAlgorithm);
        return encryptionAlgorithm.Decrypt(cipherTextWithMac);
    }
}
