using System.Security.Cryptography;
using Cryptography.NET.Algorithm;

namespace Cryptography.NET.Tests;

[TestClass]
public class AesGcmEncryptionHelperTests
{
    //private readonly string[] passwordsMultiple = { "secure_password_1", "secure_password_2", "secure_password_3", "secure_password_4" };
    //private readonly string[] passwordsSingle = { "secure_password_1" };
    //private readonly string hmacKey = "my_hmac_key";

    /// <summary>
    /// 暗号化および復号化が元のテキストを正しく戻すことを確認するテスト。
    /// テストケースは、単一のパスワードと複数のパスワードに対するHMACの有無である。
    /// </summary>
    /// <param name="passwordList">カンマ区切りのパスワードリスト。</param>
    /// <param name="hmacKey">HMACキー（空白の場合もある）。</param>
    [TestMethod]
    [DataRow("secure_password_1", "my_hmac_key", DisplayName = "Single Password with HMAC")]
    [DataRow("secure_password_1", "", DisplayName = "Single Password with Empty HMAC")]
    [DataRow("secure_password_1;secure_password_2;secure_password_3;secure_password_4", "my_hmac_key", DisplayName = "Multiple Passwords with HMAC")]
    [DataRow("secure_password_1;secure_password_2;secure_password_3;secure_password_4", "", DisplayName = "Multiple Passwords with Empty HMAC")]
    public void Encrypt_Decrypt_ShouldReturnOriginalText(string passwordList, string hmacKey)
    {
        // Arrange
        string originalText = "This is a secret message!";
        string[] passwords = passwordList.Split(';');

        // Act
        string encryptedTextSha256 = EncryptionAlgorithm.Encrypt(originalText, passwords, hmacKey, HashAlgorithmName.SHA256, Common.EncryptionSettings.EncryptionAlgorithm.AesGcm);
        string decryptedTextSha256 = EncryptionAlgorithm.Decrypt(encryptedTextSha256, passwords, hmacKey, HashAlgorithmName.SHA256, Common.EncryptionSettings.EncryptionAlgorithm.AesGcm);
        Assert.AreEqual(originalText, decryptedTextSha256, "Decrypted text should match the original plain text when using SHA256.");
    }
}