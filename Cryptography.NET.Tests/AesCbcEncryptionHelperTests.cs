using System.Security.Cryptography;
using Cryptography.NET.Algorithm;

namespace Cryptography.NET.Tests;

[TestClass]
public class AesCbcEncryptionHelperTests
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

        // SHA256
        string encryptedTextSha256 = EncryptionAlgorithm.Encrypt(originalText, passwords, hmacKey, HashAlgorithmName.SHA256);
        string decryptedTextSha256 = EncryptionAlgorithm.Decrypt(encryptedTextSha256, passwords, hmacKey, HashAlgorithmName.SHA256);
        Assert.AreEqual(originalText, decryptedTextSha256, "Decrypted text should match the original plain text when using SHA256.");

        // SHA512
        string encryptedTextSha512 = EncryptionAlgorithm.Encrypt(originalText, passwords, hmacKey, HashAlgorithmName.SHA512);
        string decryptedTextSha512 = EncryptionAlgorithm.Decrypt(encryptedTextSha512, passwords, hmacKey, HashAlgorithmName.SHA512);
        Assert.AreEqual(originalText, decryptedTextSha512, "Decrypted text should match the original plain text when using SHA512.");
    }

    /// <summary>
    /// 不正なHMACキーが提供された場合にCryptographicExceptionがスローされることを確認するテスト。
    /// </summary>
    [TestMethod]
    [ExpectedException(typeof(CryptographicException))]
    public void Decrypt_InvalidHmac_ShouldThrowCryptographicException()
    {
        // Arrange
        string originalText = "This is a secret message!";
        string[] passwords = { "password1", "password2" };
        string hmacKey = "hmacKey";

        // 正しいデータを暗号化
        string encryptedText = EncryptionAlgorithm.Encrypt(originalText, passwords, hmacKey);
        Assert.IsNotNull(encryptedText, "Encrypted text should not be null.");

        // 暗号化データを変更して復号化しようとする
        byte[] tamperedData = Convert.FromBase64String(encryptedText);
        tamperedData[10] ^= 0xff; // 一部のデータを変更する
        string tamperedEncryptedText = Convert.ToBase64String(tamperedData);

        // 復号化を試みるが、CryptographicExceptionが発生するはず
        EncryptionAlgorithm.Decrypt(tamperedEncryptedText, passwords, hmacKey);
    }

    /// <summary>
    /// SHA256またはSHA512以外のハッシュアルゴリズムが指定された場合にArgumentExceptionがスローされることを確認するテスト。
    /// </summary>
    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Encrypt_WithUnsupportedHashAlgorithm_ShouldThrowArgumentException()
    {
        // Arrange
        string originalText = "This is a secret message!";
        string[] passwords = { "password1" };
        string hmacKey = "hmacKey";
        var unsupportedAlgorithm = new HashAlgorithmName("MD5"); // MD5は許可されていない

        // Act
        EncryptionAlgorithm.Encrypt(originalText, passwords, hmacKey, unsupportedAlgorithm);
    }

    /// <summary>
    /// SHA256またはSHA512以外のハッシュアルゴリズムが指定された場合にArgumentExceptionがスローされることを確認するテスト。
    /// </summary>
    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Decrypt_WithUnsupportedHashAlgorithm_ShouldThrowArgumentException()
    {
        // Arrange
        string encryptedText = "This is a secret message!";
        string[] passwords = { "password1" };
        string hmacKey = "hmacKey";
        var unsupportedAlgorithm = new HashAlgorithmName("MD5"); // MD5は許可されていない

        // Act
        EncryptionAlgorithm.Decrypt(encryptedText, passwords, hmacKey, unsupportedAlgorithm);
    }
}