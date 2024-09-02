using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using Cryptography.NET; // ここで実際の名前空間に合わせて変更

namespace Cryptography.NET.Tests;

[TestClass]
public class RsaAesEncryptionHelperTests
{
    private RSAParameters _publicKey;
    private RSAParameters _privateKey;

    [TestInitialize]
    public void Setup()
    {
        // RSA鍵ペアを生成
        (_publicKey, _privateKey) = RsaAesEncryptionHelper.GenerateRsaKeyPair();
    }

    [TestMethod]
    public void TestEncryptDecrypt()
    {
        // テスト用の平文
        string plainText = "Hello, World!";

        // 暗号化
        string encryptedText = RsaAesEncryptionHelper.Encrypt(plainText, _publicKey);

        // 復号化
        string decryptedText = RsaAesEncryptionHelper.Decrypt(encryptedText, _privateKey);

        // 結果の確認
        Assert.AreEqual(plainText, decryptedText, "復号化されたテキストが元の平文と一致しません。");
    }

    [TestMethod]
    public void TestGenerateRsaKeyPair()
    {
        // 鍵ペアの生成
        var (publicKey, privateKey) = RsaAesEncryptionHelper.GenerateRsaKeyPair();

        // 鍵のチェック
        Assert.IsNotNull(publicKey.Modulus, "公開鍵のモジュラスがnullです。");
        Assert.IsNotNull(publicKey.Exponent, "公開鍵の指数がnullです。");
        Assert.IsNotNull(privateKey.Modulus, "秘密鍵のモジュラスがnullです。");
        Assert.IsNotNull(privateKey.D, "秘密鍵のDがnullです。");
    }
}
