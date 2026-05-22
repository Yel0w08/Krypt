using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Krypt.Encryption;

public static class KryptAes
{
    public static string Encrypt(string plainText, string key)
    {
        using Aes aes = Aes.Create();

        aes.Key = GetKey(key);
        aes.GenerateIV();

        using ICryptoTransform encryptor = aes.CreateEncryptor();
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] encryptedBytes;

        using (MemoryStream ms = new())
        {
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (CryptoStream cs = new(ms, encryptor, CryptoStreamMode.Write))
            {
                cs.Write(plainBytes, 0, plainBytes.Length);
            }

            encryptedBytes = ms.ToArray();
        }

        return Convert.ToBase64String(encryptedBytes);
    }

    public static string Decrypt(string cipherText, string key)
    {
        byte[] fullCipher = Convert.FromBase64String(cipherText);

        using Aes aes = Aes.Create();
        aes.Key = GetKey(key);

        byte[] iv = new byte[16];
        Array.Copy(fullCipher, 0, iv, 0, iv.Length);
        aes.IV = iv;

        using ICryptoTransform decryptor = aes.CreateDecryptor();
        using MemoryStream ms = new(fullCipher, 16, fullCipher.Length - 16);
        using CryptoStream cs = new(ms, decryptor, CryptoStreamMode.Read);

        using StreamReader reader = new(cs);

        return reader.ReadToEnd();
    }

    private static byte[] GetKey(string key)
    {
        using SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
    }
}