using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Krypt.Encryption;

/// <summary>
/// AES-256-CBC encryption and decryption utilities.
/// The IV is prepended to the cipher output (16 bytes) and stripped on decryption.
/// Keys are derived via SHA-256 so any string length is accepted.
/// </summary>
public static class KryptAes
{
    // ─────────────────────────────────────────────
    //  String helpers (base-64 output, UTF-8 text)
    // ─────────────────────────────────────────────

    /// <summary>Encrypts a UTF-8 string and returns a Base-64 cipher string.</summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="key">Passphrase; derived to a 256-bit key via SHA-256.</param>
    /// <exception cref="ArgumentNullException"/>
    public static string Encrypt(string plainText, string key)
    {
        ArgumentNullException.ThrowIfNull(plainText, nameof(plainText));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        byte[] cipher = Encrypt(Encoding.UTF8.GetBytes(plainText), key);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>Decrypts a Base-64 cipher string and returns the original UTF-8 text.</summary>
    /// <param name="cipherText">Base-64 encoded cipher produced by <see cref="Encrypt(string,string)"/>.</param>
    /// <param name="key">The same passphrase used during encryption.</param>
    /// <exception cref="ArgumentNullException"/>
    /// <exception cref="FormatException">Thrown when <paramref name="cipherText"/> is not valid Base-64.</exception>
    /// <exception cref="CryptographicException">Thrown on wrong key or tampered data.</exception>
    public static string Decrypt(string cipherText, string key)
    {
        ArgumentNullException.ThrowIfNull(cipherText, nameof(cipherText));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        byte[] plain = Decrypt(Convert.FromBase64String(cipherText), key);
        return Encoding.UTF8.GetString(plain);
    }

    // ─────────────────────────────────────────────
    //  Byte-array helpers
    // ─────────────────────────────────────────────

    /// <summary>Encrypts raw bytes. The returned array is <c>IV (16 bytes) + cipher bytes</c>.</summary>
    public static byte[] Encrypt(byte[] plainBytes, string key)
    {
        ArgumentNullException.ThrowIfNull(plainBytes, nameof(plainBytes));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        using Aes aes = CreateAes(key);
        aes.GenerateIV();

        using ICryptoTransform encryptor = aes.CreateEncryptor();
        using MemoryStream ms = new();

        ms.Write(aes.IV, 0, aes.IV.Length); // prepend IV

        using (CryptoStream cs = new(ms, encryptor, CryptoStreamMode.Write))
            cs.Write(plainBytes, 0, plainBytes.Length);
        // CryptoStream.Dispose() flushes the final block automatically

        return ms.ToArray();
    }

    /// <summary>Decrypts a byte array produced by <see cref="Encrypt(byte[],string)"/>.</summary>
    public static byte[] Decrypt(byte[] cipherBytes, string key)
    {
        ArgumentNullException.ThrowIfNull(cipherBytes, nameof(cipherBytes));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        const int ivLength = 16;
        if (cipherBytes.Length < ivLength + 1)
            throw new ArgumentException(
                $"Cipher is too short (minimum {ivLength + 1} bytes).", nameof(cipherBytes));

        byte[] iv = cipherBytes[..ivLength];

        using Aes aes = CreateAes(key);
        aes.IV = iv;

        using ICryptoTransform decryptor = aes.CreateDecryptor();
        using MemoryStream ms = new(cipherBytes, ivLength, cipherBytes.Length - ivLength);
        using CryptoStream cs = new(ms, decryptor, CryptoStreamMode.Read);
        using MemoryStream result = new();

        cs.CopyTo(result);
        return result.ToArray();
    }

    // ─────────────────────────────────────────────
    //  Stream helpers (large payloads / files)
    // ─────────────────────────────────────────────

    /// <summary>
    /// Encrypts data from <paramref name="source"/> and writes IV + cipher to <paramref name="destination"/>.
    /// Both streams must be open and positioned correctly by the caller.
    /// </summary>
    public static void Encrypt(Stream source, Stream destination, string key)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));
        ArgumentNullException.ThrowIfNull(destination, nameof(destination));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        using Aes aes = CreateAes(key);
        aes.GenerateIV();

        destination.Write(aes.IV, 0, aes.IV.Length);

        using ICryptoTransform encryptor = aes.CreateEncryptor();
        using CryptoStream cs = new(destination, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        source.CopyTo(cs);
    }

    /// <summary>
    /// Decrypts data from <paramref name="source"/> (IV + cipher) and writes plain bytes to
    /// <paramref name="destination"/>.
    /// </summary>
    public static void Decrypt(Stream source, Stream destination, string key)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));
        ArgumentNullException.ThrowIfNull(destination, nameof(destination));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        const int ivLength = 16;
        byte[] iv = new byte[ivLength];
        int read = source.ReadAtLeast(iv, ivLength, throwOnEndOfStream: false);
        if (read < ivLength)
            throw new ArgumentException("Stream is too short to contain a valid IV.", nameof(source));

        using Aes aes = CreateAes(key);
        aes.IV = iv;

        using ICryptoTransform decryptor = aes.CreateDecryptor();
        using CryptoStream cs = new(source, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        cs.CopyTo(destination);
    }

    // ─────────────────────────────────────────────
    //  Async variants (stream overloads)
    // ─────────────────────────────────────────────

    /// <inheritdoc cref="Encrypt(Stream,Stream,string)"/>
    public static async Task EncryptAsync(
        Stream source, Stream destination, string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));
        ArgumentNullException.ThrowIfNull(destination, nameof(destination));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        using Aes aes = CreateAes(key);
        aes.GenerateIV();

        await destination.WriteAsync(aes.IV, cancellationToken).ConfigureAwait(false);

        using ICryptoTransform encryptor = aes.CreateEncryptor();
        await using CryptoStream cs = new(destination, encryptor, CryptoStreamMode.Write, leaveOpen: true);
        await source.CopyToAsync(cs, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc cref="Decrypt(Stream,Stream,string)"/>
    public static async Task DecryptAsync(
        Stream source, Stream destination, string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));
        ArgumentNullException.ThrowIfNull(destination, nameof(destination));
        ArgumentNullException.ThrowIfNull(key, nameof(key));

        const int ivLength = 16;
        byte[] iv = new byte[ivLength];
        int total = 0;
        while (total < ivLength)
        {
            int r = await source.ReadAsync(iv.AsMemory(total, ivLength - total), cancellationToken)
                                .ConfigureAwait(false);
            if (r == 0) break;
            total += r;
        }
        if (total < ivLength)
            throw new ArgumentException("Stream is too short to contain a valid IV.", nameof(source));

        using Aes aes = CreateAes(key);
        aes.IV = iv;

        using ICryptoTransform decryptor = aes.CreateDecryptor();
        await using CryptoStream cs = new(source, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        await cs.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
    }

    // ─────────────────────────────────────────────
    //  Private helpers
    // ─────────────────────────────────────────────

    /// <summary>
    /// Creates an AES instance with explicit CBC mode and PKCS7 padding.
    /// Key is derived from the passphrase via SHA-256 (256-bit output).
    /// </summary>
    private static Aes CreateAes(string key)
    {
        Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = DeriveKey(key);
        return aes;
    }

    /// <summary>Derives a 256-bit AES key from an arbitrary passphrase using SHA-256.</summary>
    private static byte[] DeriveKey(string key)
    {
        using SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
    }
}