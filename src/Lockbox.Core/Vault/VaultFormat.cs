using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Lockbox.Core.Crypto;

namespace Lockbox.Core.Vault;

[Flags]
public enum VaultFlags : ushort
{
    None = 0,
    /// <summary>The KEK mixes in a key file as well as the master password.</summary>
    KeyFile = 1,
}

/// <summary>
/// The on-disk format: a fixed 124-byte header followed by one AES-256-GCM ciphertext.
/// </summary>
/// <remarks>
/// <code>
/// offset size
///   0     4  magic "LKBX"
///   4     2  format version (LE16) = 1
///   6     2  flags (LE16), see VaultFlags
///   8     4  Argon2id memory KiB (LE32)
///  12     4  Argon2id passes (LE32)
///  16     4  Argon2id lanes (LE32)
///  20    32  Argon2id salt
///  52    12  wrap nonce          -- AES-GCM(KEK) over the 32-byte data key,
///  64    32  wrapped data key    -- AAD = bytes 0..52
///  96    16  wrap tag
/// 112    12  payload nonce       -- fresh on every save
/// 124     n  payload ciphertext  -- AES-GCM(data key), AAD = bytes 0..124
/// 124+n  16  payload tag
/// </code>
/// KEK = HKDF-SHA256(Argon2id(NFC(password), salt) [|| SHA-256(key file)], info "Lockbox-KEK-v1").
/// The data key is random, so saving never needs the password, and changing the password
/// rewraps a fresh data key without touching the entries' encryption scheme. Every header
/// byte is authenticated: altering a KDF parameter, a flag or the nonce makes unlocking fail.
/// The plaintext is LE32(json length) || UTF-8 JSON || zero padding to a 1 KiB multiple, so
/// the file size says little about individual entries.
/// </remarks>
public static class VaultFormat
{
    public const ushort FormatVersion = 1;
    public const int HeaderLength = 124;
    public const int KeySize = 32;
    public const int SaltSize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;

    private const int WrapAadLength = 52;
    private const int PaddingQuantum = 1024;
    private static ReadOnlySpan<byte> Magic => "LKBX"u8;
    private static readonly byte[] KekInfo = Encoding.ASCII.GetBytes("Lockbox-KEK-v1");

    /// <summary>The public part of a header: enough to know what to ask the user for.</summary>
    public readonly record struct HeaderInfo(ushort Version, VaultFlags Flags, KdfParameters Kdf)
    {
        public bool RequiresKeyFile => (Flags & VaultFlags.KeyFile) != 0;
    }

    public static HeaderInfo ReadHeader(ReadOnlySpan<byte> file)
    {
        if (file.Length < HeaderLength + TagSize || !file[..4].SequenceEqual(Magic))
            throw new VaultFormatException("Not a Lockbox vault.");
        var version = BinaryPrimitives.ReadUInt16LittleEndian(file[4..]);
        if (version != FormatVersion)
            throw new VaultFormatException($"Vault format version {version} is not supported by this build (expected {FormatVersion}).");
        var flags = (VaultFlags)BinaryPrimitives.ReadUInt16LittleEndian(file[6..]);
        if ((flags & ~VaultFlags.KeyFile) != 0)
            throw new VaultFormatException($"Vault has unknown flags 0x{(ushort)flags:x4}.");
        var kdf = new KdfParameters(
            (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(file[8..]), int.MaxValue),
            (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(file[12..]), int.MaxValue),
            (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(file[16..]), int.MaxValue));
        kdf.Validate();
        return new HeaderInfo(version, flags, kdf);
    }

    /// <summary>
    /// Derive the key-encryption key. Slow on purpose (Argon2id); everything else is fast.
    /// </summary>
    internal static byte[] DeriveKek(string password, ReadOnlySpan<byte> salt, KdfParameters kdf, byte[]? keyFileDigest)
    {
        // NFC so the same passphrase typed on macOS (which tends to produce decomposed
        // accents) and on Windows derives the same key.
        var passwordBytes = Encoding.UTF8.GetBytes(password.Normalize(NormalizationForm.FormC));
        var stretched = Argon2id.Hash(passwordBytes, salt, kdf.MemoryKiB, kdf.Passes, kdf.Lanes, KeySize);
        var ikm = new byte[stretched.Length + (keyFileDigest?.Length ?? 0)];
        try
        {
            stretched.CopyTo(ikm, 0);
            keyFileDigest?.CopyTo(ikm, stretched.Length);
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, KeySize, salt: null, info: KekInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(stretched);
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>Encrypt a document under existing keys. Fast: no password involved.</summary>
    internal static byte[] Seal(VaultKeys keys, VaultDocument document)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(document, VaultJson.Default.VaultDocument);
        var plaintextLength = ((4 + json.Length + PaddingQuantum - 1) / PaddingQuantum) * PaddingQuantum;
        var plaintext = new byte[plaintextLength];
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(plaintext, json.Length);
            json.CopyTo(plaintext, 4);

            var file = new byte[HeaderLength + plaintextLength + TagSize];
            WriteHeader(file, keys);
            var payloadNonce = file.AsSpan(112, NonceSize);
            RandomNumberGenerator.Fill(payloadNonce);

            using var aes = new AesGcm(keys.DataKey, TagSize);
            aes.Encrypt(payloadNonce, plaintext,
                file.AsSpan(HeaderLength, plaintextLength),
                file.AsSpan(HeaderLength + plaintextLength, TagSize),
                file.AsSpan(0, HeaderLength));
            return file;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Decrypt a vault. Throws <see cref="VaultUnlockException"/> for a wrong password or key
    /// file, <see cref="VaultFormatException"/> for anything structurally wrong.
    /// </summary>
    internal static (VaultKeys Keys, VaultDocument Document) Unseal(ReadOnlySpan<byte> file, string password, byte[]? keyFileDigest)
    {
        var header = ReadHeader(file);
        if (header.RequiresKeyFile && keyFileDigest is null)
            throw new VaultFormatException("This vault needs its key file as well as the master password.");
        if (!header.RequiresKeyFile && keyFileDigest is not null)
            throw new VaultFormatException("This vault does not use a key file.");

        var salt = file.Slice(20, SaltSize).ToArray();
        var kek = DeriveKek(password, salt, header.Kdf, keyFileDigest);
        var dataKey = new byte[KeySize];
        try
        {
            using var wrap = new AesGcm(kek, TagSize);
            wrap.Decrypt(file.Slice(52, NonceSize), file.Slice(64, KeySize), file.Slice(96, TagSize), dataKey, file[..WrapAadLength]);
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(dataKey);
            throw new VaultUnlockException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }

        var keys = new VaultKeys(header.Flags, header.Kdf, salt,
            file.Slice(52, NonceSize).ToArray(), file.Slice(64, KeySize).ToArray(), file.Slice(96, TagSize).ToArray(), dataKey);

        var ciphertextLength = file.Length - HeaderLength - TagSize;
        var plaintext = new byte[ciphertextLength];
        try
        {
            using var aes = new AesGcm(dataKey, TagSize);
            aes.Decrypt(file.Slice(112, NonceSize), file.Slice(HeaderLength, ciphertextLength),
                file.Slice(HeaderLength + ciphertextLength, TagSize), plaintext, file[..HeaderLength]);

            var jsonLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext);
            if (jsonLength < 0 || jsonLength > ciphertextLength - 4)
                throw new VaultFormatException("Vault payload length is out of range.");
            var document = JsonSerializer.Deserialize(plaintext.AsSpan(4, jsonLength), VaultJson.Default.VaultDocument)
                ?? throw new VaultFormatException("Vault payload is empty.");
            return (keys, document);
        }
        catch (AuthenticationTagMismatchException)
        {
            // The password was right (the wrap opened), so this is a damaged or edited file.
            keys.Dispose();
            throw new VaultFormatException("The vault unlocked but its contents failed authentication: the file is corrupted or has been modified.");
        }
        catch
        {
            keys.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static void WriteHeader(Span<byte> file, VaultKeys keys)
    {
        Magic.CopyTo(file);
        BinaryPrimitives.WriteUInt16LittleEndian(file[4..], FormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(file[6..], (ushort)keys.Flags);
        BinaryPrimitives.WriteUInt32LittleEndian(file[8..], (uint)keys.Kdf.MemoryKiB);
        BinaryPrimitives.WriteUInt32LittleEndian(file[12..], (uint)keys.Kdf.Passes);
        BinaryPrimitives.WriteUInt32LittleEndian(file[16..], (uint)keys.Kdf.Lanes);
        keys.Salt.CopyTo(file[20..]);
        keys.WrapNonce.CopyTo(file[52..]);
        keys.WrappedKey.CopyTo(file[64..]);
        keys.WrapTag.CopyTo(file[96..]);
    }

    /// <summary>The bytes the wrap is authenticated against (header up to the wrap nonce).</summary>
    internal static byte[] WrapAad(VaultFlags flags, KdfParameters kdf, ReadOnlySpan<byte> salt)
    {
        var aad = new byte[WrapAadLength];
        Magic.CopyTo(aad);
        BinaryPrimitives.WriteUInt16LittleEndian(aad.AsSpan(4), FormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(aad.AsSpan(6), (ushort)flags);
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(8), (uint)kdf.MemoryKiB);
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(12), (uint)kdf.Passes);
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(16), (uint)kdf.Lanes);
        salt.CopyTo(aad.AsSpan(20));
        return aad;
    }
}

/// <summary>
/// The key material of an open vault: the random data key (secret) and its wrapped form
/// (safe to store). Disposing zeroes the data key.
/// </summary>
internal sealed class VaultKeys(
    VaultFlags flags, KdfParameters kdf, byte[] salt, byte[] wrapNonce, byte[] wrappedKey, byte[] wrapTag, byte[] dataKey)
    : IDisposable
{
    public VaultFlags Flags { get; } = flags;
    public KdfParameters Kdf { get; } = kdf;
    public byte[] Salt { get; } = salt;
    public byte[] WrapNonce { get; } = wrapNonce;
    public byte[] WrappedKey { get; } = wrappedKey;
    public byte[] WrapTag { get; } = wrapTag;
    public byte[] DataKey { get; } = dataKey;

    /// <summary>Fresh salt, fresh data key, wrapped under a KEK from this password (and key file).</summary>
    public static VaultKeys Create(string password, byte[]? keyFileDigest, KdfParameters kdf)
    {
        kdf.Validate();
        var flags = keyFileDigest is null ? VaultFlags.None : VaultFlags.KeyFile;
        var salt = RandomNumberGenerator.GetBytes(VaultFormat.SaltSize);
        var dataKey = RandomNumberGenerator.GetBytes(VaultFormat.KeySize);
        var wrapNonce = RandomNumberGenerator.GetBytes(VaultFormat.NonceSize);
        var wrappedKey = new byte[VaultFormat.KeySize];
        var wrapTag = new byte[VaultFormat.TagSize];

        var kek = VaultFormat.DeriveKek(password, salt, kdf, keyFileDigest);
        try
        {
            using var aes = new AesGcm(kek, VaultFormat.TagSize);
            aes.Encrypt(wrapNonce, dataKey, wrappedKey, wrapTag, VaultFormat.WrapAad(flags, kdf, salt));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
        return new VaultKeys(flags, kdf, salt, wrapNonce, wrappedKey, wrapTag, dataKey);
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(DataKey);
}
