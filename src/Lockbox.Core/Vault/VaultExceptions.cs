namespace Lockbox.Core.Vault;

/// <summary>The file is not a Lockbox vault, or is a version or shape this build cannot read.</summary>
public sealed class VaultFormatException(string message) : Exception(message);

/// <summary>
/// The password, the key file, or both are wrong - or the file has been altered. AES-GCM
/// cannot tell these apart, and Lockbox deliberately does not try to.
/// </summary>
public sealed class VaultUnlockException()
    : Exception("Could not unlock the vault: wrong master password or key file, or the file has been modified.");

/// <summary>
/// The file on disk changed after this session opened or last saved it - typically another
/// device saved through the cloud folder. Saving now would silently discard that change.
/// </summary>
public sealed class VaultConflictException(string path)
    : Exception($"'{path}' was changed by something else since it was opened. Reopen it to see those changes, or save with force to overwrite them.");
