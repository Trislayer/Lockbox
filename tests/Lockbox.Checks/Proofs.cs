namespace Lockbox.Checks;

/// <summary>
/// Every check class, with the recorded proof that it can fail: what was broken in the
/// production code, and what went red. A class with no proof here fails ConventionChecks, so a
/// new check class is not trusted until someone has watched it fail.
/// </summary>
/// <remarks>
/// Recipe: copy the file, apply the mutation, build, run, restore from the copy and touch it -
/// in one command, never across a commit. Record the result here and in the commit body.
/// </remarks>
internal static class Proofs
{
    public static readonly IReadOnlyDictionary<string, string> Recorded = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [nameof(CryptoChecks)] =
            "BLAKE2b G rotation 63->62: both RFC 7693 vectors, all 50 hashlib cases and every Argon2id case red. " +
            "Argon2id GB rotation 24->23: the RFC 9106 vector and all 6 OpenSSL cases red.",
        [nameof(VaultChecks)] =
            "Save without the conflict check: 'saving over someone else's change is refused' and 'the refused save left " +
            "the laptop's version intact' red. KEK without NFC: 'a passphrase typed decomposed opens ...' red. " +
            "No RekeyBackups after a password change: 'no backup opens with the old password' and 3 more red. " +
            "RollbackWarning always null: 'an older version put back in place is reported' and 1 more red. " +
            "PrivateFiles without UnixCreateMode: the key file, vault, backup and ledger 0600 checks red. " +
            "SaveBeforeLock forcing the save: 'the other device's version is left as it was' and 2 more red.",
        [nameof(GeneratorChecks)] =
            "No Fisher-Yates shuffle: 'the first character is drawn from the whole alphabet' red (26 distinct).",
        [nameof(ConventionChecks)] =
            "A planted violation per lint (`!`, NoWarn in a csproj, #nullable disable, JSON options without " +
            "Respect*, a PackageReference, a crypto type used outside Crypto/ and VaultFormat.cs, an unregistered " +
            "check class, an uncredited file in Resources/): each lint red.",
    };
}
