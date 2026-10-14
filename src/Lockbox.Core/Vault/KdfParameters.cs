namespace Lockbox.Core.Vault;

/// <summary>Argon2id cost parameters, stored in the vault header so they can be raised later.</summary>
public readonly record struct KdfParameters(int MemoryKiB, int Passes, int Lanes)
{
    /// <summary>
    /// What a new vault gets: 512 MiB, 4 passes, 4 lanes - roughly half a second to unlock on
    /// a current desktop (a few seconds on a weak laptop), and 512 MiB per guess for anyone
    /// attacking a copy of the file.
    /// </summary>
    public static KdfParameters Default => new(512 * 1024, 4, 4);

    // Upper bounds enforced when reading a header, so a corrupted or hostile file cannot
    // make Lockbox allocate unbounded memory or spin for hours before the tag check fails.
    public const int MaxMemoryKiB = 4 * 1024 * 1024; // 4 GiB
    public const int MaxPasses = 64;
    public const int MaxLanes = 64;

    public void Validate()
    {
        if (Lanes is < 1 or > MaxLanes)
            throw new VaultFormatException($"Argon2 lanes {Lanes} is outside 1-{MaxLanes}.");
        if (Passes is < 1 or > MaxPasses)
            throw new VaultFormatException($"Argon2 passes {Passes} is outside 1-{MaxPasses}.");
        if (MemoryKiB < 8 * Lanes || MemoryKiB > MaxMemoryKiB)
            throw new VaultFormatException($"Argon2 memory {MemoryKiB} KiB is outside {8 * Lanes}-{MaxMemoryKiB} KiB.");
    }

    public override string ToString() => $"Argon2id m={MemoryKiB / 1024} MiB, t={Passes}, p={Lanes}";
}
