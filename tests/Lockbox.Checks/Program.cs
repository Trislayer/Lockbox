using Lockbox.Checks;

Checks.Group(nameof(CryptoChecks), CryptoChecks.Run);
Checks.Group(nameof(VaultChecks), VaultChecks.Run);
Checks.Group(nameof(GeneratorChecks), GeneratorChecks.Run);
Checks.Group(nameof(ConventionChecks), ConventionChecks.Run);

Console.WriteLine($"\n{Checks.Passed} passed, {Checks.Failed} failed, {Checks.Skipped} skipped");
return Checks.Failed == 0 ? 0 : 1;
