using Lockbox.Checks;

CryptoChecks.Run();
VaultChecks.Run();
GeneratorChecks.Run();
ConventionChecks.Run();

Console.WriteLine($"\n{Checks.Passed} passed, {Checks.Failed} failed, {Checks.Skipped} skipped");
return Checks.Failed == 0 ? 0 : 1;
