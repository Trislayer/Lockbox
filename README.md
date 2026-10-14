# Lockbox

A password vault in a single encrypted file. Put the file in Google Drive or iCloud Drive
(or carry it by hand); open it with one master password, optionally plus a key file that
never goes near the cloud. C#/.NET 10, Native AOT, Windows/macOS/Linux, **no NuGet
dependencies**.

| Project | What it is |
| --- | --- |
| `src/Lockbox.Core` | File format, crypto, entries, saving. The only code that encrypts or decrypts. |
| `src/Lockbox.Cli` | `lockbox` - command-line front end (3 MB native exe). |
| `src/Lockbox.Web` | `lockbox-ui` - the same vault in a browser tab, served on 127.0.0.1 only (12 MB native exe). |
| `tests/Lockbox.Checks` | Plain console test runner (`dotnet run -c Release`). |

## Use

```text
lockbox new "G:\My Drive\vault.lbx" --create-keyfile C:\Users\me\vault.lbxkey
lockbox open "G:\My Drive\vault.lbx" --keyfile C:\Users\me\vault.lbxkey
lockbox-ui "G:\My Drive\vault.lbx" --keyfile C:\Users\me\vault.lbxkey
```

Set `LOCKBOX_VAULT` / `LOCKBOX_KEYFILE` to skip the paths. In a `lockbox open` session:
`list`, `show`, `reveal`, `copy <entry> [username|url]`, `add`, `edit`, `rm`, `history`, `gen`,
`save`, `reload`, `passwd`, `info`, `quit`. `lockbox-ui` prints a single-use link and opens
the browser; press `L` in its terminal for a new link, `Q` to lock and quit.

## Build

```text
dotnet run --project tests/Lockbox.Checks -c Release
dotnet publish src/Lockbox.Cli -c Release -r win-x64 -o publish/win-x64
dotnet publish src/Lockbox.Web -c Release -r win-x64 -o publish/win-x64
```

Use `linux-x64` / `linux-arm64` / `osx-arm64` / `osx-x64` for the other platforms. Native
AOT does not cross-compile between operating systems: build macOS binaries on a Mac and
Linux binaries on Linux (or WSL). On Windows it needs the VS C++ build tools; if publish
says `'vswhere.exe' is not recognized`, add `C:\Program Files (x86)\Microsoft Visual
Studio\Installer` to `PATH`. Publishing downloads the SDK's own AOT compiler and runtime
packs - toolchain, not dependencies; nothing third-party is linked in.

## How the file is protected

- **Key derivation:** Argon2id (RFC 9106), 512 MiB, 4 passes, 4 lanes by default - every
  password guess against a stolen file costs 512 MiB and roughly half a second.
  Implemented in `Lockbox.Core/Crypto` together with BLAKE2b, because the base class library
  has neither; pinned by the RFC test vectors and by agreement with OpenSSL (via Node) and
  Python's hashlib in `Lockbox.Checks`.
- **Key file (optional):** its SHA-256 is mixed in with HKDF-SHA256. Keep it off the cloud
  and back it up; without it the vault cannot be opened.
- **Encryption:** a random 256-bit data key, wrapped by the password-derived key with
  AES-256-GCM; the entries are AES-256-GCM under the data key with a fresh nonce on every
  save. Every header byte is authenticated. Layout: `src/Lockbox.Core/Vault/VaultFormat.cs`.
- **Saving:** refuses to overwrite a file another device saved since you opened it (reload,
  or force); keeps the last 10 versions in `<vault>.backups/`; writes via temp file + rename
  and reads back to verify. Files like `vault (1).lbx` next to the vault are flagged as
  probable sync conflicts.
- **Clipboard:** cleared after 30 seconds (only if it still holds what Lockbox put there).
  On Windows it is excluded from clipboard history and cloud clipboard.
- **Idle lock:** 10 minutes, unless there are unsaved changes.

## What it does not protect against

- **A weak master password.** Anyone with the file can guess offline forever. Use a 7+ word
  passphrase (`lockbox gen --words 7`, 77 bits) or a key file.
- **Malware running as you.** It can log keystrokes or read the unlocked vault from memory.
  .NET cannot reliably wipe strings, so decrypted entries stay in managed memory until the
  process exits; the data key itself is zeroed on lock.
- **The browser (`lockbox-ui`).** Extensions with access to all sites can read the page. Use a
  browser profile without extensions, or the CLI, for the most sensitive work.
- **Two devices editing offline at once.** Sync clients make a conflict copy; Lockbox flags
  it, but merging is manual (open both, copy entries across).
