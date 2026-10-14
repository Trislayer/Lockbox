# Lockbox

A password vault in a single encrypted file. Put the file in Google Drive or iCloud Drive
(or carry it by hand); open it with one master password, optionally plus a key file that
never goes near the cloud. C#/.NET 10, Native AOT, Windows/macOS/Linux, **no NuGet
dependencies**. The optional desktop app (`desktop/`) is an Electron window around
`lockbox-ui`; it is the one part with third-party code (Electron and its Chromium), and it
holds no vault logic.

| Project | What it is |
| --- | --- |
| `src/Lockbox.Core` | File format, crypto, entries, saving. The only code that encrypts or decrypts. |
| `src/Lockbox.Cli` | `lockbox` - command-line front end (3 MB native exe). |
| `src/Lockbox.Web` | `lockbox-ui` - the same vault in a browser tab, served on 127.0.0.1 only (11 MB native exe). |
| `desktop` | `Lockbox` app - Electron window that starts the bundled `lockbox-ui --hosted` and shows its page: no browser extensions, no link to copy. |
| `tests/Lockbox.Checks` | Plain console test runner (`dotnet run -c Release`): crypto vectors, vault behaviour, and convention lints. |

Conventions the build holds (each is a lint in `tests/Lockbox.Checks/ConventionChecks.cs`):
nullable reference types on, with nullable warnings as compile errors and no `!`
operator; JSON refuses nulls in non-nullable members; no NuGet packages; and every check
class has a recorded proof that it can fail (`Proofs.cs`).

## Use

```text
lockbox new "G:\My Drive\vault.lbx" --create-keyfile C:\Users\me\vault.lbxkey
lockbox open "G:\My Drive\vault.lbx" --keyfile C:\Users\me\vault.lbxkey
lockbox-ui "G:\My Drive\vault.lbx" --keyfile C:\Users\me\vault.lbxkey
```

Set `LOCKBOX_VAULT` / `LOCKBOX_KEYFILE` to skip the paths. In a `lockbox open` session:
`list`, `show`, `reveal`, `copy <entry> [username|url]`, `add`, `edit`, `rm`, `history`, `gen`,
`save`, `reload`, `passwd`, `info`, `quit`. `lockbox-ui` prints a single-use link and opens
the browser on it (through an owner-only file, so the link never appears on a command line
other users can see); press `L` in its terminal for a new link, `Q` to lock and quit.

Third-party content: the BIP39 English wordlist (MIT), credited in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), which is copied next to every built executable.

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

Desktop app (Node 24+), after publishing `lockbox-ui` for this machine into `publish/<rid>`:

```text
cd desktop
npm ci
npm start       # run from source
npm run dist    # package: .dmg/.zip (macOS), setup .exe (Windows), AppImage (Linux) in desktop/dist
```

The macOS app is ad-hoc signed, not notarized: one downloaded from a release needs
right-click > Open the first time. Electron versions are pinned exactly; update them for
Chromium security fixes.

CI (`.github/workflows/build.yml`) runs the checks and builds all of the above on macOS,
Windows and Linux runners for every push, and attaches them to a release for `v*` tags.

## How the file is protected

- **Key derivation:** Argon2id (RFC 9106), 512 MiB, 4 passes, 4 lanes by default - every
  password guess against a stolen file costs 512 MiB and roughly half a second.
  Implemented in `Lockbox.Core/Crypto` together with BLAKE2b, because the base class library
  has neither; pinned by the RFC test vectors and by agreement with OpenSSL (via Node) and
  Python's hashlib in `Lockbox.Checks`. They are the only crypto not taken from .NET itself:
  a lint keeps them in `Crypto/` and lets only `VaultFormat.cs` call them.
- **Key file (optional):** its SHA-256 is mixed in with HKDF-SHA256. Keep it off the cloud
  and back it up; without it the vault cannot be opened.
- **Encryption:** a random 256-bit data key, wrapped by the password-derived key with
  AES-256-GCM; the entries are AES-256-GCM under the data key with a fresh nonce on every
  save. Every header byte is authenticated. Layout: `src/Lockbox.Core/Vault/VaultFormat.cs`.
- **Changing the master password** generates a fresh data key and salt, and re-encrypts the
  backups to match, so no file Lockbox keeps opens with the old password.
- **Saving:** refuses to overwrite a file another device saved since you opened it (reload,
  or force); keeps the last 10 versions in `<vault>.backups/`; writes via temp file + rename
  and reads back to verify. Files like `vault (1).lbx` next to the vault are flagged as
  probable sync conflicts. The vault, its backups and key files are created readable by
  you only (0600 on macOS/Linux).
- **Older copies:** every save raises a revision number inside the encrypted payload, and
  each device remembers the highest revision it has seen (in local app data, not the cloud
  folder). Opening an older one - an old version someone put back in place, or a backup -
  shows a warning.
- **Clipboard:** cleared after 30 seconds (only if it still holds what Lockbox put there).
  On Windows it is excluded from clipboard history and cloud clipboard; on macOS it is kept
  off Universal Clipboard and marked concealed, so clipboard managers skip it.
- **Idle lock:** 10 minutes. Unsaved changes are saved first - or, if another device saved
  in the meantime, written to `vault (unsaved <time>).lbx` beside it, flagged like a sync
  conflict. The browser tab reloads on lock, so nothing decrypted stays in the page.

## What it does not protect against

- **A weak master password.** Anyone with the file can guess offline forever. Use a 7+ word
  passphrase (`lockbox gen --words 7`, 77 bits) or a key file.
- **Malware running as you.** It can log keystrokes or read the unlocked vault from memory.
  .NET cannot reliably wipe strings, so decrypted entries stay in managed memory until the
  process exits; the data key itself is zeroed on lock.
- **The browser (`lockbox-ui`).** Extensions with access to all sites can read the page. Use the
  desktop app, a browser profile without extensions, or the CLI for the most sensitive work.
- **Copies made before a password change.** Your cloud provider's version history and trash
  (Google Drive keeps both for 30 days), or a copy someone already downloaded, still open with
  the old password. If it leaked, assume those copies are readable.
- **An old version on a device that never saw a newer one.** The rollback warning only knows
  what this device has opened.
- **Two devices editing offline at once.** Sync clients make a conflict copy; Lockbox flags
  it, but merging is manual (open both, copy entries across).
