using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Lockbox.Core;

/// <summary>
/// Puts a secret on the system clipboard and takes it off again - but only if it is still
/// ours, so a later copy by the user is never wiped.
/// </summary>
/// <remarks>
/// On Windows the text goes in through user32 with the formats that keep it out of Win+V
/// clipboard history and cloud clipboard sync ("ExcludeClipboardContentFromMonitorProcessing",
/// "CanIncludeInClipboardHistory" = 0, "CanUploadToCloudClipboard" = 0). On macOS it uses
/// pbcopy/pbpaste; on Linux wl-copy/wl-paste (Wayland), then xclip, then xsel.
/// </remarks>
public enum ClipboardClearOutcome
{
    /// <summary>Nothing was copied since the last clear.</summary>
    NothingToClear,
    Cleared,
    /// <summary>The clipboard holds something newer than Lockbox's copy, so it was left alone.</summary>
    ChangedSinceCopy,
    /// <summary>The clipboard could not be read or cleared: it may still hold the secret.</summary>
    Failed,
}

public static partial class SecureClipboard
{
    private static readonly Lock s_gate = new();
    private static uint s_windowsSequence;
    private static string? s_lastCopied;

    /// <summary>Copy <paramref name="text"/>; returns false with a reason if no clipboard is usable.</summary>
    public static bool TryCopy(string text, out string? error)
    {
        lock (s_gate)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    Windows.SetText(text);
                    s_windowsSequence = Windows.GetClipboardSequenceNumber();
                }
                else
                {
                    Unix.SetText(text);
                }
                s_lastCopied = text;
                error = null;
                return true;
            }
            catch (Exception e)
            {
                error = e.Message;
                return false;
            }
        }
    }

    /// <summary>
    /// Clear the clipboard if it still holds the last thing <see cref="TryCopy"/> put there.
    /// <see cref="ClipboardClearOutcome.Failed"/> means the secret may still be there; callers
    /// tell the user. After a failure the next call tries again.
    /// </summary>
    public static ClipboardClearOutcome ClearIfOurs()
    {
        lock (s_gate)
        {
            if (s_lastCopied is null) return ClipboardClearOutcome.NothingToClear;
            try
            {
                ClipboardClearOutcome outcome;
                if (OperatingSystem.IsWindows())
                {
                    if (Windows.GetClipboardSequenceNumber() != s_windowsSequence)
                        outcome = ClipboardClearOutcome.ChangedSinceCopy;
                    else
                    {
                        Windows.Clear();
                        outcome = ClipboardClearOutcome.Cleared;
                    }
                }
                else if (Unix.GetText() != s_lastCopied)
                {
                    outcome = ClipboardClearOutcome.ChangedSinceCopy;
                }
                else
                {
                    Unix.SetText("");
                    outcome = ClipboardClearOutcome.Cleared;
                }
                s_lastCopied = null;
                return outcome;
            }
            catch
            {
                // Typically another process holding the clipboard at this moment.
                return ClipboardClearOutcome.Failed;
            }
        }
    }

    /// <summary>The warning to show for <see cref="ClipboardClearOutcome.Failed"/>, or null.</summary>
    public static string? WarningFor(ClipboardClearOutcome outcome) => outcome == ClipboardClearOutcome.Failed
        ? "Could not clear the clipboard - it may still hold a password. Copy something else over it."
        : null;

    private static partial class Windows
    {
        private const uint CF_UNICODETEXT = 13;
        private const uint GMEM_MOVEABLE = 0x0002;
        private static readonly nint HWND_MESSAGE = -3;

        public static void SetText(string text)
        {
            WithClipboard(() =>
            {
                if (!EmptyClipboard()) throw new InvalidOperationException("Could not empty the clipboard.");
                SetData(CF_UNICODETEXT, MemoryMarshal.AsBytes((text + "\0").AsSpan()));
                // Keep it out of clipboard history (Win+V) and cloud clipboard sync.
                SetData(RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing"), [0, 0, 0, 0]);
                SetData(RegisterClipboardFormatW("CanIncludeInClipboardHistory"), [0, 0, 0, 0]);
                SetData(RegisterClipboardFormatW("CanUploadToCloudClipboard"), [0, 0, 0, 0]);
            });
        }

        public static void Clear() => WithClipboard(() => EmptyClipboard());

        private static void WithClipboard(Action action)
        {
            // OpenClipboard(NULL) would leave the clipboard without an owner, which makes
            // SetClipboardData unreliable; a message-only window gives it one.
            var hwnd = CreateWindowExW(0, "STATIC", null, 0, 0, 0, 0, 0, HWND_MESSAGE, 0, 0, 0);
            try
            {
                var opened = false;
                for (var attempt = 0; attempt < 10 && !opened; attempt++)
                {
                    opened = OpenClipboard(hwnd);
                    if (!opened) Thread.Sleep(50); // another process holds it briefly
                }
                if (!opened) throw new InvalidOperationException("The clipboard is in use by another program.");
                try
                {
                    action();
                }
                finally
                {
                    CloseClipboard();
                }
            }
            finally
            {
                if (hwnd != 0) DestroyWindow(hwnd);
            }
        }

        private static void SetData(uint format, ReadOnlySpan<byte> data)
        {
            var handle = GlobalAlloc(GMEM_MOVEABLE, (nuint)data.Length);
            if (handle == 0) throw new OutOfMemoryException("GlobalAlloc failed.");
            var pointer = GlobalLock(handle);
            unsafe
            {
                data.CopyTo(new Span<byte>((void*)pointer, data.Length));
            }
            GlobalUnlock(handle);
            if (SetClipboardData(format, handle) == 0)
            {
                GlobalFree(handle);
                throw new InvalidOperationException("SetClipboardData failed.");
            }
            // On success the system owns the memory.
        }

        [LibraryImport("user32.dll")]
        public static partial uint GetClipboardSequenceNumber();

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool OpenClipboard(nint hWndNewOwner);

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CloseClipboard();

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool EmptyClipboard();

        [LibraryImport("user32.dll", SetLastError = true)]
        private static partial nint SetClipboardData(uint uFormat, nint hMem);

        [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        private static partial uint RegisterClipboardFormatW(string lpszFormat);

        [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        private static partial nint CreateWindowExW(uint dwExStyle, string lpClassName, string? lpWindowName, uint dwStyle,
            int x, int y, int nWidth, int nHeight, nint hWndParent, nint hMenu, nint hInstance, nint lpParam);

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool DestroyWindow(nint hWnd);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial nint GlobalAlloc(uint uFlags, nuint dwBytes);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial nint GlobalLock(nint hMem);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool GlobalUnlock(nint hMem);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        private static partial nint GlobalFree(nint hMem);
    }

    private static class Unix
    {
        public static void SetText(string text)
        {
            var (copy, _) = Tools();
            // The secret goes over stdin, never on the command line where `ps` can see it.
            Exec(copy.File, copy.Args, stdin: text);
        }

        public static string GetText()
        {
            var (_, paste) = Tools();
            return Exec(paste.File, paste.Args, stdin: null);
        }

        private static ((string File, string[] Args) Copy, (string File, string[] Args) Paste) Tools()
        {
            if (OperatingSystem.IsMacOS())
                return (("pbcopy", []), ("pbpaste", []));
            if (Environment.GetEnvironmentVariable("WAYLAND_DISPLAY") is { Length: > 0 } && OnPath("wl-copy"))
                return (("wl-copy", []), ("wl-paste", ["--no-newline"]));
            if (OnPath("xclip"))
                return (("xclip", ["-selection", "clipboard"]), ("xclip", ["-selection", "clipboard", "-o"]));
            if (OnPath("xsel"))
                return (("xsel", ["--clipboard", "--input"]), ("xsel", ["--clipboard", "--output"]));
            throw new InvalidOperationException("No clipboard tool found: install wl-clipboard, xclip or xsel.");
        }

        private static bool OnPath(string tool) =>
            (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Any(dir => dir.Length > 0 && File.Exists(Path.Combine(dir, tool)));

        private static string Exec(string file, string[] args, string? stdin)
        {
            var psi = new ProcessStartInfo(file)
            {
                RedirectStandardInput = stdin is not null,
                RedirectStandardOutput = stdin is null,
                UseShellExecute = false,
            };
            foreach (var arg in args) psi.ArgumentList.Add(arg);
            using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}.");
            string output = "";
            if (stdin is not null)
            {
                process.StandardInput.Write(stdin);
                process.StandardInput.Close();
            }
            else
            {
                output = process.StandardOutput.ReadToEnd();
            }
            // wl-copy and xclip fork a background owner and return; that is expected.
            process.WaitForExit(5000);
            return output;
        }
    }
}
