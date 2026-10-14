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
/// "CanIncludeInClipboardHistory" = 0, "CanUploadToCloudClipboard" = 0). On macOS it goes in
/// through NSPasteboard marked current-host-only, which keeps it off Universal Clipboard (other
/// Apple devices), and with the nspasteboard.org concealed/transient types that clipboard
/// managers honour by not recording it. On Linux wl-copy/wl-paste (Wayland), then xclip, then xsel.
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
    private static nint s_macChangeCount;
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
                else if (OperatingSystem.IsMacOS())
                {
                    s_macChangeCount = MacOS.SetText(text);
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
                else if (OperatingSystem.IsMacOS())
                {
                    outcome = MacOS.ClearIfChangeCount(s_macChangeCount)
                        ? ClipboardClearOutcome.Cleared
                        : ClipboardClearOutcome.ChangedSinceCopy;
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

    /// <summary>NSPasteboard through the Objective-C runtime (no bindings: Native AOT, no NuGet).</summary>
    private static unsafe partial class MacOS
    {
        private const string ObjC = "/usr/lib/libobjc.A.dylib";
        private const nuint NSPasteboardContentsCurrentHostOnly = 1;

        static MacOS()
        {
            // Registers NSPasteboard with the runtime; a console app does not load AppKit itself.
            NativeLibrary.Load("/System/Library/Frameworks/AppKit.framework/AppKit");
        }

        /// <summary>Put <paramref name="text"/> on the general pasteboard; returns its change count afterwards.</summary>
        public static nint SetText(string text)
        {
            var pool = objc_autoreleasePoolPush();
            try
            {
                var pasteboard = GeneralPasteboard();
                // Clears the pasteboard and keeps what follows off Universal Clipboard.
                Send(pasteboard, Selector("prepareForNewContentsWithOptions:"), NSPasteboardContentsCurrentHostOnly);
                nint value;
                fixed (char* chars = text)
                    value = Send(Class("NSString"), Selector("stringWithCharacters:length:"), chars, (nuint)text.Length);
                SetString(pasteboard, value, "public.utf8-plain-text");
                // http://nspasteboard.org: clipboard managers skip concealed and transient content.
                var empty = Send(Class("NSString"), Selector("string"));
                SetString(pasteboard, empty, "org.nspasteboard.ConcealedType");
                SetString(pasteboard, empty, "org.nspasteboard.TransientType");
                return Send(pasteboard, Selector("changeCount"));
            }
            finally
            {
                objc_autoreleasePoolPop(pool);
            }
        }

        /// <summary>Clear the pasteboard if nothing has been put on it since <paramref name="changeCount"/>.</summary>
        public static bool ClearIfChangeCount(nint changeCount)
        {
            var pool = objc_autoreleasePoolPush();
            try
            {
                var pasteboard = GeneralPasteboard();
                if (Send(pasteboard, Selector("changeCount")) != changeCount) return false;
                Send(pasteboard, Selector("clearContents"));
                return true;
            }
            finally
            {
                objc_autoreleasePoolPop(pool);
            }
        }

        private static nint GeneralPasteboard() =>
            Send(Class("NSPasteboard"), Selector("generalPasteboard")) is var p and not 0
                ? p
                : throw new InvalidOperationException("NSPasteboard is not available.");

        private static void SetString(nint pasteboard, nint value, string type)
        {
            var typeName = Send(Class("NSString"), Selector("stringWithUTF8String:"), type);
            if (!SendBool(pasteboard, Selector("setString:forType:"), value, typeName))
                throw new InvalidOperationException($"NSPasteboard refused {type}.");
        }

        private static nint Class(string name) =>
            objc_getClass(name) is var c and not 0 ? c : throw new InvalidOperationException($"Objective-C class {name} not found.");

        private static nint Selector(string name) => sel_registerName(name);

        [LibraryImport(ObjC, StringMarshalling = StringMarshalling.Utf8)]
        private static partial nint objc_getClass(string name);

        [LibraryImport(ObjC, StringMarshalling = StringMarshalling.Utf8)]
        private static partial nint sel_registerName(string name);

        [LibraryImport(ObjC)]
        private static partial nint objc_autoreleasePoolPush();

        [LibraryImport(ObjC)]
        private static partial void objc_autoreleasePoolPop(nint pool);

        // objc_msgSend must be called through a prototype matching each method's real signature.
        [LibraryImport(ObjC, EntryPoint = "objc_msgSend")]
        private static partial nint Send(nint receiver, nint selector);

        [LibraryImport(ObjC, EntryPoint = "objc_msgSend")]
        private static partial nint Send(nint receiver, nint selector, nuint argument);

        [LibraryImport(ObjC, EntryPoint = "objc_msgSend", StringMarshalling = StringMarshalling.Utf8)]
        private static partial nint Send(nint receiver, nint selector, string argument);

        [LibraryImport(ObjC, EntryPoint = "objc_msgSend")]
        private static partial nint Send(nint receiver, nint selector, char* characters, nuint length);

        [LibraryImport(ObjC, EntryPoint = "objc_msgSend")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static partial bool SendBool(nint receiver, nint selector, nint first, nint second);
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
