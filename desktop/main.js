// Lockbox desktop: the lockbox-ui page in a window of its own. The vault, the crypto and the
// API all stay in the native lockbox-ui server (src/Lockbox.Web); this starts it as a child
// process in --hosted mode and owns nothing but the window.
//
// What the window adds over a browser tab: no extensions can read the page, and the launch link
// travels over the child's stdout pipe, never on a command line or through a file.
"use strict";

const { app, BrowserWindow, Menu, dialog, ipcMain, session } = require("electron");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const { serverExecutable } = require("./server-path");

// In memory only (no "persist:" prefix): the session cookie, cache and storage never touch disk.
const PARTITION = "lockbox";

let server = null;
let origin = null;
let win = null;
let quitting = false;

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (!win) return;
    if (win.isMinimized()) win.restore();
    win.focus();
  });
  app.whenReady().then(start);
}

function start() {
  harden(session.fromPartition(PARTITION));
  ipcMain.handle("pick-path", pickPath);
  Menu.setApplicationMenu(buildMenu());

  const executable = serverExecutable(app.isPackaged ? process.resourcesPath : null);
  // LOCKBOX_VAULT / LOCKBOX_KEYFILE are inherited, as for lockbox-ui on its own.
  server = spawn(executable, ["--hosted"], { stdio: ["pipe", "pipe", "inherit"], windowsHide: true });
  server.on("error", (e) => fail(`Could not start ${executable}: ${e.message}`));
  server.on("exit", () => {
    // Quit in the page, a crash, or our own shutdown: the window has nothing left to show.
    server = null;
    app.quit();
  });

  readline.createInterface({ input: server.stdout }).on("line", (line) => {
    if (!line.startsWith("url ")) return;
    const url = line.slice(4).trim();
    origin = new URL(url).origin;
    if (win) win.loadURL(url);
    else openWindow(url);
  });
}

function openWindow(url) {
  win = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 640,
    minHeight: 480,
    title: "Lockbox",
    show: false,
    webPreferences: {
      partition: PARTITION,
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      spellcheck: false, // never send what is typed (passwords included) to a spellchecker
      devTools: !app.isPackaged,
      preload: path.join(__dirname, "preload.js"),
    },
  });
  win.once("ready-to-show", () => win.show());
  win.on("closed", () => { win = null; });

  // The page refuses to unload with unsaved changes (beforeunload); in a browser that is a
  // prompt, in Electron it would silently cancel the close. Ask instead.
  win.webContents.on("will-prevent-unload", (event) => {
    const choice = dialog.showMessageBoxSync(win, {
      type: "warning",
      buttons: ["Quit without saving", "Cancel"],
      defaultId: 1,
      cancelId: 1,
      message: "The vault has unsaved changes.",
      detail: "Quitting locks the vault and discards them.",
    });
    if (choice === 0) event.preventDefault();
  });

  win.loadURL(url);
}

// "Lockbox Keys" in the home folder, owner-only: see KeyFolder.cs in Lockbox.Core.
const KEY_FOLDER = path.join(app.getPath("home"), "Lockbox Keys");

/** A native open or save dialog for one of the page's path fields; resolves to the chosen path or null. */
async function pickPath(event, request) {
  if (!win || origin === null || new URL(event.senderFrame.url).origin !== origin) return null;
  const keyFile = request?.kind === "keyfile";
  if (request?.save === true) {
    // A new key file goes in Lockbox Keys, not Documents: Documents is often synced to the
    // cloud (iCloud on macOS, OneDrive on Windows), which would put it beside the vault.
    if (keyFile) fs.mkdirSync(KEY_FOLDER, { recursive: true, mode: 0o700 });
    const result = await dialog.showSaveDialog(win, {
      title: keyFile ? "New key file" : "New vault file",
      defaultPath: keyFile ? path.join(KEY_FOLDER, "vault.lbxkey") : path.join(app.getPath("documents"), "vault.lbx"),
      filters: [keyFile ? { name: "Key file", extensions: ["lbxkey"] } : { name: "Lockbox vault", extensions: ["lbx"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"],
    });
    return result.canceled ? null : result.filePath ?? null;
  }
  // No filter for an existing key file: any file up to 1 MiB works as one, with any name or
  // none (key files made before .lbxkey was added automatically have no extension).
  const result = await dialog.showOpenDialog(win, {
    title: keyFile ? "Choose key file" : "Open vault",
    defaultPath: keyFile && fs.existsSync(KEY_FOLDER) ? KEY_FOLDER : undefined,
    filters: keyFile ? [] : [{ name: "Lockbox vault", extensions: ["lbx"] }, { name: "All files", extensions: ["*"] }],
    properties: ["openFile"],
  });
  return result.canceled ? null : result.filePaths[0] ?? null;
}

/** Only the local server, ever: no other navigation, windows, permissions or requests. */
function harden(ses) {
  ses.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  ses.setPermissionCheckHandler(() => false);
  ses.webRequest.onBeforeRequest((details, callback) => {
    const allowed = origin !== null && (details.url === origin || details.url.startsWith(origin + "/"));
    callback({ cancel: !allowed && !details.url.startsWith("devtools:") });
  });
}

app.on("web-contents-created", (_event, contents) => {
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-navigate", (event, url) => {
    if (origin === null || new URL(url).origin !== origin) event.preventDefault();
  });
  contents.on("will-attach-webview", (event) => event.preventDefault());
});

function buildMenu() {
  const lockbox = {
    label: "Lockbox",
    submenu: [
      // For a page that lost its sign-in: the server issues a fresh launch link and we load it.
      { label: "Reconnect", click: () => server?.stdin.write("link\n") },
      { type: "separator" },
      { role: "quit" },
    ],
  };
  const template = process.platform === "darwin"
    ? [{ role: "appMenu" }, { role: "editMenu" }, { role: "viewMenu" }, { role: "windowMenu" }, lockbox]
    : [lockbox, { role: "editMenu" }, { role: "viewMenu" }];
  return Menu.buildFromTemplate(template);
}

function fail(message) {
  dialog.showErrorBox("Lockbox", message);
  app.quit();
}

// One window, one vault: closing it quits on every platform (no lingering macOS dock app).
app.on("window-all-closed", () => app.quit());

// Closing stdin tells the server to lock and stop; give it a moment, then make sure.
app.on("will-quit", (event) => {
  if (!server || quitting) return;
  quitting = true;
  event.preventDefault();
  const child = server;
  const timer = setTimeout(() => child.kill(), 3000);
  child.once("exit", () => { clearTimeout(timer); app.quit(); });
  child.stdin.end();
});
