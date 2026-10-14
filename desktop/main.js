// Lockbox desktop: the lockbox-ui page in a window of its own. The vault, the crypto and the
// API all stay in the native lockbox-ui server (src/Lockbox.Web); this starts it as a child
// process in --hosted mode and owns nothing but the window.
//
// What the window adds over a browser tab: no extensions can read the page, and the launch link
// travels over the child's stdout pipe, never on a command line or through a file.
"use strict";

const { app, BrowserWindow, Menu, dialog, session } = require("electron");
const { spawn } = require("node:child_process");
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
