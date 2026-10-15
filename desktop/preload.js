// The only things the page gets from the desktop app: the real path of a file dropped on it,
// and a native open/save dialog. Both hand back a path the user chose; nothing is read here.
"use strict";

const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("lockboxDesktop", {
  /** Path of a File from a drop event, or "" if it has none. */
  pathForFile: (file) => webUtils.getPathForFile(file),
  /** kind: "vault" or "keyfile"; save: a new file rather than an existing one. Resolves to a path or null. */
  pickPath: (kind, save) => ipcRenderer.invoke("pick-path", { kind, save: Boolean(save) }),
});
