// Where the native lockbox-ui lives: bundled into the app under resources/server, or - when
// running from source - the publish output for this machine (dotnet publish src/Lockbox.Web
// -r <rid> -o publish/<rid>). Shared by main.js and stage-server.js.
"use strict";

const path = require("node:path");

const executableName = process.platform === "win32" ? "lockbox-ui.exe" : "lockbox-ui";

/** The .NET runtime identifier for this machine, as used for publish/<rid>. */
function runtimeIdentifier() {
  const os = { darwin: "osx", win32: "win", linux: "linux" }[process.platform];
  const arch = { x64: "x64", arm64: "arm64" }[process.arch];
  if (!os || !arch) throw new Error(`Lockbox is not built for ${process.platform}-${process.arch}.`);
  return `${os}-${arch}`;
}

function publishDirectory() {
  return process.env.LOCKBOX_PUBLISH_DIR ?? path.join(__dirname, "..", "publish", runtimeIdentifier());
}

/** @param {string | null} resourcesPath process.resourcesPath when packaged, else null. */
function serverExecutable(resourcesPath) {
  return resourcesPath
    ? path.join(resourcesPath, "server", executableName)
    : path.join(publishDirectory(), executableName);
}

module.exports = { executableName, runtimeIdentifier, publishDirectory, serverExecutable };
