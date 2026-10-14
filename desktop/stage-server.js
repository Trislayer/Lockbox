// Copy the native lockbox-ui and its notice from publish/<rid> into server/, which
// electron-builder bundles as resources/server. Run by `npm run dist` before packaging.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { executableName, publishDirectory } = require("./server-path");

const source = publishDirectory();
const target = path.join(__dirname, "server");
const files = [executableName, "THIRD-PARTY-NOTICES.md"];

for (const file of files) {
  if (!fs.existsSync(path.join(source, file)))
    throw new Error(`${path.join(source, file)} is missing: run dotnet publish src/Lockbox.Web -c Release -r <rid> -o ${source} first.`);
}
fs.rmSync(target, { recursive: true, force: true });
fs.mkdirSync(target);
for (const file of files) fs.copyFileSync(path.join(source, file), path.join(target, file));
fs.chmodSync(path.join(target, executableName), 0o755);
console.log(`Staged ${files.join(", ")} from ${source}`);
