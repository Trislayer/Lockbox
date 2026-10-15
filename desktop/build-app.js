// Build the desktop app in one go, from any folder: the checks, the native lockbox-ui for this
// machine, the npm packages (only when missing or out of date), then the packaged app.
// Run it through build-app.sh (macOS, Linux) or build-app.cmd (Windows) at the repo root.
//
//   --skip-checks   skip Lockbox.Checks
//   --open          open the built app when done (macOS)
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { publishDirectory, runtimeIdentifier } = require("./server-path");

const args = new Set(process.argv.slice(2));
const desktop = __dirname;
const root = path.join(desktop, "..");

function run(title, command, commandArgs, cwd) {
  console.log(`\n== ${title}`);
  // npm is npm.cmd on Windows, which only starts through a shell.
  const result = spawnSync(command, commandArgs, { cwd, stdio: "inherit", shell: process.platform === "win32" });
  if (result.status !== 0) {
    console.error(`\nbuild-app: "${title}" failed${result.error ? `: ${result.error.message}` : ""}. Nothing after it was run.`);
    process.exit(1);
  }
}

/** npm ci when node_modules is missing or older than package-lock.json. */
function needsInstall() {
  const installed = path.join(desktop, "node_modules", ".package-lock.json");
  if (!fs.existsSync(installed)) return true;
  return fs.statSync(path.join(desktop, "package-lock.json")).mtimeMs > fs.statSync(installed).mtimeMs;
}

const rid = runtimeIdentifier();
if (!args.has("--skip-checks"))
  run("Checks", "dotnet", ["run", "--project", "tests/Lockbox.Checks", "-c", "Release"], root);
run(`lockbox-ui for ${rid}`, "dotnet", ["publish", "src/Lockbox.Web", "-c", "Release", "-r", rid, "-o", publishDirectory()], root);
if (needsInstall()) run("npm packages", "npm", ["ci"], desktop);
else console.log("\n== npm packages: up to date");
run("Desktop app", "npm", ["run", "dist"], desktop);

const dist = path.join(desktop, "dist");
const app = path.join(dist, rid === "osx-x64" ? "mac" : "mac-arm64", "Lockbox.app");
console.log(`\nDone. Output in ${dist}:`);
for (const name of fs.readdirSync(dist).filter((n) => /\.(dmg|zip|exe|AppImage)$/.test(n))) console.log(`  ${name}`);
if (fs.existsSync(app)) {
  console.log(`  ${path.relative(dist, app)}`);
  if (args.has("--open")) spawnSync("open", [app]);
}
