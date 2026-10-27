// Lazy loader for heavy optional runtime deps (playwright-core, wreq-js).
//
// They are devDependencies only, so end-user installs stay small. On first
// use the package is downloaded into <DATA_DIR>/runtime (same pattern as
// cli/hooks/sqliteRuntime.js) and imported from there. Resolution order:
// app node_modules (dev / traced standalone) → runtime dir → npm install.
//
// Never throws at import time of THIS module — failures surface from
// loadRuntimeDep() with a manual-install hint.
//
// Every resolve/import here must stay invisible to webpack. It rewrites a
// statically imported createRequire() into a stub, so `.resolve` read off it
// compiled to `(void 0).resolve` and threw "Cannot read properties of undefined
// (reading 'resolve')" in the production build; a bare import() becomes a
// context module that rejects every path. Both go through nativeImport instead.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { getWritableDataDir } from "../utils/writableDataDir.js";

const nativeImport = (specifier) => import(/* webpackIgnore: true */ specifier);

// Keep in sync with package.json devDependencies.
const LAZY_DEP_VERSIONS = {
  "playwright-core": "^1.62.1",
  "wreq-js": "^3.2.0",
};

function getRuntimeDir() {
  return path.join(getWritableDataDir(), "runtime");
}

function isModuleMissing(error) {
  const code = String(error?.code || "");
  return code === "MODULE_NOT_FOUND" || code === "ERR_MODULE_NOT_FOUND";
}

function ensureRuntimeDir() {
  const dir = getRuntimeDir();
  fs.mkdirSync(dir, { recursive: true });
  // Without its own package.json npm walks up to the nearest project root —
  // /app/package.json in the Docker image — and installs the whole app tree
  // there instead of this one package here.
  const pkgPath = path.join(dir, "package.json");
  if (!fs.existsSync(pkgPath)) {
    fs.writeFileSync(pkgPath, JSON.stringify({
      name: "9router-runtime",
      version: "1.0.0",
      private: true,
      description: "User-writable runtime deps for 9router",
    }, null, 2));
  }
  return dir;
}

// npm ≥7 prefixes "npm error", older npm "npm ERR!". Skip the code/errno and
// log-path bookkeeping lines so the reason names the actual failure.
function npmFailureReason(stderr) {
  const lines = String(stderr).split("\n")
    .map((line) => line.replace(/^npm (?:ERR!|error)\s?/, "").trim())
    .filter((line) => line && !/^(?:code|syscall|errno|path|at) |^A complete log/.test(line));
  return lines[0] || "unknown npm error";
}

function npmInstall(pkg, version) {
  const cwd = ensureRuntimeDir();
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const args = ["install", "--no-audit", "--no-fund", "--prefer-online", `${pkg}@${version}`];
  return new Promise((resolve) => {
    const child = spawn(npm, args, { cwd, stdio: ["ignore", "pipe", "pipe"], shell: process.platform === "win32" });
    let stderr = "";
    child.stderr?.on("data", (chunk) => { stderr += String(chunk); });
    child.on("error", (error) => resolve({ ok: false, stderr: String(error.message || error) }));
    child.on("close", (status) => resolve({ ok: status === 0, stderr }));
  });
}

async function importFromRuntimeDir(pkg) {
  const { createRequire } = await nativeImport("node:module");
  const resolved = createRequire(path.join(getRuntimeDir(), "package.json")).resolve(pkg);
  return nativeImport(pathToFileURL(resolved).href);
}

const inflight = new Map();

async function load(pkg) {
  // 1) Resolvable from the app install (dev machine / Docker image).
  try {
    return await nativeImport(pkg);
  } catch (error) {
    if (!isModuleMissing(error)) throw error;
  }
  // 2) Already present in the runtime dir from a previous install.
  try {
    return await importFromRuntimeDir(pkg);
  } catch (error) {
    if (!isModuleMissing(error)) throw error;
  }
  // 3) Download on demand, then import from the runtime dir.
  const version = LAZY_DEP_VERSIONS[pkg] || "latest";
  const dir = getRuntimeDir();
  const res = await npmInstall(pkg, version);
  if (!res.ok) {
    throw new Error(
      `${pkg} is missing and the on-demand install failed (${npmFailureReason(res.stderr).slice(0, 160)}) — ` +
      `install it manually: cd "${dir}" && npm install ${pkg}@${version}`
    );
  }
  return importFromRuntimeDir(pkg);
}

export function loadRuntimeDep(pkg) {
  if (!inflight.has(pkg)) {
    inflight.set(pkg, load(pkg).finally(() => inflight.delete(pkg)));
  }
  return inflight.get(pkg);
}
