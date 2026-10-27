import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";

// Docker images ship without the lazy deps in node_modules, so they load from
// <DATA_DIR>/runtime. That path once compiled to `(void 0).resolve` and broke
// the OpenCode free tier with a 502; these tests pin the runtime-dir paths.
const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));

vi.mock("node:child_process", () => ({ spawn: spawnMock }));

function fakeNpmFailure(stderrText) {
  spawnMock.mockImplementation(() => {
    const child = new EventEmitter();
    child.stderr = new EventEmitter();
    setImmediate(() => {
      child.stderr.emit("data", Buffer.from(stderrText));
      child.emit("close", 1);
    });
    return child;
  });
}

describe("lazyRuntime", () => {
  let dataDir;
  let prevDataDir;

  beforeEach(() => {
    vi.resetModules();
    spawnMock.mockReset();
    prevDataDir = process.env.DATA_DIR;
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "9router-lazy-runtime-"));
    process.env.DATA_DIR = dataDir;
  });

  afterEach(() => {
    if (prevDataDir === undefined) delete process.env.DATA_DIR;
    else process.env.DATA_DIR = prevDataDir;
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("loads a package installed only in the runtime dir without calling npm", async () => {
    const pkgDir = path.join(dataDir, "runtime", "node_modules", "lazy-runtime-fixture");
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, "package.json"), JSON.stringify({ name: "lazy-runtime-fixture", main: "index.js" }));
    fs.writeFileSync(path.join(pkgDir, "index.js"), "exports.createSession = () => 'ok';");

    const { loadRuntimeDep } = await import("../../open-sse/services/lazyRuntime.js");
    const mod = await loadRuntimeDep("lazy-runtime-fixture");

    expect(mod.createSession()).toBe("ok");
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("installs into its own project root and reports the real npm failure", async () => {
    fakeNpmFailure([
      "npm error code ECONNREFUSED",
      "npm error errno ECONNREFUSED",
      "npm error FetchError: request to https://registry.npmjs.org/wreq-js failed, reason: connect ECONNREFUSED",
      "npm error A complete log of this run can be found in: /root/.npm/_logs/debug.log",
    ].join("\n"));

    const { loadRuntimeDep } = await import("../../open-sse/services/lazyRuntime.js");
    const error = await loadRuntimeDep("lazy-runtime-missing-fixture").catch((e) => e);

    const runtimeDir = path.join(dataDir, "runtime");
    expect(spawnMock.mock.calls[0][2].cwd).toBe(runtimeDir);
    expect(JSON.parse(fs.readFileSync(path.join(runtimeDir, "package.json"), "utf8")).private).toBe(true);
    expect(error.message).toContain("reason: connect ECONNREFUSED");
    expect(error.message).not.toContain("A complete log");
    expect(error.message).toContain(`cd "${runtimeDir}" && npm install lazy-runtime-missing-fixture@latest`);
  });
});
