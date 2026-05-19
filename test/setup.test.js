const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const setupScript = path.join(__dirname, "..", "bin", "setup.js");

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "pi-xai-oauth-setup-"));
}

function runSetup(args, { cwd, home, pathPrefix, extraEnv = {} }) {
  return spawnSync(process.execPath, [setupScript, ...args], {
    cwd,
    env: {
      ...process.env,
      HOME: home,
      PATH: pathPrefix ? `${pathPrefix}${path.delimiter}${process.env.PATH}` : process.env.PATH,
      ...extraEnv,
    },
    encoding: "utf8",
  });
}

test("setup --help prints usage without touching the filesystem", () => {
  const cwd = makeTempDir();
  const home = makeTempDir();
  const result = runSetup(["--help"], { cwd, home });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage:/);
  assert.equal(fs.existsSync(path.join(cwd, ".scaffold")), false);
});

test("setup --scaffold generates the scaffold and AGENTS files", () => {
  const cwd = makeTempDir();
  const home = makeTempDir();
  const result = runSetup(["--scaffold", "--yes"], { cwd, home });
  assert.equal(result.status, 0, result.stderr);

  for (const file of ["plan.md", "constraints.md", "progress.md", "context.md"]) {
    assert.equal(fs.existsSync(path.join(cwd, ".scaffold", file)), true, file);
  }
  assert.equal(fs.existsSync(path.join(cwd, "AGENTS.md")), true);
  assert.match(fs.readFileSync(path.join(cwd, ".scaffold", "plan.md"), "utf8"), /pi-package/);
});

test("setup installs the package and seeds pi settings in automated mode", () => {
  const cwd = makeTempDir();
  const home = makeTempDir();
  const binDir = makeTempDir();
  const logPath = path.join(cwd, "pi.log");
  const piPath = path.join(binDir, "pi");

  fs.writeFileSync(
    piPath,
    `#!/bin/sh
printf '%s\\n' "$*" >> "$PI_LOG"
exit 0
`,
    { mode: 0o755 },
  );

  const result = runSetup(["--yes"], { cwd, home, pathPrefix: binDir, extraEnv: { PI_LOG: logPath } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Setup complete!/);
  assert.equal(fs.existsSync(path.join(home, ".pi", "agent", "settings.json")), true);
  const settings = JSON.parse(fs.readFileSync(path.join(home, ".pi", "agent", "settings.json"), "utf8"));
  assert.equal(settings.defaultProvider, "xai-auth");
  assert.equal(settings.defaultModel, "grok-4.3");
  assert.equal(settings.defaultThinkingLevel, "high");
  assert.ok(Array.isArray(settings.packages));
  assert.ok(settings.packages.includes("npm:pi-xai-oauth"));
  assert.match(fs.readFileSync(logPath, "utf8"), /install npm:pi-xai-oauth/);
});
