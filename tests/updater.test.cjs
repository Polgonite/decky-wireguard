const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const ts = require("typescript");

const source = readFileSync(resolve(__dirname, "../src/updater.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
}).outputText;
const hash = "a".repeat(64);

function release(version, publishedAt = "2026-11-17T09:00:00Z") {
  return {
    tag_name: `v${version}`,
    published_at: publishedAt,
    draft: false,
    prerelease: true,
    assets: [{
      name: `decky-wireguard-${version}.zip`,
      state: "uploaded",
      browser_download_url: `https://github.com/Polgonite/decky-wireguard/releases/download/v${version}/decky-wireguard-${version}.zip`,
      digest: `sha256:${hash}`,
    }],
  };
}

function updater({ data = [release("0.1.0-dev.42.1.shaabcdef0")], version = "0.1.0" } = {}) {
  const installs = [];
  const requests = [];
  const response = { ok: true, status: 200, json: async () => data };
  let timeout;
  const context = {
    exports: {},
    DeckyBackend: { call: async (...args) => { installs.push(args); } },
    setTimeout: (callback, delay) => { timeout = callback; assert.equal(delay, 15000); return 1; },
    clearTimeout: () => { timeout = undefined; },
    require: (name) => {
      if (name === "@decky/api") return {
        fetchNoCors: async (...args) => { requests.push(args); return response; },
      };
      if (name === "../package.json") return { version };
      if (name === "@decky/ui" || name === "react/jsx-runtime" || name === "react") return {};
      throw new Error(`Unexpected module: ${name}`);
    },
  };
  runInNewContext(compiled, context);
  return { ...context.exports, context, installs, requests, response, expire: () => timeout?.() };
}

test("latest published installable release wins, including prereleases and out-of-order results", () => {
  const check = updater();
  const old = release("0.1.0-dev.1", "2026-11-16T09:00:00Z");
  const newest = release("0.1.0-dev.2");
  const draft = { ...release("0.1.0-dev.3", "2026-11-18T09:00:00Z"), draft: true };
  const sourceOnly = { ...release("0.1.0-dev.4", "2026-11-19T09:00:00Z"), assets: [] };
  assert.equal(check.latestBuild([old, newest, draft, sourceOnly]).version, "0.1.0-dev.2");
});

test("invalid responses and assets outside the expected repository fail closed", () => {
  const check = updater();
  const foreign = release("0.1.0-dev.2");
  foreign.assets[0].browser_download_url = "https://example.com/update.zip";
  for (const data of [null, {}, [], [foreign], [null, { tag_name: "../bad" }]]) {
    assert.throws(() => check.latestBuild(data), /invalid release list|No installable/);
  }
});

test("update requests Decky's native confirmation with the exact URL, version, digest and UPDATE type", async () => {
  const check = updater();
  const message = await check.requestLatestBuild();
  assert.match(check.requests[0][0], /api.github.com\/repos\/Polgonite\/decky-wireguard\/releases\?per_page=100$/);
  assert.equal(check.installs.length, 1);
  assert.deepEqual(Array.from(check.installs[0]), [
    "utilities/install_plugin",
    release("0.1.0-dev.42.1.shaabcdef0").assets[0].browser_download_url,
    "WireGuard", "0.1.0-dev.42.1.shaabcdef0", hash, 2,
  ]);
  assert.match(message, /Confirm .*installation dialog/);
});

test("the installed build is not reinstalled", async () => {
  const check = updater({ version: "0.1.0-dev.42.1.shaabcdef0" });
  assert.match(await check.requestLatestBuild(), /Already running the latest/);
  assert.equal(check.installs.length, 0);
});

test("a missing or malformed digest never installs or falls back to an older build", async () => {
  for (const digest of [null, undefined, "sha256:bad", `sha1:${hash}`]) {
    const newest = release("0.1.0-dev.2");
    newest.assets[0].digest = digest;
    const check = updater({ data: [release("0.1.0-dev.1", "2026-11-16T09:00:00Z"), newest] });
    await assert.rejects(check.requestLatestBuild(), /no SHA-256 digest/);
    assert.equal(check.installs.length, 0);
  }
});

test("GitHub rate limits, network errors and invalid JSON are surfaced without installation", async () => {
  const limited = updater();
  limited.response.ok = false;
  limited.response.status = 403;
  await assert.rejects(limited.requestLatestBuild(), /HTTP 403/);
  assert.equal(limited.installs.length, 0);
  for (const error of [new Error("Offline"), new SyntaxError("Invalid JSON")]) {
    const check = updater();
    check.response.json = async () => { throw error; };
    await assert.rejects(check.requestLatestBuild(), (failure) => failure.message === error.message);
    assert.equal(check.installs.length, 0);
  }
});

test("timeout prevents a late GitHub response from triggering installation", async () => {
  const check = updater();
  let finish;
  check.response.json = () => new Promise((resolve) => { finish = resolve; });
  const pending = check.requestLatestBuild();
  await new Promise((resolve) => setImmediate(resolve));
  check.expire();
  await assert.rejects(pending, /timed out/);
  finish([release("0.1.0-dev.42")]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(check.installs.length, 0);
});

test("unavailable installer fails before fetching and native installer failures propagate", async () => {
  const unavailable = updater();
  delete unavailable.context.DeckyBackend;
  await assert.rejects(unavailable.requestLatestBuild(), /installer is unavailable/);
  assert.equal(unavailable.requests.length, 0);
  const broken = updater();
  broken.context.DeckyBackend.call = async () => { throw new Error("Installer failed"); };
  await assert.rejects(broken.requestLatestBuild(), /Installer failed/);
});
