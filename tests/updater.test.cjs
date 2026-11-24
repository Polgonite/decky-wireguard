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
const latestURL = "https://api.github.com/repos/Polgonite/decky-wireguard/releases/latest";
const listURL = "https://api.github.com/repos/Polgonite/decky-wireguard/releases?per_page=100";

function release(version, publishedAt = "2026-11-17T09:00:00Z", prerelease = version.includes("-")) {
  return {
    tag_name: `v${version}`,
    published_at: publishedAt,
    draft: false,
    prerelease,
    assets: [{
      name: `decky-wireguard-${version}.zip`,
      state: "uploaded",
      browser_download_url: `https://github.com/Polgonite/decky-wireguard/releases/download/v${version}/decky-wireguard-${version}.zip`,
      digest: `sha256:${hash}`,
    }],
  };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

function updater({
  stable = release("0.1.0"),
  list = [release("0.2.0-dev.42.1.shaabcdef0"), release("0.1.0")],
  version = "0.1.0",
  settings = {},
} = {}) {
  const installs = [];
  const requests = [];
  const toasts = [];
  const quickAccess = [];
  const errors = [];
  const timers = [];
  const state = {
    loaded: true, loading: false, saving: false, error: null,
    showAdvanced: false, includePrereleases: false, autoUpdateCheck: false, ...settings,
  };
  const listeners = new Set();
  let loads = 0;
  const response = { ok: true, status: 200, stable, list, failure: null };
  const context = {
    exports: {},
    console: { error: (...args) => errors.push(args.join(" ")) },
    DeckyBackend: { call: async (...args) => { installs.push(args); } },
    setTimeout: (callback, delay) => { timers.push({ callback, delay, active: true }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].active = false; },
    require: (name) => {
      if (name === "@decky/api") return {
        fetchNoCors: async (url, init) => {
          requests.push([url, init]);
          if (response.failure) throw response.failure;
          const body = url === latestURL ? response.stable : response.list;
          const missing = url === latestURL && response.stable === null;
          return {
            ok: response.ok && !missing,
            status: missing ? 404 : response.status,
            json: async () => body,
          };
        },
        toaster: { toast: (toast) => toasts.push(toast) },
      };
      if (name === "@decky/ui") return {
        Navigation: { OpenQuickAccessMenu: (tab) => quickAccess.push(tab) },
        QuickAccessTab: { Decky: 7 },
        ButtonItem: "ButtonItem",
        PanelSectionRow: "PanelSectionRow",
      };
      if (name === "./ui-settings") return {
        getUISettings: () => state,
        subscribeUISettings: (listener) => { listeners.add(listener); return () => listeners.delete(listener); },
        loadUISettings: async () => { loads++; },
        useUISettings: () => state,
      };
      if (name === "../package.json") return { version };
      if (name === "react") return {
        useState: (initial) => [initial, () => {}],
        useRef: (initial) => ({ current: initial }),
        useSyncExternalStore: (_subscribe, snapshot) => snapshot(),
      };
      if (name === "react/jsx-runtime") {
        const element = (type, props) => ({ type, props });
        return { jsx: element, jsxs: element };
      }
      throw new Error(`Unexpected module: ${name}`);
    },
  };
  runInNewContext(compiled, context);
  const timer = (delay) => timers.findLast((candidate) => candidate.active && candidate.delay === delay);
  return {
    ...context.exports, context, installs, requests, response, toasts, quickAccess, errors, state, timers,
    loads: () => loads,
    notify: () => listeners.forEach((listener) => listener()),
    expire: () => timer(15000)?.callback(),
    fire: async (delay) => {
      const pending = timer(delay);
      assert.ok(pending, `No active ${delay} ms timer`);
      pending.active = false;
      pending.callback();
      await flush();
    },
    pending: () => timers.filter((candidate) => candidate.active && candidate.delay !== 15000).map((c) => c.delay),
  };
}

test("versions follow SemVer precedence, including numeric and development identifiers", () => {
  const { compareVersions } = updater();
  const ascending = [
    "0.1.0-dev.9.1.shaaaaaaa", "0.1.0-dev.10.1.shaaaaaaa", "0.1.0-dev.10.2.sha0000000",
    "0.1.0-dev.10.2.shabcdef0", "0.1.0-rc.1", "0.1.0", "0.1.1-dev.1.1.sha1234567", "0.1.1", "0.2.0", "1.0.0",
    "1.0.10", "1.0.100",
  ];
  for (let index = 1; index < ascending.length; index++) {
    assert.ok(compareVersions(ascending[index], ascending[index - 1]) > 0, `${ascending[index]} > ${ascending[index - 1]}`);
    assert.ok(compareVersions(ascending[index - 1], ascending[index]) < 0);
  }
  assert.equal(compareVersions("0.1.0-dev.1", "0.1.0-dev.1"), 0);
  assert.ok(compareVersions("0.1.0-1", "0.1.0-a") < 0);
  assert.ok(compareVersions("0.1.0-dev", "0.1.0-dev.1") < 0);
  assert.ok(compareVersions("0.1.0-dev.99999999999999999999", "0.1.0-dev.99999999999999999998") > 0);
  assert.throws(() => compareVersions("0.1", "0.1.0"), /Cannot compare/);
});

test("stable selection ignores prereleases published later and picks the highest version", () => {
  const { latestBuild } = updater();
  const older = release("0.1.0", "2026-11-18T09:00:00Z");
  const newer = release("0.2.0", "2026-11-16T09:00:00Z");
  const development = release("0.3.0-dev.1", "2026-11-19T09:00:00Z");
  const flagged = release("0.4.0", "2026-11-20T09:00:00Z", true);
  assert.equal(latestBuild([older, newer, development, flagged]).version, "0.2.0");
});

test("opted-in selection uses the highest version, not the latest publication date", () => {
  const { latestBuild } = updater();
  const old = release("0.2.0-dev.9.1.shaaaaaaa", "2026-11-19T09:00:00Z");
  const newest = release("0.2.0-dev.10.1.shabbbbbbb", "2026-11-16T09:00:00Z");
  const stable = release("0.1.0", "2026-11-20T09:00:00Z");
  const draft = { ...release("0.3.0-dev.1", "2026-11-18T09:00:00Z"), draft: true };
  const sourceOnly = { ...release("0.3.0-dev.2", "2026-11-19T09:00:00Z"), assets: [] };
  assert.equal(latestBuild([old, stable, newest, draft, sourceOnly], true).version, "0.2.0-dev.10.1.shabbbbbbb");
  assert.equal(latestBuild([old, stable], true).version, "0.2.0-dev.9.1.shaaaaaaa");
  assert.equal(latestBuild([release("0.2.0-dev.1"), release("0.2.0")], true).version, "0.2.0");
});

test("invalid responses and assets outside the expected repository fail closed", () => {
  const check = updater();
  const foreign = release("0.2.0");
  foreign.assets[0].browser_download_url = "https://example.com/update.zip";
  for (const prereleases of [false, true]) {
    for (const data of [null, {}, [], [foreign], [null, { tag_name: "../bad" }], [release("01.2.3")]]) {
      assert.throws(() => check.latestBuild(data, prereleases), /invalid release list|No installable/);
    }
  }
  assert.throws(() => check.latestBuild([release("0.2.0-dev.1")]), /No installable stable/);
});

test("stable checks read only the latest stable release, however many development builds follow it", async () => {
  const check = updater({ list: new Array(100).fill(release("0.9.0-dev.1")), stable: release("0.2.0") });
  const message = await check.requestLatestBuild();
  assert.deepEqual(check.requests.map(([url]) => url), [latestURL]);
  assert.deepEqual(Array.from(check.installs[0]).slice(2, 4), ["WireGuard", "0.2.0"]);
  assert.match(message, /Confirm 0.2.0 .*installation dialog/);
});

test("opted-in checks read the newest page and the latest stable release, which may not be on it", async () => {
  const check = updater({ stable: release("0.2.0"), list: [release("0.1.1-dev.9"), release("0.1.1-dev.8")] });
  await check.requestLatestBuild(true);
  assert.deepEqual(check.requests.map(([url]) => url).sort(), [latestURL, listURL].sort());
  assert.equal(check.installs[0][3], "0.2.0");

  const development = updater({ stable: release("0.1.0"), list: [release("0.2.0-dev.9"), release("0.1.0")] });
  await development.requestLatestBuild(true);
  assert.equal(development.installs[0][3], "0.2.0-dev.9");
});

test("a repository without a stable release reports it, or still offers development builds when opted in", async () => {
  const stableOnly = updater({ stable: null });
  await assert.rejects(stableOnly.requestLatestBuild(), /No installable stable WireGuard release/);
  assert.equal(stableOnly.installs.length, 0);

  const optedIn = updater({ stable: null, list: [release("0.1.0-dev.5")], version: "0.1.0-dev.4" });
  await optedIn.requestLatestBuild(true);
  assert.equal(optedIn.installs[0][3], "0.1.0-dev.5");
});

test("a stable install is not offered an older stable release that was published later", async () => {
  const check = updater({ version: "0.2.0", stable: release("0.1.0", "2026-11-20T09:00:00Z") });
  assert.match(await check.requestLatestBuild(), /0\.2\.0 is newer than the latest stable release \(0\.1\.0\).*never downgrade/);
  assert.equal(check.installs.length, 0);
});

test("a later-published development prerelease is not installed over an equal stable version", async () => {
  const check = updater({
    version: "0.2.0", stable: release("0.2.0"),
    list: [release("0.1.0-dev.42", "2026-11-21T09:00:00Z"), release("0.2.0")],
  });
  assert.match(await check.requestLatestBuild(), /Already running the latest/);
  assert.match(await check.requestLatestBuild(true), /Already running the latest/);
  assert.equal(check.installs.length, 0);
});

test("a development build never moves to an older stable release but upgrades to a newer one", async () => {
  const newer = updater({ version: "0.2.0-dev.7", stable: release("0.1.0") });
  assert.match(await newer.requestLatestBuild(), /newer than the latest stable release \(0\.1\.0\)/);
  assert.equal(newer.installs.length, 0);

  const released = updater({ version: "0.1.0-dev.7", stable: release("0.1.0") });
  await released.requestLatestBuild();
  assert.equal(released.installs[0][3], "0.1.0");

  const optedIn = updater({ version: "0.2.0-dev.7", list: [release("0.1.0"), release("0.2.0-dev.3")], stable: release("0.1.0") });
  assert.match(await optedIn.requestLatestBuild(true), /newer than the latest available release \(0\.2\.0-dev\.3\)/);
  assert.equal(optedIn.installs.length, 0);
});

test("update requests Decky's native confirmation with the exact URL, version, digest and UPDATE type", async () => {
  const check = updater({ version: "0.1.0-dev.1" });
  const message = await check.requestLatestBuild(true);
  assert.equal(check.requests[0][1].headers.Accept, "application/vnd.github+json");
  assert.equal(check.installs.length, 1);
  assert.deepEqual(Array.from(check.installs[0]), [
    "utilities/install_plugin",
    release("0.2.0-dev.42.1.shaabcdef0").assets[0].browser_download_url,
    "WireGuard", "0.2.0-dev.42.1.shaabcdef0", hash, 2,
  ]);
  assert.match(message, /Confirm .*installation dialog/);
});

test("the installed build is not reinstalled", async () => {
  const check = updater({ version: "0.2.0-dev.42.1.shaabcdef0" });
  assert.match(await check.requestLatestBuild(true), /Already running the latest/);
  assert.equal(check.installs.length, 0);
});

test("an installed version that cannot be ordered never installs", async () => {
  const check = updater({ version: "test" });
  await assert.rejects(check.requestLatestBuild(), /Cannot compare versions/);
  assert.equal(check.installs.length, 0);
});

test("a missing or malformed digest never installs or falls back to an older build", async () => {
  for (const prereleases of [false, true]) {
    for (const digest of [null, undefined, "sha256:bad", `sha1:${hash}`]) {
      const newest = release("0.2.0");
      newest.assets[0].digest = digest;
      const check = updater({ stable: newest, list: [release("0.1.1"), newest], version: "0.1.0" });
      await assert.rejects(check.requestLatestBuild(prereleases), /no SHA-256 digest/);
      assert.equal(check.installs.length, 0);
    }
  }
});

test("GitHub rate limits, network errors and invalid JSON are surfaced without installation", async () => {
  for (const prereleases of [false, true]) {
    const limited = updater();
    limited.response.ok = false;
    limited.response.status = 403;
    await assert.rejects(limited.requestLatestBuild(prereleases), /HTTP 403/);
    assert.equal(limited.installs.length, 0);
    for (const error of [new Error("Offline"), new SyntaxError("Invalid JSON")]) {
      const check = updater();
      check.response.failure = error;
      await assert.rejects(check.requestLatestBuild(prereleases), (failure) => failure.message === error.message);
      assert.equal(check.installs.length, 0);
    }
  }
  const invalid = updater({ list: {} });
  await assert.rejects(invalid.requestLatestBuild(true), /invalid release list/);
});

test("timeout prevents a late GitHub response from triggering installation", async () => {
  const check = updater({ version: "0.1.0-dev.1" });
  let finish;
  check.response.stable = new Promise((resolve) => { finish = resolve; });
  const pending = check.requestLatestBuild();
  await flush();
  check.expire();
  await assert.rejects(pending, /timed out/);
  finish(release("0.2.0"));
  await flush();
  assert.equal(check.installs.length, 0);
});

test("unavailable installer fails before fetching and native installer failures propagate", async () => {
  const unavailable = updater();
  delete unavailable.context.DeckyBackend;
  await assert.rejects(unavailable.requestLatestBuild(), /installer is unavailable/);
  assert.equal(unavailable.requests.length, 0);
  const broken = updater({ version: "0.0.9" });
  broken.context.DeckyBackend.call = async () => { throw new Error("Installer failed"); };
  await assert.rejects(broken.requestLatestBuild(), /Installer failed/);
});

const startup = 30_000;
const change = 2_000;
const interval = 12 * 60 * 60 * 1000;
const retry = 10 * 60 * 1000;

test("automatic checks do nothing unless enabled, and wait for the loaded settings", async () => {
  const off = updater({ version: "0.0.9" });
  off.startUpdateMonitor();
  assert.equal(off.loads(), 1);
  assert.deepEqual(off.pending(), []);
  assert.equal(off.requests.length, 0);

  const unloaded = updater({ version: "0.0.9", settings: { loaded: false, autoUpdateCheck: true } });
  unloaded.startUpdateMonitor();
  assert.deepEqual(unloaded.pending(), []);
  unloaded.state.loaded = true;
  unloaded.notify();
  assert.deepEqual(unloaded.pending(), [startup]);
});

test("an automatic check toasts once per new version, never installs, and opens the Decky panel when clicked", async () => {
  const check = updater({ version: "0.1.0", stable: release("0.2.0"), settings: { autoUpdateCheck: true } });
  check.startUpdateMonitor();
  assert.deepEqual(check.pending(), [startup]);
  await check.fire(startup);
  assert.deepEqual(check.requests.map(([url]) => url), [latestURL]);
  assert.equal(check.toasts.length, 1);
  assert.match(check.toasts[0].body, /0\.2\.0/);
  check.toasts[0].onClick();
  assert.deepEqual(check.quickAccess, [7]);
  assert.equal(check.installs.length, 0);

  assert.deepEqual(check.pending(), [interval]);
  await check.fire(interval);
  assert.equal(check.toasts.length, 1);

  check.response.stable = release("0.3.0");
  await check.fire(interval);
  assert.equal(check.toasts.length, 2);
  assert.match(check.toasts[1].body, /0\.3\.0/);
});

test("no prompt appears when the installed build is current or newer", async () => {
  for (const version of ["0.2.0", "0.3.0"]) {
    const check = updater({ version, stable: release("0.2.0"), settings: { autoUpdateCheck: true } });
    check.startUpdateMonitor();
    await check.fire(startup);
    assert.equal(check.toasts.length, 0);
    assert.deepEqual(check.errors, []);
    assert.deepEqual(check.pending(), [interval]);
  }
});

test("automatic checks follow the development preference and the channel never leaks between settings", async () => {
  const check = updater({
    version: "0.1.0", stable: release("0.1.0"), list: [release("0.2.0-dev.5"), release("0.1.0")],
    settings: { autoUpdateCheck: true },
  });
  check.startUpdateMonitor();
  await check.fire(startup);
  assert.equal(check.toasts.length, 0);

  check.state.includePrereleases = true;
  check.notify();
  assert.deepEqual(check.pending(), [change]);
  await check.fire(change);
  assert.deepEqual(check.requests.slice(1).map(([url]) => url).sort(), [latestURL, listURL].sort());
  assert.equal(check.toasts.length, 1);
  assert.match(check.toasts[0].body, /0\.2\.0-dev\.5/);

  check.state.includePrereleases = false;
  check.notify();
  assert.deepEqual(check.pending(), [change]);
});

test("unrelated settings updates keep the schedule; disabling cancels it", async () => {
  const check = updater({ settings: { autoUpdateCheck: true } });
  check.startUpdateMonitor();
  const scheduled = check.timers.length;
  check.state.saving = true;
  check.notify();
  check.state.showAdvanced = true;
  check.notify();
  assert.equal(check.timers.length, scheduled);
  assert.deepEqual(check.pending(), [startup]);

  check.state.autoUpdateCheck = false;
  check.notify();
  assert.deepEqual(check.pending(), []);
  assert.equal(check.requests.length, 0);
});

test("a result that arrives after the setting changed or the monitor stopped is discarded", async () => {
  const check = updater({ version: "0.1.0", settings: { autoUpdateCheck: true } });
  let finish;
  check.response.stable = new Promise((resolve) => { finish = resolve; });
  const stop = check.startUpdateMonitor();
  check.fire(startup);
  await flush();
  check.state.autoUpdateCheck = false;
  check.notify();
  finish(release("0.2.0"));
  await flush();
  assert.equal(check.toasts.length, 0);
  assert.deepEqual(check.pending(), []);

  check.state.autoUpdateCheck = true;
  check.response.stable = release("0.2.0");
  check.notify();
  const pending = check.fire(change);
  stop();
  await pending;
  assert.equal(check.toasts.length, 0);
  assert.deepEqual(check.pending(), []);
});

test("failed automatic checks are logged quietly and retried sooner", async () => {
  const check = updater({ version: "0.1.0", settings: { autoUpdateCheck: true } });
  check.response.failure = new Error("Offline");
  check.startUpdateMonitor();
  await check.fire(startup);
  assert.equal(check.errors.length, 1);
  assert.match(check.errors[0], /^WireGuard update check: .*Offline$/);
  assert.equal(check.toasts.length, 0);
  assert.deepEqual(check.pending(), [retry]);
  check.response.failure = null;
  check.response.stable = release("0.2.0");
  await check.fire(retry);
  assert.equal(check.toasts.length, 1);
  assert.deepEqual(check.pending(), [interval]);
});

test("the update button reports the development subscription and how to leave it", () => {
  const description = (settings, version = "0.1.0") => {
    const check = updater({ version, settings });
    const row = check.UpdateButton();
    return row.props.children[0].props.description;
  };
  assert.equal(description({ loaded: true }), "Installed: 0.1.0.");
  assert.equal(
    description({ loaded: true, includePrereleases: true, showAdvanced: true }),
    "Installed: 0.1.0. You are subscribed to development updates.",
  );
  assert.equal(
    description({ loaded: true, includePrereleases: true, showAdvanced: false }),
    "Installed: 0.1.0. You are subscribed to development updates. " +
      "To unsubscribe, show advanced settings and turn off development updates.",
  );
  assert.match(description({ loaded: false, error: "Read failed", includePrereleases: true }), /only stable releases/);
  assert.equal(description({ loaded: false, loading: true }), "Installed: 0.1.0.");
});

test("an automatically found update is shown in settings until the monitor stops", async () => {
  const check = updater({ version: "0.1.0", stable: release("0.2.0"), settings: { autoUpdateCheck: true } });
  const stop = check.startUpdateMonitor();
  await check.fire(startup);
  const status = () => check.UpdateButton().props.children[1];
  assert.equal(status().props.children.join(""), "Update available: 0.2.0.");
  stop();
  assert.equal(status(), null);
});
