const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const ts = require("typescript");

const source = readFileSync(resolve(__dirname, "../src/index.tsx"), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
}).outputText;

const configPage = () => null;
const flush = () => new Promise((resolve) => setImmediate(resolve));

function monitor(app) {
  const reports = [];
  const errors = [];
  const routes = new Set();
  let interval;
  const context = {
    exports: {},
    App: app,
    console: { error: (...args) => errors.push(args) },
    window: {
      setInterval: (callback) => { interval = callback; return 1; },
      clearInterval: () => { interval = undefined; },
    },
    require: (name) => {
      if (name === "@decky/api") return {
        definePlugin: (factory) => factory,
        routerHook: {
          addRoute: (path, component) => {
            assert.equal(component, configPage);
            routes.add(path);
          },
          removeRoute: (path) => routes.delete(path),
        },
        callable: (route) => async (...args) => {
          assert.equal(route, "set_steam_readiness");
          reports.push(args);
          return { success: true };
        },
      };
      if (name === "@decky/ui") return { staticClasses: { Title: "title" } };
      if (name === "react/jsx-runtime") return { jsx: () => ({}), jsxs: () => ({}) };
      if (name === "./config-page") return { CONFIG_ROUTE: "/config/:uuid", ConfigPage: configPage };
      if (name === "./plugin-navigation") return {};
      if (name === "./ui-settings") return {};
      if (name === "./updater") return { UpdateButton: () => null, startUpdateMonitor: () => () => {} };
      if (name === "react" || name === "react-icons/fa") return {};
      throw new Error(`Unexpected module: ${name}`);
    },
  };
  runInNewContext(compiled, context);
  const plugin = context.exports.default();
  return {
    reports, errors, context, routes,
    tick: async () => { interval?.(); await flush(); },
    stop: async () => { plugin.onDismount(); await flush(); },
  };
}

for (const offline of [false, true]) {
  test(`completed ${offline ? "offline" : "online"} login uses Steam's predicate, not a numeric enum`, async () => {
    const app = {
      BHasCurrentUser: () => true,
      GetServicesInitialized: () => true,
      BIsOfflineMode: () => offline,
      m_eLoginState: 1,
    };
    const check = monitor(app);
    try {
      await flush();
      assert.equal(check.reports.at(-1)[0], true);
      delete app.m_eLoginState;
      await check.tick();
      assert.equal(check.reports.at(-1)[0], true);
      assert.equal(check.reports.at(-1)[1], null);
    } finally {
      await check.stop();
    }
  });
}

test("unfinished login or UI initialization never grants readiness, even with numeric state 7", async () => {
  let hasUser = false;
  let initialized = false;
  const check = monitor({
    m_eLoginState: 7,
    BHasCurrentUser: () => hasUser,
    GetServicesInitialized: () => initialized,
  });
  try {
    await flush();
    assert.equal(check.reports.at(-1)[0], false);
    hasUser = true;
    await check.tick();
    assert.equal(check.reports.at(-1)[0], false);
    initialized = true;
    await check.tick();
    assert.equal(check.reports.at(-1)[0], true);
    hasUser = false;
    await check.tick();
    assert.equal(check.reports.at(-1)[0], false);
  } finally {
    await check.stop();
  }
});

test("missing and failing Steam APIs fail closed, report the error, and recover", async () => {
  const check = monitor(undefined);
  try {
    await flush();
    assert.equal(check.reports.at(-1)[0], false);
    assert.match(check.reports.at(-1)[1], /unavailable/);
    check.context.App = {
      BHasCurrentUser: () => { throw new Error("Steam API failure"); },
      GetServicesInitialized: () => true,
    };
    await check.tick();
    assert.equal(check.reports.at(-1)[0], false);
    assert.match(check.reports.at(-1)[1], /Steam API failure/);
    check.context.App.BHasCurrentUser = () => true;
    await check.tick();
    assert.equal(check.reports.at(-1)[0], true);
    assert.equal(check.reports.at(-1)[1], null);
  } finally {
    await check.stop();
  }
});

test("monitor works without mounting the panel; unloading revokes readiness and the editor route", async () => {
  const check = monitor({
    BHasCurrentUser: () => true,
    GetServicesInitialized: () => true,
  });
  await flush();
  assert.equal(check.reports.at(-1)[0], true);
  assert.deepEqual([...check.routes], ["/config/:uuid"]);
  await check.stop();
  assert.equal(check.reports.at(-1)[0], false);
  assert.equal(check.routes.size, 0);
  const count = check.reports.length;
  await check.tick();
  assert.equal(check.reports.length, count);
  assert.deepEqual(check.errors, []);
});
