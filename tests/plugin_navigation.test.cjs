const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const ts = require("typescript");

function compile(file) {
  return ts.transpileModule(readFileSync(resolve(__dirname, "../src", file), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
}

const navigationCompiled = compile("plugin-navigation.ts");
const indexCompiled = compile("index.tsx");
const flush = () => new Promise((resolve) => setImmediate(resolve));
const profile = {
  uuid: "home", name: "Home", device: "", state: "disconnected",
  handshake: "inactive", handshake_error: null,
};

function plugin(profiles) {
  let hooks = [];
  let cursor = 0;
  let effects = [];
  const subscriptions = [];
  const element = (type, props) => ({ type, props });
  const context = {
    exports: {},
    App: { BHasCurrentUser: () => true, GetServicesInitialized: () => true },
    window: { setInterval: () => 1, clearInterval: () => {} },
    require: (name) => {
      if (name === "react") return {
        useState: (initial) => {
          const index = cursor++;
          if (!(index in hooks)) hooks[index] = typeof initial === "function" ? initial() : initial;
          return [hooks[index], (update) => {
            hooks[index] = typeof update === "function" ? update(hooks[index]) : update;
          }];
        },
        useRef: (initial) => {
          const index = cursor++;
          return hooks[index] ??= { current: initial };
        },
        useCallback: (callback) => callback,
        useEffect: (effect) => effects.push(effect),
        useSyncExternalStore: (subscribe, snapshot) => {
          subscriptions.push(subscribe);
          return snapshot();
        },
      };
      if (name === "react/jsx-runtime") return { jsx: element, jsxs: element };
      if (name === "@decky/api") return {
        definePlugin: (factory) => factory,
        routerHook: { addRoute: () => {}, removeRoute: () => {} },
        callable: (route) => async () => {
          if (route === "get_profiles") return { success: true, profiles };
          if (route === "get_startup_settings" || route === "set_steam_readiness") {
            return { success: true };
          }
          assert.fail(`Unexpected backend call: ${route}`);
        },
      };
      if (name === "@decky/ui") return {
        staticClasses: { Title: "title" }, Navigation: { NavigateBack: () => {}, OpenQuickAccessMenu: () => {} },
        QuickAccessTab: { Decky: 999 }, PanelSection: "PanelSection",
      };
      if (name === "./plugin-navigation") return navigation.exports;
      if (name === "./config-page" || name === "./updater" || name === "react-icons/fa") return {};
      throw new Error(`Unexpected module: ${name}`);
    },
  };
  const navigation = { exports: {}, require: context.require };
  runInNewContext(navigationCompiled, navigation);
  runInNewContext(indexCompiled, context);
  const content = context.exports.default().content.type;
  return {
    navigation: navigation.exports,
    subscribe: (listener) => subscriptions.at(-1)(listener),
    render: () => {
      cursor = 0;
      return content();
    },
    mount: async () => {
      hooks = [];
      effects = [];
      cursor = 0;
      content();
      effects.forEach((effect) => effect());
      await flush();
    },
  };
}

test("returning to the plugin retains the edited connection across panel remounts", async () => {
  const panel = plugin([profile]);
  panel.navigation.returnToPlugin("home");
  await panel.mount();
  assert.equal(panel.render().props.title, "Manage connection");
  await panel.mount();
  assert.equal(panel.render().props.title, "Manage connection");
  assert.equal(panel.navigation.useSelectedConnection()[0], "home");
});

test("a missing connection falls back to the plugin landing page", async () => {
  const panel = plugin([]);
  panel.navigation.returnToPlugin("deleted");
  await panel.mount();
  assert.equal(panel.render().props.title, "WireGuard connections");
  assert.equal(panel.navigation.useSelectedConnection()[0], null);
});

test("returning without a saved connection opens the landing page and notifies a mounted panel", () => {
  const panel = plugin([profile]);
  panel.navigation.returnToPlugin("home");
  panel.render();
  let updates = 0;
  const unsubscribe = panel.subscribe(() => { updates++; });
  panel.navigation.returnToPlugin(null);
  assert.equal(updates, 1);
  assert.equal(panel.render().props.title, "WireGuard connections");
  unsubscribe();
  panel.navigation.returnToPlugin("home");
  assert.equal(updates, 1);
});
