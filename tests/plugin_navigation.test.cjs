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
const settingsCompiled = compile("ui-settings.ts");
const indexCompiled = compile("index.tsx");
const flush = () => new Promise((resolve) => setImmediate(resolve));
const profile = {
  uuid: "home", name: "Home", device: "", state: "disconnected",
  handshake: "inactive", handshake_error: null,
};

function plugin(profiles, backend, options = {}) {
  let hooks = [];
  let cursor = 0;
  let effects = [];
  let pluginExits = 0;
  let showAdvanced = options.advanced ?? false;
  const navigations = [];
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
        callable: (route) => async (...args) => {
          if (route === "get_profiles") return { success: true, profiles };
          if (route === "get_ui_settings" || route === "set_ui_settings") {
            if (options.uiBackend) return options.uiBackend(route, ...args);
            if (route === "set_ui_settings") showAdvanced = args[0];
            return { success: true, show_advanced_settings: showAdvanced };
          }
          if (backend && route !== "set_steam_readiness") return backend(route, ...args);
          if (route === "get_startup_settings" || route === "set_steam_readiness") {
            return { success: true };
          }
          assert.fail(`Unexpected backend call: ${route}`);
        },
      };
      if (name === "@decky/ui") return {
        staticClasses: { Title: "title" },
        Navigation: {
          NavigateBack: () => {}, OpenQuickAccessMenu: () => {},
          Navigate: (path) => navigations.push(path), CloseSideMenus: () => navigations.push("close"),
        },
        QuickAccessTab: { Decky: 999 }, PanelSection: "PanelSection", Focusable: "Focusable",
        ButtonItem: "ButtonItem", ToggleField: "ToggleField",
      };
      if (name === "./plugin-navigation") return navigation.exports;
      if (name === "./ui-settings") return uiSettings.exports;
      if (name === "./config-page") return { configPath: (uuid) => `/config/${uuid}` };
      if (name === "./updater") return { UpdateButton: "UpdateButton" };
      if (name === "react-icons/fa") return {};
      throw new Error(`Unexpected module: ${name}`);
    },
  };
  const navigation = { exports: {}, require: context.require };
  const uiSettings = { exports: {}, require: context.require };
  runInNewContext(navigationCompiled, navigation);
  runInNewContext(settingsCompiled, uiSettings);
  runInNewContext(indexCompiled, context);
  const content = context.exports.default().content.type;
  return {
    navigation: navigation.exports,
    navigations,
    subscribe: (listener) => subscriptions.at(-1)(listener),
    subscribeToSettings: (listener) => {
      uiSettings.exports.useUISettings();
      return subscriptions.at(-1)(listener);
    },
    render: () => {
      cursor = 0;
      return content();
    },
    cancel: () => {
      cursor = 0;
      const view = content();
      const handler = view.props.onCancelButton;
      if (handler) {
        handler({ preventDefault() {}, stopPropagation() {} });
      } else {
        // Steam dispatches B to the nearest registered handler, not every ancestor.
        pluginExits++;
      }
    },
    get pluginExits() { return pluginExits; },
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
  assert.equal(panel.render().props.children.props.title, "Manage connection");
  await panel.mount();
  assert.equal(panel.render().props.children.props.title, "Manage connection");
  assert.equal(panel.navigation.useSelectedConnection()[0], "home");
});

test("a missing connection falls back to the plugin landing page", async () => {
  const panel = plugin([]);
  panel.navigation.returnToPlugin("deleted");
  await panel.mount();
  assert.equal(panel.render().props.children.props.title, "Connections");
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
  assert.equal(panel.render().props.children.props.title, "Connections");
  unsubscribe();
  panel.navigation.returnToPlugin("home");
  assert.equal(updates, 1);
});

test("B returns from connection settings to the list without closing the sidebar", async () => {
  const panel = plugin([profile]);
  panel.navigation.returnToPlugin("home");
  await panel.mount();
  const event = {
    preventDefault: () => { event.prevented = true; },
    stopPropagation: () => { event.stopped = true; },
  };
  const view = panel.render();
  assert.equal(view.type, "Focusable");
  view.props.onCancelButton(event);
  assert.equal(event.prevented, true);
  assert.equal(event.stopped, true);
  assert.equal(panel.navigation.useSelectedConnection()[0], null);
  assert.equal(panel.render().props.children.props.title, "Connections");

  panel.cancel();
  assert.equal(panel.pluginExits, 1);
});

for (const profiles of [[], [profile]]) {
  test(`B exits the plugin from the ${profiles.length ? "populated" : "empty"} connection list`, async () => {
    const panel = plugin(profiles);
    panel.cancel();
    assert.equal(panel.pluginExits, 1, "B must exit while profiles are still loading");
    await panel.mount();
    panel.cancel();
    assert.equal(panel.pluginExits, 2, "B must reach Decky's leave-plugin handler");
  });
}

test("B exits after a deleted connection falls back to the list", async () => {
  const panel = plugin([]);
  panel.navigation.returnToPlugin("deleted");
  await panel.mount();
  panel.cancel();
  assert.equal(panel.pluginExits, 1);
});

test("the Back button returns from connection settings to the list", async () => {
  const panel = plugin([profile]);
  panel.navigation.returnToPlugin("home");
  await panel.mount();
  const section = panel.render().props.children;
  const backRow = section.props.children[1];
  assert.equal(backRow.props.children.type, "ButtonItem");
  assert.equal(backRow.props.children.props.children, "Back to connections");
  backRow.props.children.props.onClick();
  assert.equal(panel.navigation.useSelectedConnection()[0], null);
  assert.equal(panel.render().props.children.props.title, "Connections");
});

function elementsIn(node) {
  const elements = [];
  function collect(child) {
    if (!child || typeof child !== "object") return;
    elements.push(child);
    const children = child.props?.children;
    (Array.isArray(children) ? children : [children]).forEach(collect);
  }
  collect(node);
  return elements;
}

test("the new connection button opens the configuration page", async () => {
  const panel = plugin([]);
  await panel.mount();
  const add = elementsIn(panel.render()).find((node) =>
    node.type === "ButtonItem" && node.props.children === "Add connection");
  assert.ok(add);
  add.props.onClick();
  assert.deepEqual(panel.navigations, ["/config/new", "close"]);
});

for (const back of ["button", "controller"]) {
  test(`settings contains logging and update controls; ${back} returns to connections`, async () => {
    const panel = plugin([profile]);
    await panel.mount();
    const list = elementsIn(panel.render());
    const settings = list.find((node) => node.type === "ButtonItem" && node.props.children === "Settings");
    assert.ok(settings);
    assert.equal(list.some((node) => node.type === "UpdateButton" || node.type?.name === "LoggingControls"), false);
    settings.props.onClick();

    const view = panel.render();
    assert.equal(view.props.children.props.title, "Settings");
    const elements = elementsIn(view);
    assert.ok(elements.some((node) => node.type === "UpdateButton"));
    assert.ok(elements.some((node) => node.type?.name === "LoggingControls"));
    assert.equal(elements.some((node) => node.type === "ButtonItem" && node.props.children === "Add connection"), false);

    if (back === "button") {
      elements.find((node) => node.type === "ButtonItem" && node.props.children === "Back to connections").props.onClick();
    } else {
      const event = {
        preventDefault: () => { event.prevented = true; },
        stopPropagation: () => { event.stopped = true; },
      };
      view.props.onCancelButton(event);
      assert.equal(event.prevented, true);
      assert.equal(event.stopped, true);
    }
    assert.equal(panel.render().props.children.props.title, "Connections");
    panel.cancel();
    assert.equal(panel.pluginExits, 1);
  });
}

function toggles(panel) {
  const fields = {};
  function collect(node) {
    if (!node || typeof node !== "object") return;
    if (node.type === "ToggleField") fields[node.props.label] = node.props;
    const children = node.props?.children;
    (Array.isArray(children) ? children : [children]).forEach(collect);
  }
  collect(panel.render());
  return fields;
}

for (const mode of ["off", "on_boot", "after_boot"]) {
  for (const advanced of [false, true]) {
    test(`startup wait switches require advanced settings and Smart connect mode (${mode}, ${advanced})`, async () => {
      const panel = plugin([profile], (route) => {
        assert.equal(route, "get_startup_settings");
        return {
          success: true, on_boot: mode === "on_boot", after_boot: mode === "after_boot",
          wait_for_steam: true, wait_for_internet: true, waiting: null,
        };
      }, { advanced });
      panel.navigation.returnToPlugin("home");
      await panel.mount();
      const fields = toggles(panel);
      assert.ok(fields["Connect during boot"]);
      assert.ok(fields["Smart connect"]);
      for (const label of ["Wait for Steam login", "Wait for internet"]) {
        assert.equal(fields[label] !== undefined, advanced && mode === "after_boot");
        if (advanced && mode === "after_boot") {
          assert.equal(fields[label].checked, true);
          assert.equal(fields[label].disabled, false);
        }
      }
    });
  }
}

test("startup wait choices survive hiding, showing, and remounting the panel", async () => {
  const settings = {
    on_boot: false, after_boot: true,
    wait_for_steam: true, wait_for_internet: true, waiting: null,
  };
  const panel = plugin([profile], (route, uuid, first, second) => {
    assert.equal(uuid, "home");
    if (route === "get_startup_settings") return { success: true, ...settings };
    if (route === "set_startup_requirements") {
      settings.wait_for_steam = first;
      settings.wait_for_internet = second;
    } else {
      assert.equal(route, "set_startup");
      settings.on_boot = first === "on_boot";
      settings.after_boot = first === "after_boot";
    }
    return { success: true };
  }, { advanced: true });
  panel.navigation.returnToPlugin("home");
  await panel.mount();
  for (const label of ["Wait for Steam login", "Wait for internet"]) {
    toggles(panel)[label].onChange(false);
    await flush();
    assert.equal(toggles(panel)[label].checked, false);
  }
  toggles(panel)["Smart connect"].onChange(false);
  await flush();
  assert.equal(toggles(panel)["Wait for Steam login"], undefined);
  assert.equal(toggles(panel)["Wait for internet"], undefined);
  toggles(panel)["Smart connect"].onChange(true);
  await flush();
  await panel.mount();
  assert.equal(toggles(panel)["Wait for Steam login"].checked, false);
  assert.equal(toggles(panel)["Wait for internet"].checked, false);
});

test("the settings toggle hides wait switches without changing their saved values", async () => {
  const startup = {
    on_boot: false, after_boot: true,
    wait_for_steam: false, wait_for_internet: true, waiting: null,
  };
  const calls = [];
  let showAdvanced = false;
  const uiBackend = (route, enabled) => {
    if (route === "set_ui_settings") showAdvanced = enabled;
    return { success: true, show_advanced_settings: showAdvanced };
  };
  const panel = plugin([profile], (route) => {
    calls.push(route);
    assert.equal(route, "get_startup_settings");
    return { success: true, ...startup };
  }, { uiBackend });
  await panel.mount();

  const openSettings = () => {
    elementsIn(panel.render()).find((node) =>
      node.type === "ButtonItem" && node.props.children === "Settings").props.onClick();
  };
  const closeSettings = () => {
    elementsIn(panel.render()).find((node) =>
      node.type === "ButtonItem" && node.props.children === "Back to connections").props.onClick();
  };
  const openConnection = async () => {
    panel.navigation.returnToPlugin("home");
    await panel.mount();
  };
  const openList = async () => {
    panel.navigation.returnToPlugin(null);
    await panel.mount();
  };

  openSettings();
  assert.equal(toggles(panel)["Show advanced settings"].checked, false);
  toggles(panel)["Show advanced settings"].onChange(true);
  await flush();
  assert.equal(toggles(panel)["Show advanced settings"].checked, true);
  closeSettings();
  await openConnection();
  assert.equal(toggles(panel)["Wait for Steam login"].checked, false);
  assert.equal(toggles(panel)["Wait for internet"].checked, true);

  await openList();
  openSettings();
  toggles(panel)["Show advanced settings"].onChange(false);
  await flush();
  closeSettings();
  await openConnection();
  assert.equal(toggles(panel)["Wait for Steam login"], undefined);
  assert.equal(toggles(panel)["Wait for internet"], undefined);
  assert.equal(toggles(panel)["Smart connect"].checked, true);

  await openList();
  openSettings();
  toggles(panel)["Show advanced settings"].onChange(true);
  await flush();
  closeSettings();
  await openConnection();
  assert.equal(toggles(panel)["Wait for Steam login"].checked, false);
  assert.equal(toggles(panel)["Wait for internet"].checked, true);
  assert.ok(calls.every((route) => route === "get_startup_settings"));

  const reloaded = plugin([profile], undefined, { uiBackend });
  await reloaded.mount();
  elementsIn(reloaded.render()).find((node) =>
    node.type === "ButtonItem" && node.props.children === "Settings").props.onClick();
  assert.equal(toggles(reloaded)["Show advanced settings"].checked, true);
});

test("advanced preference updates notify all screens and serialize pending saves", async () => {
  let finishLoad;
  let finishSave;
  let reads = 0;
  let writes = 0;
  const panel = plugin([], undefined, {
    uiBackend: (route) => {
      if (route === "get_ui_settings") {
        reads++;
        return new Promise((resolve) => { finishLoad = resolve; });
      }
      writes++;
      return new Promise((resolve) => { finishSave = resolve; });
    },
  });
  await panel.mount();
  await panel.mount();
  assert.equal(reads, 1);
  elementsIn(panel.render()).find((node) =>
    node.type === "ButtonItem" && node.props.children === "Settings").props.onClick();
  assert.equal(toggles(panel)["Show advanced settings"].disabled, true);
  finishLoad({ success: true, show_advanced_settings: false });
  await flush();
  let firstUpdates = 0;
  let secondUpdates = 0;
  const unsubscribeFirst = panel.subscribeToSettings(() => { firstUpdates++; });
  const unsubscribeSecond = panel.subscribeToSettings(() => { secondUpdates++; });
  const toggle = toggles(panel)["Show advanced settings"];
  toggle.onChange(true);
  toggle.onChange(false);
  assert.equal(writes, 1);
  assert.equal(toggles(panel)["Show advanced settings"].checked, false);
  assert.equal(toggles(panel)["Show advanced settings"].disabled, true);
  finishSave({ success: true, show_advanced_settings: true });
  await flush();
  assert.equal(toggles(panel)["Show advanced settings"].checked, true);
  assert.equal(toggles(panel)["Show advanced settings"].disabled, false);
  assert.equal(firstUpdates, 2);
  assert.equal(secondUpdates, 2);
  unsubscribeFirst();
  unsubscribeSecond();
});

test("advanced preference errors are visible, retryable, and do not change the toggle", async () => {
  let loadFails = true;
  let saveFails = true;
  const panel = plugin([], undefined, {
    uiBackend: (route) => {
      if (route === "get_ui_settings") {
        return loadFails ? { success: false, error: "Read failed" }
          : { success: true, show_advanced_settings: false };
      }
      return saveFails ? { success: false, error: "Write failed" }
        : { success: true, show_advanced_settings: true };
    },
  });
  await panel.mount();
  elementsIn(panel.render()).find((node) =>
    node.type === "ButtonItem" && node.props.children === "Settings").props.onClick();
  assert.equal(toggles(panel)["Show advanced settings"].disabled, true);
  assert.ok(elementsIn(panel.render()).some((node) =>
    node.props?.role === "alert" && JSON.stringify(node.props.children).includes("Read failed")));
  loadFails = false;
  elementsIn(panel.render()).find((node) =>
    node.type === "ButtonItem" && node.props.children === "Retry loading settings").props.onClick();
  await flush();
  assert.equal(toggles(panel)["Show advanced settings"].disabled, false);
  toggles(panel)["Show advanced settings"].onChange(true);
  await flush();
  assert.equal(toggles(panel)["Show advanced settings"].checked, false);
  assert.ok(elementsIn(panel.render()).some((node) =>
    node.props?.role === "alert" && JSON.stringify(node.props.children).includes("Write failed")));
  saveFails = false;
  toggles(panel)["Show advanced settings"].onChange(true);
  await flush();
  assert.equal(toggles(panel)["Show advanced settings"].checked, true);
  assert.equal(elementsIn(panel.render()).some((node) => node.props?.role === "alert"), false);
});
