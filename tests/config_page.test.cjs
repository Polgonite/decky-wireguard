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

const configContext = { exports: {} };
runInNewContext(compile("wireguard-config.ts"), configContext);
const config = configContext.exports;
const compiled = compile("config-page.tsx");
const navigationCompiled = compile("plugin-navigation.ts");
const saved = config.toDraft({
  name: "Home", private_key: "", addresses: "10.0.0.2/32", dns: "", mtu: "",
  listen_port: "", peers: [],
}, []);
const flush = () => new Promise((resolve) => setImmediate(resolve));

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function page(draft = saved, backend = () => assert.fail("Unexpected backend call")) {
  const hooks = [draft, saved];
  const modals = [];
  const openedPanels = [];
  let cursor = 0;
  let navigations = 0;
  const element = (type, props) => ({ type, props });
  const context = {
    exports: {},
    require: (name) => {
      if (name === "@decky/api") return { callable: (route) => (...args) => backend(route, ...args) };
      if (name === "@decky/ui") return {
        staticClasses: { Title: "title" },
        useParams: () => ({ uuid: "test" }),
        Navigation: {
          NavigateBack: () => { navigations++; },
          OpenQuickAccessMenu: (tab) => {
            assert.equal(navigations, 1, "Close the editor before reopening the panel");
            openedPanels.push({ tab, uuid: navigation.exports.useSelectedConnection()[0] });
          },
        },
        QuickAccessTab: { Decky: 999 },
        showModal: (modal, _parent, options) => modals.push({ ...modal, options }),
        ...Object.fromEntries(["ButtonItem", "ConfirmModal", "DialogBody", "Focusable", "PanelSectionRow"]
          .map((name) => [name, name])),
      };
      if (name === "react/jsx-runtime") return { jsx: element, jsxs: element };
      if (name === "react") return {
        useState: (initial) => {
          const index = cursor++;
          if (!(index in hooks)) hooks[index] = initial;
          return [hooks[index], (update) => {
            hooks[index] = typeof update === "function" ? update(hooks[index]) : update;
          }];
        },
        useRef: (initial) => {
          const index = cursor++;
          return hooks[index] ??= { current: initial };
        },
        useCallback: (callback) => callback,
        useEffect: () => {},
        useSyncExternalStore: (_subscribe, snapshot) => snapshot(),
      };
      if (name === "./connection-editor") return { ConnectionEditor: "ConnectionEditor" };
      if (name === "./wireguard-config") return config;
      if (name === "./plugin-navigation") return navigation.exports;
      throw new Error(`Unexpected module: ${name}`);
    },
  };
  const navigation = { exports: {}, require: context.require };
  runInNewContext(navigationCompiled, navigation);
  runInNewContext(compiled, context);

  function render() {
    cursor = 0;
    const tree = context.exports.ConfigPage();
    function find(node, type, predicate = () => true) {
      if (!node || typeof node !== "object") return;
      if (node.type === type && predicate(node)) return node;
      const children = node.props?.children;
      for (const child of Array.isArray(children) ? children : [children]) {
        const found = find(child, type, predicate);
        if (found) return found;
      }
    }
    return {
      back: () => find(tree, "ButtonItem").props.onClick(),
      backDisabled: find(tree, "ButtonItem").props.disabled,
      save: () => find(tree, "ButtonItem", (node) => node.props.children === "Save changes").props.onClick(),
      cancel: () => {
        let prevented = false;
        let stopped = false;
        find(tree, "Focusable").props.onCancelButton({
          preventDefault: () => { prevented = true; },
          stopPropagation: () => { stopped = true; },
        });
        assert.ok(prevented && stopped, "Back input must be handled without bubbling");
      },
      change: (update) => find(tree, "ConnectionEditor").props.onChange(update),
    };
  }
  return { render, modals, openedPanels, get navigations() { return navigations; } };
}

for (const input of ["back", "cancel"]) {
  test(`${input} leaves an unchanged configuration without confirmation`, () => {
    const editor = page();
    editor.render()[input]();
    assert.equal(editor.navigations, 1);
    assert.deepEqual(editor.openedPanels, [{ tab: 999, uuid: "test" }]);
    assert.equal(editor.modals.length, 0);
  });

  test(`${input} confirms changes, allows keeping them, and leaves after discarding`, () => {
    const editor = page({ ...saved, config: { ...saved.config, name: "Changed" } });
    const view = editor.render();
    view[input]();
    view[input]();
    assert.equal(editor.navigations, 0);
    assert.equal(editor.openedPanels.length, 0);
    assert.equal(editor.modals.length, 1);
    editor.modals[0].options.fnOnClose();
    assert.equal(editor.navigations, 0);
    view[input]();
    assert.equal(editor.modals.length, 2);
    editor.modals[1].props.onOK();
    assert.equal(editor.navigations, 1);
    assert.deepEqual(editor.openedPanels, [{ tab: 999, uuid: "test" }]);
  });

  test(`${input} waits for saving and reloading before leaving without a discard prompt`, async () => {
    const write = deferred();
    const reload = deferred();
    let reloading = false;
    const draft = { ...saved, config: { ...saved.config, name: "Changed" } };
    const editor = page(draft, (route) => {
      if (route === "set_connection_config") return write.promise;
      if (route === "get_profiles") return { success: true, profiles: [{ uuid: "test", state: "disconnected" }] };
      if (route === "get_connection_config") {
        reloading = true;
        return reload.promise;
      }
      assert.fail(`Unexpected backend call: ${route}`);
    });
    const view = editor.render();
    view.save();
    view[input]();
    assert.equal(editor.navigations, 0, "Back must be blocked before React rerenders");
    assert.equal(editor.modals.length, 0);
    assert.equal(editor.render().backDisabled, true);

    write.resolve({ success: true });
    await flush();
    assert.equal(reloading, true);
    editor.render()[input]();
    assert.equal(editor.navigations, 0, "Back must remain blocked during the reload");
    assert.equal(editor.modals.length, 0);
    assert.equal(editor.render().backDisabled, true);

    reload.resolve({ success: true, config: draft.config, advanced: [] });
    await flush();
    assert.equal(editor.render().backDisabled, false);
    editor.render()[input]();
    assert.equal(editor.navigations, 1);
    assert.equal(editor.modals.length, 0);
  });

  test(`${input} can discard unsaved changes after a failed save`, async () => {
    const write = deferred();
    const editor = page({ ...saved, config: { ...saved.config, name: "Changed" } }, (route) => {
      assert.equal(route, "set_connection_config");
      return write.promise;
    });
    editor.render().save();
    editor.render()[input]();
    assert.equal(editor.modals.length, 0);
    assert.equal(editor.navigations, 0);

    write.resolve({ success: false, error: "Save failed" });
    await flush();
    assert.equal(editor.render().backDisabled, false);
    editor.render()[input]();
    assert.equal(editor.modals.length, 1);
    assert.equal(editor.navigations, 0);
    editor.modals[0].props.onOK();
    assert.equal(editor.navigations, 1);
  });
}

test("B leaves without confirmation after edits are reverted", () => {
  const editor = page();
  editor.render().change({ ...saved, config: { ...saved.config, name: "Changed" } });
  editor.render().change(saved);
  editor.render().cancel();
  assert.equal(editor.navigations, 1);
  assert.equal(editor.modals.length, 0);
});
