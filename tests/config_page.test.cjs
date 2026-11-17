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

function page(draft = saved) {
  const hooks = [draft, saved];
  const modals = [];
  const openedPanels = [];
  let cursor = 0;
  let navigations = 0;
  const element = (type, props) => ({ type, props });
  const context = {
    exports: {},
    require: (name) => {
      if (name === "@decky/api") return { callable: () => () => assert.fail("Unexpected backend call") };
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
    function find(node, type) {
      if (!node || typeof node !== "object") return;
      if (node.type === type) return node;
      const children = node.props?.children;
      for (const child of Array.isArray(children) ? children : [children]) {
        const found = find(child, type);
        if (found) return found;
      }
    }
    return {
      back: () => find(tree, "ButtonItem").props.onClick(),
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
}

test("B leaves without confirmation after edits are reverted", () => {
  const editor = page();
  editor.render().change({ ...saved, config: { ...saved.config, name: "Changed" } });
  editor.render().change(saved);
  editor.render().cancel();
  assert.equal(editor.navigations, 1);
  assert.equal(editor.modals.length, 0);
});
