const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const ts = require("typescript");

function compile(file) {
  return ts.transpileModule(readFileSync(resolve(__dirname, "../src", file), "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2020 },
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

function page(draft = saved, backend = () => assert.fail("Unexpected backend call"), options = {}) {
  const hooks = [draft, options.saved === undefined ? saved : options.saved];
  const effects = [];
  const modals = [];
  const openedPanels = [];
  let cursor = 0;
  let navigations = 0;
  const element = (type, props) => ({ type, props });
  const context = {
    exports: {},
    require: (name) => {
      if (name === "@decky/api") return {
        callable: (route) => (...args) => backend(route, ...args),
        openFilePicker: (...args) => options.pick(...args),
      };
      if (name === "@decky/ui") return {
        staticClasses: { Title: "title" },
        useParams: () => ({ uuid: options.uuid ?? "test" }),
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
        useEffect: (effect) => effects.push(effect),
        useSyncExternalStore: (_subscribe, snapshot) => snapshot(),
      };
      if (name === "./connection-editor") return { ConnectionEditor: "ConnectionEditor" };
      if (name === "./wireguard-config") return config;
      if (name === "./plugin-navigation") return navigation.exports;
      if (name === "./ui-settings") return {
        useUISettings: () => options.uiSettings ?? { showAdvanced: false, error: null },
      };
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
      save: () => find(tree, "ButtonItem", (node) => node.props.children === "Save").props.onClick(),
      importFile: () => find(tree, "ButtonItem", (node) => node.props.children === "Import .conf file").props.onClick(),
      draft: find(tree, "ConnectionEditor")?.props.draft,
      allowAdvanced: find(tree, "ConnectionEditor")?.props.allowAdvanced,
      messages: (function collect(node) {
        if (!node || typeof node !== "object") return [];
        const children = node.props?.children;
        if (typeof node.type === "function" && typeof children === "string") return [children];
        return (Array.isArray(children) ? children : [children]).flatMap(collect);
      })(tree),
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
  return {
    render, modals, openedPanels,
    mount: async () => {
      render();
      effects.splice(0).forEach((effect) => effect());
      await flush();
    },
    get navigations() { return navigations; },
  };
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

test("import browses folders and only updates the draft until Save is pressed", async () => {
  const calls = [];
  const editor = page(saved, (route, ...args) => {
    calls.push([route, ...args]);
    if (route === "read_conf_file") return { success: true, text: "[Interface]\nPrivateKey = imported\n" };
    if (route === "set_connection_config") return { success: true };
    if (route === "get_profiles") return { success: true, profiles: [{ uuid: "test", state: "disconnected" }] };
    if (route === "get_connection_config") return { success: true, config: saved.config, advanced: [] };
    assert.fail(`Unexpected call: ${route}`);
  }, {
    pick: async (type, _start, files, folders, _filter, extensions) => {
      assert.equal(type, 0);
      assert.equal(files, true);
      assert.equal(folders, true, "Users must be able to browse into directories");
      assert.deepEqual(Array.from(extensions), ["conf"]);
      return { path: "/home/deck/VPN.conf", realpath: "/home/deck/VPN.conf" };
    },
  });
  editor.render().importFile();
  await flush();
  assert.deepEqual(calls.map(([route]) => route), ["read_conf_file"]);
  const draft = editor.render().draft;
  assert.equal(draft.config.name, "Home");
  assert.equal(draft.config.private_key, "imported");
  assert.equal(draft.config.addresses, "");
  assert.deepEqual(Array.from(draft.config.peers), []);
  editor.render().save();
  await flush();
  assert.equal(calls[1][0], "set_connection_config");
  assert.equal(calls[1][1], "test");
  assert.equal(calls[1][2].private_key, "imported");
});

for (const failure of ["User canceled", new Error("Picker unavailable")]) {
  test(`file picker ${typeof failure === "string" ? "cancellation" : "failure"} leaves the draft unchanged`, async () => {
    const editor = page(saved, undefined, { pick: () => Promise.reject(failure) });
    editor.render().importFile();
    await flush();
    const view = editor.render();
    assert.equal(view.draft, saved);
    assert.equal(view.backDisabled, false);
    assert.equal(view.messages.some((message) => message.includes("Picker unavailable")), typeof failure !== "string");
    assert.equal(view.messages.includes("User canceled"), false);
  });
}

test("new connections start locally, create only on Save, and use the created UUID thereafter", async () => {
  const calls = [];
  const blank = config.emptyDraft();
  const draft = { ...blank, config: { ...blank.config, name: "New VPN", private_key: "key" } };
  const editor = page(null, (route, ...args) => {
    calls.push([route, ...args]);
    if (route === "create_connection_config") return { success: true, uuid: "created" };
    if (route === "set_connection_config") return { success: true };
    if (route === "get_profiles") return { success: true, profiles: [{ uuid: "created", state: "disconnected" }] };
    if (route === "get_connection_config") return { success: true, config: draft.config, advanced: [] };
    assert.fail(`Unexpected call: ${route}`);
  }, { uuid: "new", saved: null });
  await editor.mount();
  assert.equal(calls.length, 0, "Opening a new editor must not create or load a profile");
  assert.equal(editor.render().draft.config.name, "");
  editor.render().change(draft);
  editor.render().save();
  await flush();
  assert.equal(calls[0][0], "create_connection_config");
  assert.equal(calls.find(([route]) => route === "get_connection_config")[1], "created");
  editor.render().change({ ...draft, config: { ...draft.config, name: "Renamed" } });
  editor.render().save();
  await flush();
  assert.equal(calls.filter(([route]) => route === "create_connection_config").length, 1);
  assert.equal(calls.find(([route]) => route === "set_connection_config")[1], "created");
  editor.render().back();
  assert.deepEqual(editor.openedPanels, [{ tab: 999, uuid: "created" }]);
});

test("an untouched new connection can be closed without creating a profile", async () => {
  const editor = page(null, undefined, { uuid: "new", saved: null });
  await editor.mount();
  editor.render().back();
  assert.equal(editor.modals.length, 0);
  assert.deepEqual(editor.openedPanels, [{ tab: 999, uuid: null }]);
});

test("the editor receives the current advanced settings preference", () => {
  const uiSettings = { showAdvanced: false, error: null };
  const editor = page(saved, undefined, { uiSettings });
  assert.equal(editor.render().allowAdvanced, false);
  uiSettings.showAdvanced = true;
  assert.equal(editor.render().allowAdvanced, true);
  uiSettings.showAdvanced = false;
  assert.equal(editor.render().allowAdvanced, false);
  uiSettings.error = "Read failed";
  assert.ok(editor.render().messages.some((message) => message.includes("Read failed")));
});

test("advanced editor controls disappear when disabled without losing draft edits", () => {
  const compiledEditor = compile("connection-editor.tsx");
  const hooks = [];
  let cursor = 0;
  let draft = config.toDraft({ ...saved.config, mtu: "1380" }, [
    { key: "ipv4.dns-priority", value: "0" },
  ]);
  const element = (type, props) => ({ type, props });
  const context = {
    exports: {},
    require: (name) => {
      if (name === "@decky/ui") return {
        staticClasses: { PanelSectionTitle: "title" },
        ButtonItem: "ButtonItem", PanelSectionRow: "PanelSectionRow", TextField: "TextField",
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
        useRef: (initial) => hooks[cursor++] ??= { current: initial },
      };
      if (name === "./wireguard-config") return config;
      throw new Error(`Unexpected module: ${name}`);
    },
  };
  runInNewContext(compiledEditor, context);
  const render = (allowAdvanced) => {
    cursor = 0;
    const tree = context.exports.ConnectionEditor({
      draft, allowAdvanced, disabled: false,
      onChange: (update) => { draft = typeof update === "function" ? update(draft) : update; },
    });
    const nodes = [];
    function collect(node) {
      if (Array.isArray(node)) {
        node.forEach(collect);
        return;
      }
      if (!node || typeof node !== "object") return;
      nodes.push(node);
      const children = node.props?.children;
      (Array.isArray(children) ? children : [children]).forEach(collect);
    }
    collect(tree);
    return nodes;
  };
  const button = (nodes, label) => nodes.find((node) =>
    node.type === "ButtonItem" && node.props.children === label);
  const field = (nodes, label) => nodes.find((node) =>
    node.type === "TextField" && node.props.label === label);

  assert.equal(button(render(false), "Show advanced"), undefined);
  assert.equal(field(render(false), "MTU"), undefined);
  button(render(true), "Show advanced").props.onClick();
  field(render(true), "MTU").props.onChange({ target: { value: "1420" } });
  field(render(true), "IPv4: DNS Priority").props.onChange({ target: { value: "-50" } });
  assert.equal(button(render(false), "Hide advanced"), undefined);
  assert.equal(field(render(false), "MTU"), undefined);
  assert.equal(field(render(true), "MTU").props.value, "1420");
  assert.equal(field(render(true), "IPv4: DNS Priority").props.value, "-50");
  assert.equal(config.fromDraft(draft).config.mtu, "1420");
  assert.equal(config.fromDraft(draft).advanced[0].value, "-50");
});
