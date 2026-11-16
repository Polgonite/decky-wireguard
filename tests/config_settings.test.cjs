const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const ts = require("typescript");

const source = readFileSync(resolve(__dirname, "../src/config-settings.ts"), "utf8");
const context = { exports: {} };
runInNewContext(ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS },
}).outputText, context);
const { groupConnectionSettings, advancedSettingLabel } = context.exports;

test("common fields follow Interface then Peer order regardless of NetworkManager order", () => {
  const keys = [
    "wireguard.peers", "wireguard.listen-port", "ipv6.dns", "ipv4.dns",
    "wireguard.mtu", "ipv6.addresses", "ipv4.addresses", "wireguard.private-key",
  ];
  const settings = keys.map((key) => ({ key, isNew: false, value: key }));
  const result = groupConnectionSettings(settings);
  assert.deepEqual(Array.from(result.common, (group) => group.title), ["Interface", "Peers"]);
  assert.deepEqual(Array.from(result.common.flatMap((group) => group.settings),
    ({ setting }) => setting.key), [
    "wireguard.private-key", "ipv4.addresses", "ipv6.addresses", "ipv4.dns",
    "ipv6.dns", "wireguard.mtu", "wireguard.listen-port", "wireguard.peers",
  ]);
  assert.equal(result.advanced.length, 0);
});

test("advanced properties and unsaved custom fields are retained without changing draft values", () => {
  const settings = [
    { key: "connection.id", isNew: false, value: "VPN" },
    { key: "wireguard.private-key", isNew: false, value: "edited-key" },
    { key: "ipv4.dns", isNew: true, value: "10.0.0.1" },
    { key: "", isNew: true, value: "" },
    { key: "future.property", isNew: false, value: "unknown" },
  ];
  const result = groupConnectionSettings(settings);
  assert.deepEqual(Array.from(result.advanced), [
    settings[0], settings[2], settings[3], settings[4],
  ]);
  assert.equal(result.common[0].settings[0].setting, settings[1]);
  assert.equal(result.advanced[1], settings[2]);
});

test("advanced fields have readable labels while unknown properties remain identifiable", () => {
  assert.equal(advancedSettingLabel("ipv4.dns-search"), "IPv4: DNS Search");
  assert.equal(advancedSettingLabel("connection.uuid"), "Connection: UUID");
  assert.equal(advancedSettingLabel("future.custom-property"), "Future: Custom Property");
});
