const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const ts = require("typescript");

const source = readFileSync(resolve(__dirname, "../src/wireguard-config.ts"), "utf8");
const context = { exports: {} };
runInNewContext(ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText, context);
const { advancedSettingLabel, draftChanged, emptyDraft, fromDraft, importConf, publicKeyFromPrivate, toDraft } = context.exports;
const key = (hex) => Buffer.from(hex, "hex").toString("base64");
const plain = (value) => JSON.parse(JSON.stringify(value));

const peer = {
  original_public_key: "peer", public_key: "peer", preshared_key: "", allowed_ips: "0.0.0.0/0",
  endpoint: "vpn.example.com:51820", persistent_keepalive: "25",
};
const config = {
  name: "Home", private_key: "", addresses: "10.0.0.2/32", dns: "10.0.0.1", mtu: "",
  listen_port: "", peers: [peer],
};

test("public keys match the RFC 7748 X25519 test vectors", () => {
  assert.equal(
    publicKeyFromPrivate(key("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")),
    key("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  );
  assert.equal(
    publicKeyFromPrivate(` ${key("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")}\n`),
    key("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  );
  for (const invalid of ["", "not-a-key", key("00".repeat(31)), `${key("00".repeat(32)).slice(0, 42)}B=`]) {
    assert.equal(publicKeyFromPrivate(invalid), null, invalid);
  }
});

test("drafts round-trip to the backend shape and send only changed advanced properties", () => {
  const saved = toDraft(config, [{ key: "ipv4.dns-priority", value: "0" }, { key: "connection.zone", value: "" }]);
  const draft = {
    config: { ...saved.config, peers: [...saved.config.peers, { ...saved.config.peers[0], id: "new", original_public_key: null }] },
    advanced: [
      { ...saved.advanced[0], value: "-50" },
      saved.advanced[1],
      { id: "new-1", key: " ipv4.dns-options ", value: "rotate", originalValue: "", isNew: true },
      { id: "new-2", key: "", value: "ignored", originalValue: "", isNew: true },
    ],
  };
  const request = plain(fromDraft(draft));
  assert.deepEqual(request.config.peers, [peer, { ...peer, original_public_key: null }]);
  assert.deepEqual(request.advanced, [
    { key: "ipv4.dns-priority", value: "-50" }, { key: "ipv4.dns-options", value: "rotate" },
  ]);
  assert.throws(() => fromDraft({ ...draft, advanced: [draft.advanced[0], { ...draft.advanced[2], key: "ipv4.dns-priority" }] }),
    /unique/);
});

test("unsaved changes include peer removal and named new properties, not blank rows", () => {
  const saved = toDraft(config, []);
  assert.equal(draftChanged(saved, saved), false);
  assert.equal(draftChanged({ ...saved, config: { ...saved.config, peers: [] } }, saved), true);
  const blank = { id: "new", key: " ", value: "", originalValue: "", isNew: true };
  assert.equal(draftChanged({ ...saved, advanced: [blank] }, saved), false);
  assert.equal(draftChanged({ ...saved, advanced: [{ ...blank, key: "ipv4.dns-priority" }] }, saved), true);
});

test("advanced property labels are readable", () => {
  assert.equal(advancedSettingLabel("ipv4.dns-search"), "IPv4: DNS Search");
  assert.equal(advancedSettingLabel("future.custom-property"), "Future: Custom Property");
});

test("import replaces tunnel identity and peers without retaining old secrets or advanced settings loss", () => {
  const saved = toDraft({
    ...config, private_key: "old private", mtu: "1380", listen_port: "51821",
    peers: [{ ...peer, preshared_key: "old psk" }, { ...peer, public_key: "old second peer" }],
  }, [{ key: "ipv4.dns-priority", value: "-50" }]);
  const before = plain(saved);
  const draft = importConf(saved, "\uFEFF[Interface]\r\n# comment\r\n[Peer]\r\nPublicKey = imported\r\n", "other.conf");
  assert.deepEqual(plain(draft.config), {
    name: "Home", private_key: "", addresses: "", dns: "", mtu: "1380", listen_port: "51821",
    peers: [{
      id: "import-peer-0", original_public_key: null, public_key: "imported", preshared_key: "",
      allowed_ips: "", endpoint: "", persistent_keepalive: "",
    }],
  });
  assert.equal(draft.advanced, saved.advanced);
  assert.deepEqual(plain(saved), before, "Import must not mutate the existing draft");
  assert.equal(draftChanged(draft, saved), true);
  assert.deepEqual(plain(fromDraft(draft).advanced), []);
});

test("import populates new profiles, repeated lists, interface options and multiple peers", () => {
  const draft = importConf(emptyDraft(), `
    [Interface]
    PrivateKey = private==
    Address = 10.1.0.2/32, fd00::2/128
    Address = 10.2.0.2/32 # another address
    DNS = 10.1.0.1
    DNS = home.lan
    MTU = 1420
    ListenPort = 51820
    [Peer]
    PublicKey = public==
    PresharedKey = shared==
    AllowedIPs = 0.0.0.0/0
    AllowedIPs = ::/0
    Endpoint = vpn.example.com:51820
    PersistentKeepalive = 25
    [Peer]
    PublicKey = second==
  `, "Office.conf");
  assert.deepEqual(plain(fromDraft(draft).config), {
    name: "Office", private_key: "private==", addresses: "10.1.0.2/32, fd00::2/128, 10.2.0.2/32",
    dns: "10.1.0.1, home.lan", mtu: "1420", listen_port: "51820",
    peers: [
      { original_public_key: null, public_key: "public==", preshared_key: "shared==",
        allowed_ips: "0.0.0.0/0, ::/0", endpoint: "vpn.example.com:51820", persistent_keepalive: "25" },
      { original_public_key: null, public_key: "second==", preshared_key: "",
        allowed_ips: "", endpoint: "", persistent_keepalive: "" },
    ],
  });
  assert.equal(importConf(draft, "[Interface]\nPrivateKey = replacement", "other.conf").config.peers.length, 0);
});

test("invalid or unsupported imports fail atomically without exposing values", () => {
  const saved = toDraft(config, []);
  const before = plain(saved);
  for (const text of [
    "", "[Peer]\nPublicKey = secret", "PrivateKey = secret", "[Something]",
    "[Interface]\n[Interface]", "[Interface]\nPrivateKey=one\nPrivateKey=secret",
    "[Interface]\nPostUp = secret", "[Interface]\nPrivateKey = new\n[Peer]\nUnknown = secret",
    "[Interface]\n" + "[Peer]\n".repeat(65),
  ]) {
    assert.throws(() => importConf(saved, text, "file.conf"), (error) => {
      assert.equal(error.message.includes("secret"), false);
      return true;
    });

    assert.deepEqual(plain(saved), before);
  }
});

test("FwMark overrides only its advanced property and is retained when omitted", () => {
  for (const properties of [[], [{ key: "wireguard.fwmark", value: "0" }]]) {
    const saved = toDraft(config, [...properties, { key: "ipv4.dns-priority", value: "-50" }]);
    const imported = importConf(saved, "[Interface]\nFwMark = 0xca6c", "file.conf");
    assert.deepEqual(plain(fromDraft(imported).advanced), [{ key: "wireguard.fwmark", value: "0xca6c" }]);
    assert.equal(imported.advanced.find((property) => property.key === "ipv4.dns-priority").value, "-50");
    assert.equal(importConf(imported, "[Interface]", "file.conf").advanced, imported.advanced);
  }
});
