const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { test } = require("node:test");
const { runInNewContext } = require("node:vm");
const ts = require("typescript");

const source = readFileSync(resolve(__dirname, "../src/wireguard-config.ts"), "utf8");
const context = { exports: {}, URL };
runInNewContext(ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText, context);
const { advancedSettingLabel, draftChanged, emptyDraft, fromDraft, importConf, publicKeyFromPrivate, rebaseDraft } = context.exports;
const toDraft = (config, advanced, flags = {
  private_key: 0, peers: Object.fromEntries(config.peers.map((peer) => [peer.public_key, 0])),
}) => context.exports.toDraft(config, advanced, flags);
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

test("rebasing a persisted new peer keeps its saved identity and unrelated draft edits", () => {
  const base = toDraft({ ...config, peers: [] }, []);
  const local = {
    ...base, config: { ...config, name: "Unsaved name", peers: [{ ...peer, id: "new-peer-0", original_public_key: null }] },
  };
  const fresh = toDraft(config, []);
  const rebased = rebaseDraft(base, local, fresh);
  assert.equal(rebased.config.name, "Unsaved name");
  assert.deepEqual(plain(rebased.config.peers), plain(fresh.config.peers));
  const changed = toDraft({ ...config, peers: [{ ...peer, preshared_key: "different" }] }, []);
  assert.throws(() => rebaseDraft(base, local, changed), /Both copies changed peers/);
});

test("recovery refuses key edits across storage policy changes but keeps unrelated edits", () => {
  const base = toDraft(config, [], { private_key: 0, peers: { peer: 4 } });
  const fresh = toDraft(config, [], { private_key: 1, peers: { peer: 2 } });
  const local = structuredClone(base);
  local.config.private_key = "new private key";
  assert.throws(() => rebaseDraft(base, local, fresh), /private key's storage policy changed/);
  local.config.private_key = base.config.private_key;
  local.config.peers[0].preshared_key = "new preshared key";
  assert.throws(() => rebaseDraft(base, local, fresh), /preshared-key storage policy changed/);
  local.config.peers[0].preshared_key = base.config.peers[0].preshared_key;
  local.config.peers[0].endpoint = "new.example:51820";
  const merged = rebaseDraft(base, local, fresh);
  assert.equal(merged.config.peers[0].endpoint, "new.example:51820");
  assert.deepEqual(merged.secretFlags, fresh.secretFlags);
});

test("recovery refuses overlapping IPv6 gateway edits", () => {
  const gateway = (value) => toDraft(config, [{ key: "ipv6.gateway", value }]);
  const local = gateway("fd00::1");
  local.advanced[0].value = "fd00::3";
  assert.throws(() => rebaseDraft(gateway("fd00::1"), local, gateway("fd00::2")), /Both copies changed ipv6.gateway/);
});

test("rebasing compares canonical peer settings and retains saved identities", () => {
  const base = toDraft({ ...config, peers: [] }, []);
  const localPeer = {
    ...peer, id: "new-peer", original_public_key: null, public_key: " peer ",
    preshared_key: " key ", endpoint: " vpn.example.com:51820 ",
    allowed_ips: "10.0.0.8, 192.0.2.129/24 2001:DB8::1234/64, ::ffff:192.0.2.1",
    persistent_keepalive: " OFF ",
  };
  const persistedPeer = {
    ...peer, preshared_key: "key", allowed_ips: "10.0.0.8/32, 192.0.2.0/24, 2001:db8::/64, ::ffff:c000:201/128",
    persistent_keepalive: "",
  };
  const local = { ...base, config: { ...base.config, name: "Unsaved name", peers: [localPeer] } };
  const fresh = toDraft({ ...config, peers: [persistedPeer] }, []);
  const rebased = rebaseDraft(base, local, fresh);
  assert.equal(rebased.config.name, "Unsaved name");
  assert.deepEqual(plain(rebased.config.peers), plain(fresh.config.peers));

  const different = toDraft({ ...config, peers: [{ ...persistedPeer, allowed_ips: "10.0.0.9/32" }] }, []);
  assert.throws(() => rebaseDraft(base, local, different), /Both copies changed peers/);
  const differentKeepalive = toDraft({ ...config, peers: [{ ...persistedPeer, persistent_keepalive: "25" }] }, []);
  assert.throws(() => rebaseDraft(base, local, differentKeepalive), /Both copies changed peers/);
  for (const invalid of ["10.0.0.08", "10.0.0.8/33", "2001:db8:::1", "10.0.0.8/"]) {
    const invalidLocal = { ...local, config: { ...local.config, peers: [{ ...localPeer, allowed_ips: invalid }] } };
    assert.throws(() => rebaseDraft(base, invalidLocal, fresh), /Both copies changed peers/);
  }
});

test("rebasing peer edits retains saved identities for individually matching peers", () => {
  const savedPeer = { ...peer, allowed_ips: "10.0.0.8/32", persistent_keepalive: "" };
  const secondPeer = { ...peer, original_public_key: "second", public_key: "second" };
  const base = toDraft({ ...config, peers: [savedPeer, secondPeer] }, []);
  const local = {
    ...base, config: { ...base.config, peers: [
      { ...base.config.peers[0], original_public_key: null, allowed_ips: "10.0.0.8", persistent_keepalive: "off" },
      { ...base.config.peers[1], endpoint: "other.example.com:51820" },
    ] },
  };
  const rebased = rebaseDraft(base, local, toDraft({ ...config, peers: [savedPeer, secondPeer] }, []));
  assert.equal(rebased.config.peers[0].original_public_key, "peer");
  assert.equal(rebased.config.peers[1].endpoint, "other.example.com:51820");
  assert.equal(rebased.config.peers[1].original_public_key, "second");
});

test("rebasing recognizes network masks and numeric keepalive equivalents", () => {
  const base = toDraft({ ...config, peers: [] }, []);
  for (const [allowed_ips, persistent_keepalive] of [
    ["10.0.0.8/255.255.255.0", "00025"],
    ["10.0.0.8/0.0.0.255", "25"],
  ]) {
    const local = { ...base, config: { ...base.config, peers: [
      { ...peer, id: "new", original_public_key: null, allowed_ips, persistent_keepalive },
    ] } };
    const fresh = toDraft({ ...config, peers: [{ ...peer, allowed_ips: "10.0.0.0/24" }] }, []);
    assert.deepEqual(plain(rebaseDraft(base, local, fresh).config.peers), plain(fresh.config.peers));
  }
});

test("rebasing treats the control characters Python calls whitespace like the backend", () => {
  const base = toDraft({ ...config, peers: [] }, []);
  for (const space of ["\u001c", "\u001d", "\u001e", "\u001f", "\u0085"]) {
    const local = { ...base, config: { ...base.config, peers: [{
      ...peer, id: "new", original_public_key: null, public_key: `peer${space}`,
      allowed_ips: `10.0.0.0/24${space}10.0.1.0/24`, endpoint: `vpn.example.com:51820${space}`,
      persistent_keepalive: `25${space}`,
    }] } };
    const fresh = toDraft({ ...config, peers: [{ ...peer, allowed_ips: "10.0.0.0/24, 10.0.1.0/24" }] }, []);
    assert.deepEqual(plain(rebaseDraft(base, local, fresh).config.peers), plain(fresh.config.peers));
  }
});

test("rebasing addresses detects external IP methods that the backend would overwrite", () => {
  const methods = (ipv4, ipv6) => [
    { key: "ipv4.method", value: ipv4 }, { key: "ipv6.method", value: ipv6 },
  ];
  const draft = (addresses, ipv4, ipv6) => toDraft({ ...config, addresses }, methods(ipv4, ipv6));
  const base = draft("10.0.0.2/32", "manual", "disabled");
  const local = draft("10.0.0.2/32, fd00::1/64", "manual", "disabled");
  const changed = draft("10.0.0.2/32", "manual", "link-local");
  assert.throws(() => rebaseDraft(base, local, changed), /Both copies changed ipv6\.method/);

  // Both families are recalculated, even if the edited address is in the other family.
  const ipv4Local = draft("10.0.0.3/32", "manual", "disabled");
  const externalManual = draft("10.0.0.2/32", "manual", "manual");
  assert.throws(() => rebaseDraft(base, ipv4Local, externalManual), /Both copies changed ipv6\.method/);

  const explicit = draft(local.config.addresses, "manual", "disabled");
  explicit.advanced[1].value = "link-local";
  assert.throws(() => rebaseDraft(base, explicit, changed), /Both copies changed ipv6\.method/);

  const ipv4Base = draft("", "disabled", "disabled");
  const ipv4Added = draft("10.0.0.2/32", "disabled", "disabled");
  const ipv4External = draft("", "ignore", "disabled");
  assert.throws(() => rebaseDraft(ipv4Base, ipv4Added, ipv4External), /Both copies changed ipv4\.method/);

  const missingMethod = draft("10.0.0.2/32", "manual", "link-local");
  missingMethod.advanced = missingMethod.advanced.filter((property) => property.key !== "ipv6.method");
  assert.throws(() => rebaseDraft(base, local, missingMethod), /Cannot safely rebase addresses.*ipv6\.method/);
});

test("rebasing addresses preserves external methods when the effective result agrees", () => {
  const draft = (addresses, ipv4, ipv6) => toDraft({ ...config, addresses }, [
    { key: "ipv4.method", value: ipv4 }, { key: "ipv6.method", value: ipv6 },
  ]);
  const base = draft("10.0.0.2/32", "manual", "disabled");
  const local = draft("10.0.0.2/32, fd00::1/64", "manual", "disabled");
  const sameEffective = draft("10.0.0.2/32", "manual", "manual");
  assert.equal(rebaseDraft(base, local, sameEffective).config.addresses, local.config.addresses);
  const noImplicitWrite = draft(local.config.addresses, "manual", "link-local");
  assert.equal(rebaseDraft(base, local, noImplicitWrite).advanced[1].value, "link-local");
  const unrelatedFamily = draft("10.0.0.2/32", "manual", "ignore");
  const ipv4Local = draft("10.0.0.3/32", "manual", "disabled");
  assert.equal(rebaseDraft(base, ipv4Local, unrelatedFamily).advanced[1].value, "ignore");

  const explicit = draft(local.config.addresses, "manual", "disabled");
  explicit.advanced[1].value = "manual";
  assert.equal(rebaseDraft(base, explicit, sameEffective).config.addresses, local.config.addresses);
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
