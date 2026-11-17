export interface PeerConfig {
  original_public_key: string | null;
  public_key: string;
  preshared_key: string;
  allowed_ips: string;
  endpoint: string;
  persistent_keepalive: string;
}

export interface WireGuardConfig {
  name: string;
  private_key: string;
  addresses: string;
  dns: string;
  mtu: string;
  listen_port: string;
  peers: PeerConfig[];
}

export interface AdvancedProperty {
  key: string;
  value: string;
}

export interface EditablePeer extends PeerConfig {
  id: string;
}

export interface EditableProperty extends AdvancedProperty {
  id: string;
  originalValue: string;
  isNew: boolean;
}

export interface EditorDraft {
  config: Omit<WireGuardConfig, "peers"> & { peers: EditablePeer[] };
  advanced: EditableProperty[];
}

export function emptyDraft(): EditorDraft {
  return toDraft({
    name: "", private_key: "", addresses: "", dns: "", mtu: "", listen_port: "", peers: [],
  }, []);
}

/** Import tunnel identity and peers, but retain unrelated NetworkManager policy. */
export function importConf(draft: EditorDraft, text: string, filename: string): EditorDraft {
  const config: EditorDraft["config"] = {
    ...draft.config, private_key: "", addresses: "", dns: "", peers: [],
    name: draft.config.name || filename.replace(/\.conf$/i, ""),
  };
  let section: "Interface" | "Peer" | null = null;
  let hasInterface = false;
  let peer: EditablePeer | undefined;
  let seen = new Set<string>();
  let advanced = draft.advanced;
  const interfaceFields = {
    PrivateKey: "private_key", Address: "addresses", DNS: "dns", MTU: "mtu", ListenPort: "listen_port",
  } as const;
  const peerFields = {
    PublicKey: "public_key", PresharedKey: "preshared_key", AllowedIPs: "allowed_ips",
    Endpoint: "endpoint", PersistentKeepalive: "persistent_keepalive",
  } as const;
  for (const [index, raw] of text.replace(/^\uFEFF/, "").split(/\r?\n/).entries()) {
    const line = raw.replace(/#.*/, "").trim();
    if (!line) continue;
    function fail(message: string): never { throw new Error(`Line ${index + 1}: ${message}`); }
    if (line === "[Interface]") {
      if (hasInterface || section === "Peer") fail("Expected a single [Interface] before peers.");
      hasInterface = true;
      section = "Interface";
      seen = new Set();
      continue;
    }
    if (line === "[Peer]") {
      if (!hasInterface) fail("[Peer] must follow [Interface].");
      if (config.peers.length >= 64) fail("At most 64 peers are supported.");
      section = "Peer";
      peer = newPeer(`import-peer-${config.peers.length}`);
      config.peers.push(peer);
      seen = new Set();
      continue;
    }
    const match = /^([A-Za-z]+)\s*=\s*(.*)$/.exec(line);
    if (!match || !section) fail("Expected a setting inside [Interface] or [Peer].");
    const key = match[1]!;
    const value = match[2]!;
    const multiple = section === "Interface" ? key === "Address" || key === "DNS" : key === "AllowedIPs";
    if (seen.has(key) && !multiple) fail(`Duplicate ${key} setting.`);
    seen.add(key);
    if (section === "Interface" && Object.prototype.hasOwnProperty.call(interfaceFields, key)) {
      const field = interfaceFields[key as keyof typeof interfaceFields];
      config[field] = multiple && config[field] ? `${config[field]}, ${value}` : value;
    } else if (section === "Interface" && key === "FwMark") {
      const property = advanced.find((entry) => entry.key === "wireguard.fwmark");
      advanced = property
        ? advanced.map((entry) => entry === property ? { ...entry, value } : entry)
        : [...advanced, {
          id: "import-fwmark", key: "wireguard.fwmark", value, originalValue: "", isNew: true,
        }];
    } else if (section === "Peer" && peer && Object.prototype.hasOwnProperty.call(peerFields, key)) {
      const field = peerFields[key as keyof typeof peerFields];
      peer[field] = multiple && peer[field] ? `${peer[field]}, ${value}` : value;
    } else {
      fail(`Unsupported ${section} setting: ${key}. No fields were imported.`);
    }
  }
  if (!hasInterface) throw new Error("The file must contain an [Interface] section.");
  return { ...draft, config, advanced };
}

export function newPeer(id: string): EditablePeer {
  return {
    id, original_public_key: null, public_key: "", preshared_key: "",
    allowed_ips: "", endpoint: "", persistent_keepalive: "",
  };
}

export function toDraft(config: WireGuardConfig, advanced: AdvancedProperty[]): EditorDraft {
  return {
    config: { ...config, peers: config.peers.map((peer, index) => ({ ...peer, id: `peer-${index}` })) },
    advanced: advanced.map((property) => ({
      ...property, id: property.key, originalValue: property.value, isNew: false,
    })),
  };
}

export function fromDraft(draft: EditorDraft): { config: WireGuardConfig; advanced: AdvancedProperty[] } {
  const configured = draft.advanced.filter((property) => property.key.trim() !== "");
  const keys = configured.map((property) => property.key.trim());
  if (new Set(keys).size !== keys.length) throw new Error("Advanced property names must be unique.");
  return {
    config: {
      ...draft.config,
      peers: draft.config.peers.map((peer) => ({
        original_public_key: peer.original_public_key,
        public_key: peer.public_key,
        preshared_key: peer.preshared_key,
        allowed_ips: peer.allowed_ips,
        endpoint: peer.endpoint,
        persistent_keepalive: peer.persistent_keepalive,
      })),
    },
    advanced: configured
      .filter((property) => property.isNew || property.value !== property.originalValue)
      .map(({ key, value }) => ({ key: key.trim(), value })),
  };
}

export function draftChanged(draft: EditorDraft, saved: EditorDraft): boolean {
  return JSON.stringify(draft.config) !== JSON.stringify(saved.config) ||
    draft.advanced.some((property) =>
      (property.isNew && property.key.trim() !== "") || property.value !== property.originalValue);
}

export function advancedSettingLabel(key: string): string {
  const acronyms: Record<string, string> = {
    ipv4: "IPv4", ipv6: "IPv6", dns: "DNS", mtu: "MTU", uuid: "UUID", id: "ID",
  };
  return key.split(".").map((part) => part.split("-").map((word) =>
    acronyms[word] ?? word.charAt(0).toUpperCase() + word.slice(1),
  ).join(" ")).join(": ");
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function decodeKey(text: string): Uint8Array | null {
  const key = text.trim();
  if (!/^[A-Za-z0-9+/]{43}=$/.test(key)) return null;
  const bytes = new Uint8Array(32);
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const character of key.slice(0, 43)) {
    buffer = (buffer << 6) | base64Alphabet.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (index < 32) bytes[index++] = (buffer >> bits) & 0xff;
    }
  }
  // The final character carries two padding bits that must be zero in canonical base64.
  return (buffer & ((1 << bits) - 1)) === 0 ? bytes : null;
}

function encodeKey(bytes: Uint8Array): string {
  let text = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const chunk = ((bytes[index] ?? 0) << 16) | ((bytes[index + 1] ?? 0) << 8) | (bytes[index + 2] ?? 0);
    for (let offset = 0; offset < 4; offset++) {
      text += index * 4 / 3 + offset < Math.ceil(bytes.length * 4 / 3)
        ? base64Alphabet[(chunk >> (18 - offset * 6)) & 63] : "=";
    }
  }
  return text;
}

const P = (1n << 255n) - 19n;
const mod = (value: bigint) => ((value % P) + P) % P;

function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let current = mod(base);
  for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
    if (remaining & 1n) result = (result * current) % P;
    current = (current * current) % P;
  }
  return result;
}

/** Derive a WireGuard public key (X25519 with base point 9, RFC 7748) from a private key. */
export function publicKeyFromPrivate(privateKey: string): string | null {
  const bytes = decodeKey(privateKey);
  if (!bytes) return null;
  let scalar = 0n;
  for (let index = 31; index >= 0; index--) scalar = (scalar << 8n) | BigInt(bytes[index] ?? 0);
  scalar &= ~7n;
  scalar &= (1n << 255n) - 1n;
  scalar |= 1n << 254n;
  const x1 = 9n;
  let [x2, z2, x3, z3] = [1n, 0n, x1, 1n];
  let swap = 0n;
  for (let bit = 254n; bit >= 0n; bit--) {
    const current = (scalar >> bit) & 1n;
    if (swap ^ current) [x2, x3, z2, z3] = [x3, x2, z3, z2];
    swap = current;
    const a = mod(x2 + z2);
    const aa = (a * a) % P;
    const b = mod(x2 - z2);
    const bb = (b * b) % P;
    const e = mod(aa - bb);
    const c = mod(x3 + z3);
    const d = mod(x3 - z3);
    const da = (d * a) % P;
    const cb = (c * b) % P;
    x3 = power(da + cb, 2n);
    z3 = (x1 * power(da - cb, 2n)) % P;
    x2 = (aa * bb) % P;
    z2 = (e * mod(aa + 121665n * e)) % P;
  }
  if (swap) [x2, z2] = [x3, z3];
  let result = (x2 * power(z2, P - 2n)) % P;
  const output = new Uint8Array(32);
  for (let index = 0; index < 32; index++) {
    output[index] = Number(result & 0xffn);
    result >>= 8n;
  }
  return encodeKey(output);
}
