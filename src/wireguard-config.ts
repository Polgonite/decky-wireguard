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

function storedPeerFields(peer: PeerConfig): Omit<PeerConfig, "original_public_key"> {
  return {
    public_key: peer.public_key,
    preshared_key: peer.preshared_key,
    allowed_ips: peer.allowed_ips,
    endpoint: peer.endpoint,
    persistent_keepalive: peer.persistent_keepalive,
  };
}

// Python's str.strip() and \s (used by the backend) also treat U+001C-U+001F and U+0085 as
// whitespace and never U+FEFF; JavaScript's \s and trim() are the opposite.
const SPACE = "\\t-\\r\\u001c-\\u0020\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const trimSpace = (text: string) => text.replace(new RegExp(`^[${SPACE}]+|[${SPACE}]+$`, "g"), "");
const entries = (text: string) => text.split(new RegExp(`[${SPACE},]+`)).filter(Boolean);

function ipv4Number(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4 || parts.some((part) =>
    !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((value, part) => (value << 8n) | BigInt(part), 0n);
}

function networkValue(entry: string): string {
  const fallback = `invalid:${entry}`;
  const parts = entry.split("/");
  if (parts.length > 2 || !parts[0]) return fallback;
  const address = parts[0];
  const ipv6 = address.includes(":");
  const bits = ipv6 ? 128 : 32;
  let value: bigint | null;
  if (ipv6) {
    if (!/^[0-9a-fA-F:.]+$/.test(address)) return fallback;
    try {
      const canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1);
      const halves = canonical.split("::");
      const left = halves[0] ? halves[0].split(":") : [];
      const right = halves[1] ? halves[1].split(":") : [];
      const groups = halves.length === 2
        ? [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right]
        : left;
      value = groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n);
    } catch {
      return fallback;
    }
  } else {
    value = ipv4Number(address);
    if (value === null) return fallback;
  }
  let prefix = bits;
  if (parts.length === 2) {
    const mask = parts[1]!;
    if (/^[0-9]+$/.test(mask)) {
      prefix = Number(mask);
    } else if (!ipv6) {
      const maskValue = ipv4Number(mask);
      if (maskValue === null) return fallback;
      let binary = maskValue.toString(2).padStart(32, "0");
      if (binary.startsWith("0") && maskValue !== 0n) {
        binary = [...binary].map((bit) => bit === "0" ? "1" : "0").join("");
      }
      if (!/^1*0*$/.test(binary)) return fallback;
      prefix = binary.indexOf("0") === -1 ? 32 : binary.indexOf("0");
    } else return fallback;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return fallback;
  }
  const shift = BigInt(bits - prefix);
  return `${bits}:${(value >> shift) << shift}/${prefix}`;
}

function comparablePeer(peer: PeerConfig): string {
  const keepalive = trimSpace(peer.persistent_keepalive);
  const number = /^[0-9]+$/.test(keepalive) ? Number(keepalive) : NaN;
  return JSON.stringify({
    public_key: trimSpace(peer.public_key),
    preshared_key: trimSpace(peer.preshared_key),
    allowed_ips: entries(peer.allowed_ips).map(networkValue),
    endpoint: trimSpace(peer.endpoint),
    persistent_keepalive: !keepalive || keepalive.toLowerCase() === "off" ? "0"
      : Number.isSafeInteger(number) && number <= 65535 ? String(number) : keepalive,
  });
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
        ...storedPeerFields(peer),
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

/** Replay only local edits onto a fresh snapshot; never overwrite an overlapping external edit. */
export function rebaseDraft(base: EditorDraft, local: EditorDraft, fresh: EditorDraft): EditorDraft {
  const config = { ...fresh.config };
  const comparable = (value: string | EditablePeer[]) =>
    Array.isArray(value) ? JSON.stringify(value.map(comparablePeer)) : value;
  const copy = <K extends keyof EditorDraft["config"]>(key: K) => {
    const previous = comparable(base.config[key]);
    const edited = comparable(local.config[key]);
    const latest = comparable(fresh.config[key]);
    if (edited === previous || latest === edited) return;
    if (latest !== previous) throw new Error(`Both copies changed ${key}. Your draft was kept.`);
    config[key] = local.config[key];
  };
  for (const key of ["name", "private_key", "addresses", "dns", "mtu", "listen_port", "peers"] as const) copy(key);
  if (config.peers === local.config.peers) {
    config.peers = config.peers.map((peer) => {
      const saved = fresh.config.peers.find((candidate) => comparablePeer(candidate) === comparablePeer(peer));
      return saved ? { ...peer, original_public_key: saved.original_public_key } : peer;
    });
  }
  const advanced = fresh.advanced.map((p) => ({ ...p }));
  for (const { key, value } of fromDraft(local).advanced) {
    const previous = base.advanced.find((p) => p.key === key);
    const latest = advanced.find((p) => p.key === key);
    if (latest?.value === value) continue;
    if (latest?.value !== previous?.value) throw new Error(`Both copies changed ${key}. Your draft was kept.`);
    if (latest) latest.value = value;
    else advanced.push({ key, value, originalValue: "", isNew: true, id: key });
  }
  const rebased = { config, advanced };
  if (config.addresses !== fresh.config.addresses) {
    const addresses = entries(config.addresses);
    const updates = fromDraft(rebased).advanced;
    // Address saves recalculate both methods before applying explicit advanced updates.
    for (const family of ["ipv4", "ipv6"] as const) {
      const key = `${family}.method`;
      const previous = base.advanced.find((property) => property.key === key)?.value;
      const latest = fresh.advanced.find((property) => property.key === key)?.value;
      if (previous === undefined || latest === undefined) {
        throw new Error(`Cannot safely rebase addresses without ${key}. Your draft was kept.`);
      }
      const hasAddress = addresses.some((address) => address.includes(":") === (family === "ipv6"));
      let effective = latest;
      if (hasAddress && ["disabled", "ignore", "link-local"].includes(latest)) effective = "manual";
      else if (!hasAddress && latest === "manual") effective = "disabled";
      effective = updates.find((property) => property.key === key)?.value ?? effective;
      if (latest !== previous && effective !== latest) {
        throw new Error(`Both copies changed ${key}. Your draft was kept.`);
      }
    }
  }
  return rebased;
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
