interface SettingDefinition {
  key: string;
  label: string;
  description: string;
}

export const commonSettingGroups: { title: string; settings: SettingDefinition[] }[] = [
  {
    title: "Interface",
    settings: [
      { key: "wireguard.private-key", label: "Private key", description: "PrivateKey - this device's WireGuard key." },
      { key: "ipv4.addresses", label: "IPv4 addresses", description: "Address - tunnel addresses with subnet prefixes." },
      { key: "ipv6.addresses", label: "IPv6 addresses", description: "Address - IPv6 tunnel addresses with subnet prefixes." },
      { key: "ipv4.dns", label: "IPv4 DNS servers", description: "DNS - IPv4 resolvers used by this connection." },
      { key: "ipv6.dns", label: "IPv6 DNS servers", description: "DNS - IPv6 resolvers used by this connection." },
      { key: "wireguard.mtu", label: "MTU", description: "MTU - maximum tunnel packet size; 0 selects automatically." },
      { key: "wireguard.listen-port", label: "Listen port", description: "ListenPort - local UDP port; 0 selects automatically." },
    ],
  },
  {
    title: "Peers",
    settings: [
      {
        key: "wireguard.peers",
        label: "Peer configuration",
        description: "Peer public keys, preshared keys, server endpoints, allowed IPs and persistent keepalive, in NetworkManager peer syntax.",
      },
    ],
  },
];

const commonKeys = new Set(commonSettingGroups.flatMap((group) =>
  group.settings.map((setting) => setting.key),
));

export function groupConnectionSettings<T extends { key: string; isNew: boolean }>(settings: T[]) {
  return {
    common: commonSettingGroups.map((group) => ({
      title: group.title,
      settings: group.settings.flatMap((definition) =>
        settings.filter((setting) => !setting.isNew && setting.key === definition.key)
          .map((setting) => ({ setting, definition })),
      ),
    })).filter((group) => group.settings.length > 0),
    advanced: settings.filter((setting) => setting.isNew || !commonKeys.has(setting.key)),
  };
}

export function advancedSettingLabel(key: string): string {
  return key.split(".").map((part) => part.split("-").map((word) => {
    const acronyms: Record<string, string> = {
      ipv4: "IPv4", ipv6: "IPv6", dns: "DNS", mtu: "MTU", uuid: "UUID", id: "ID",
    };
    return acronyms[word] ?? word.charAt(0).toUpperCase() + word.slice(1);
  }).join(" ")).join(": ");
}
