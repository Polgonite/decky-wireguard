import { ButtonItem, PanelSectionRow, staticClasses, TextField } from "@decky/ui";
import { Dispatch, ReactNode, SetStateAction, useRef, useState } from "react";
import {
  advancedSettingLabel, EditablePeer, EditableProperty, EditorDraft, newPeer, publicKeyFromPrivate,
} from "./wireguard-config";

type ConfigField = Exclude<keyof EditorDraft["config"], "peers">;
type PeerField = Exclude<keyof EditablePeer, "id" | "original_public_key">;

function Heading({ children }: { children: ReactNode }) {
  return (
    <PanelSectionRow>
      <div className={staticClasses.PanelSectionTitle} style={{ paddingTop: 12 }}>{children}</div>
    </PanelSectionRow>
  );
}

/**
 * Controlled editor for a WireGuard connection, laid out like a .conf file.
 * It owns no persistence so it can serve both existing and new connections.
 */
export function ConnectionEditor({ draft, onChange, disabled }: {
  draft: EditorDraft;
  onChange: Dispatch<SetStateAction<EditorDraft>>;
  disabled: boolean;
}) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const nextId = useRef(0);
  const { config } = draft;
  const publicKey = publicKeyFromPrivate(config.private_key);

  const setField = (field: ConfigField, value: string) =>
    onChange((current) => ({ ...current, config: { ...current.config, [field]: value } }));
  const setPeers = (update: (peers: EditablePeer[]) => EditablePeer[]) =>
    onChange((current) => ({ ...current, config: { ...current.config, peers: update(current.config.peers) } }));
  const setPeerField = (id: string, field: PeerField, value: string) =>
    setPeers((peers) => peers.map((peer) => peer.id === id ? { ...peer, [field]: value } : peer));
  const setProperty = (id: string, changes: Partial<EditableProperty>) =>
    onChange((current) => ({
      ...current,
      advanced: current.advanced.map((property) => property.id === id ? { ...property, ...changes } : property),
    }));

  const field = (
    label: string, value: string, onValue: (value: string) => void,
    description: ReactNode, secret = false,
  ) => (
    <PanelSectionRow key={label}>
      <TextField
        label={label}
        description={description}
        value={value}
        disabled={disabled}
        bIsPassword={secret}
        onChange={(event) => onValue(event.target.value)}
      />
    </PanelSectionRow>
  );
  const configField = (name: ConfigField, label: string, description: ReactNode, secret = false) =>
    field(label, config[name], (value) => setField(name, value), description, secret);

  return (
    <>
      <PanelSectionRow>
        <div style={{ fontSize: "0.85em", opacity: 0.8, padding: "8px 0" }}>
          Fields match the [Interface] and [Peer] sections of a WireGuard .conf file.
          Separate multiple values with commas.
        </div>
      </PanelSectionRow>
      {configField("name", "Name", "Shown in the connection list.")}
      <Heading>Interface</Heading>
      {configField("private_key", "Private key", (
        <span style={{ overflowWrap: "anywhere" }}>
          {publicKey ? `Public key: ${publicKey}` : "This device's key. Its public key is shown here once valid."}
        </span>
      ), true)}
      {configField("addresses", "Address", "This device's tunnel IPs, e.g. 10.0.0.2/32, fd00::2/128.")}
      {configField("dns", "DNS", "Optional DNS servers and search domains used while connected.")}
      {config.peers.map((peer, index) => (
        <div key={peer.id}>
          <Heading>
            Peer{config.peers.length > 1 ? ` ${index + 1}` : ""}
            {peer.endpoint.trim() && ` \u00b7 ${peer.endpoint.trim()}`}
          </Heading>
          {[
            field("Public key", peer.public_key, (value) => setPeerField(peer.id, "public_key", value),
              "The peer's (server's) public key."),
            field("Preshared key", peer.preshared_key, (value) => setPeerField(peer.id, "preshared_key", value),
              "Optional extra shared secret.", true),
            field("Allowed IPs", peer.allowed_ips, (value) => setPeerField(peer.id, "allowed_ips", value),
              "Traffic sent through this peer. 0.0.0.0/0, ::/0 sends everything."),
            field("Endpoint", peer.endpoint, (value) => setPeerField(peer.id, "endpoint", value),
              "Server address and port, e.g. vpn.example.com:51820."),
            field("Persistent keepalive", peer.persistent_keepalive,
              (value) => setPeerField(peer.id, "persistent_keepalive", value),
              "Seconds, e.g. 25 to keep NAT open. Empty turns it off."),
          ]}
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={disabled}
              onClick={() => setPeers((peers) => peers.filter((entry) => entry.id !== peer.id))}
            >
              Remove peer{config.peers.length > 1 ? ` ${index + 1}` : ""}
            </ButtonItem>
          </PanelSectionRow>
        </div>
      ))}
      {config.peers.length === 0 && (
        <PanelSectionRow>
          <div style={{ fontSize: "0.85em", padding: "8px 0" }}>
            No peers. Add the server this device connects to.
          </div>
        </PanelSectionRow>
      )}
      <PanelSectionRow>
        <ButtonItem
          layout="below"
          disabled={disabled}
          onClick={() => setPeers((peers) => [...peers, newPeer(`new-peer-${nextId.current++}`)])}
        >
          Add peer
        </ButtonItem>
      </PanelSectionRow>
      {showAdvanced && (
        <>
          <Heading>Advanced interface</Heading>
          {configField("listen_port", "Listen port", "Local UDP port. Empty picks one automatically.")}
          {configField("mtu", "MTU", "Maximum packet size. Empty picks automatically.")}
          <Heading>NetworkManager properties</Heading>
          <PanelSectionRow>
            <div style={{ fontSize: "0.85em", opacity: 0.8, padding: "8px 0" }}>
              Other profile properties in nmcli syntax. Clear a value to reset it.
            </div>
          </PanelSectionRow>
          {draft.advanced.map((property) => (
            <PanelSectionRow key={property.id}>
              {property.isNew && (
                <TextField
                  label="Property name"
                  description="For example ipv4.dns-priority."
                  value={property.key}
                  disabled={disabled}
                  onChange={(event) => setProperty(property.id, { key: event.target.value })}
                />
              )}
              <TextField
                label={property.isNew ? "Value" : advancedSettingLabel(property.key)}
                description={property.isNew ? undefined : property.key}
                value={property.value}
                disabled={disabled}
                onChange={(event) => setProperty(property.id, { value: event.target.value })}
              />
            </PanelSectionRow>
          ))}
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={disabled}
              onClick={() => onChange((current) => ({
                ...current,
                advanced: [...current.advanced, {
                  id: `new-property-${nextId.current++}`, key: "", value: "", originalValue: "", isNew: true,
                }],
              }))}
            >
              Add property
            </ButtonItem>
          </PanelSectionRow>
        </>
      )}
      <PanelSectionRow>
        <ButtonItem
          layout="below"
          aria-expanded={showAdvanced}
          onClick={() => setShowAdvanced((current) => !current)}
        >
          {showAdvanced ? "Hide advanced" : "Show advanced"}
        </ButtonItem>
      </PanelSectionRow>
    </>
  );
}
