import { callable, definePlugin, routerHook } from "@decky/api";
import {
  ButtonItem, Focusable, GamepadEvent, Navigation, PanelSection, PanelSectionRow, staticClasses,
  ToggleField,
} from "@decky/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { FaChevronRight, FaShieldAlt } from "react-icons/fa";
import { CONFIG_ROUTE, ConfigPage, configPath } from "./config-page";
import { useSelectedConnection } from "./plugin-navigation";
import { loadUISettings, saveUISettings, useUISettings } from "./ui-settings";
import { UpdateButton } from "./updater";

type ConnectionState = "connected" | "connecting" | "disconnecting" | "disconnected" | "unknown";
type HandshakeState = "inactive" | "waiting" | "established" | "timeout" | "unknown";

interface Profile {
  uuid: string;
  name: string;
  device: string;
  state: ConnectionState;
  handshake: HandshakeState;
  handshake_error: string | null;
  probe_sent: number | null;
  diagnostic_ref?: string;
}

interface PeerHealth {
  public_key: string;
  endpoint_ip: string | null;
  last_handshake: number | null;
  received_bytes: number;
  sent_bytes: number;
  diagnostic_ref?: string;
}

type Result<T> = ({ success: true } & T) | { success: false; error: string };
type StartupMode = "off" | "on_boot" | "after_boot";
interface StartupSettings {
  on_boot: boolean;
  after_boot: boolean;
  wait_for_steam: boolean;
  wait_for_internet: boolean;
  waiting: string | null;
}
interface LoggingSettings {
  enabled: boolean;
  debug: boolean;
  logging_error: string | null;
}

const getProfiles = callable<[], Result<{ profiles: Profile[]; startup_error?: string }>>("get_profiles");
const getLoggingSettings = callable<[], Result<LoggingSettings>>("get_logging_settings");
const setLoggingSettings = callable<[enabled: boolean, debug: boolean], Result<LoggingSettings>>(
  "set_logging_settings",
);
const getPeerHealth = callable<[uuid: string], Result<{ peers: PeerHealth[] }>>("get_peer_health");
const setConnection = callable<[uuid: string, connected: boolean], Result<object>>("set_connection");
const getStartupSettings = callable<[uuid: string], Result<StartupSettings>>("get_startup_settings");
const setStartup = callable<[uuid: string, mode: StartupMode], Result<object>>("set_startup");
const setStartupRequirements = callable<
  [uuid: string, waitForSteam: boolean, waitForInternet: boolean], Result<object>
>("set_startup_requirements");
const setSteamReadiness = callable<[ready: boolean, error: string | null], Result<object>>("set_steam_readiness");

function monitorSteamReadiness(): () => void {
  let stopped = false;
  let inFlight = false;
  let lastError: string | null = null;
  const report = async () => {
    if (stopped || inFlight) return;
    inFlight = true;
    let ready = false;
    let error: string | null = null;
    try {
      if (typeof App === "undefined" || typeof App.BHasCurrentUser !== "function" ||
          typeof App.GetServicesInitialized !== "function") {
        throw new Error("Steam UI login state is unavailable.");
      }
      ready = App.BHasCurrentUser() && App.GetServicesInitialized();
    } catch (failure) {
      error = errorMessage(failure);
    }
    try {
      const result = await setSteamReadiness(ready, error);
      if (!result.success) throw new Error(result.error);
      lastError = null;
    } catch (failure) {
      const message = errorMessage(failure);
      if (message !== lastError) console.error("WireGuard Steam readiness:", message);
      lastError = message;
    } finally {
      inFlight = false;
    }
  };
  void report();
  const timer = window.setInterval(() => void report(), 2000);
  return () => {
    stopped = true;
    window.clearInterval(timer);
    void (async () => {
      try {
        const result = await setSteamReadiness(false, null);
        if (!result.success) throw new Error(result.error);
      } catch (error) {
        console.error("WireGuard Steam readiness cleanup:", errorMessage(error));
      }
    })();
  };
}

const stateLabels: Record<ConnectionState, string> = {
  connected: "Connected",
  connecting: "Connecting...",
  disconnecting: "Disconnecting...",
  disconnected: "Disconnected",
  unknown: "Unknown state",
};

const handshakeLabels: Record<HandshakeState, string> = {
  inactive: "Disconnected",
  waiting: "Verifying peer...",
  established: "Peer verified",
  timeout: "No peer response after 30 seconds",
  unknown: "Peer status unavailable",
};

const stateColors: Record<HandshakeState, string> = {
  established: "#66c96b",
  waiting: "#e8c547",
  timeout: "#e56b6b",
  inactive: "#9b9b9b",
  unknown: "#9b9b9b",
};

function profileLabel(profile: Profile): string {
  if (profile.state === "connected" && profile.handshake === "established") return "";
  return profile.state === "connected" || profile.handshake === "timeout"
    ? handshakeLabels[profile.handshake] : stateLabels[profile.state];
}

function StatusCircle({ state, probeSent }: { state: HandshakeState; probeSent: number | null }) {
  const verified = state === "established";
  return (
    <span
      key={probeSent ?? "idle"}
      role={verified ? "img" : undefined}
      aria-label={verified ? handshakeLabels.established : undefined}
      aria-hidden={verified ? undefined : true}
      className={`decky-wireguard-status${probeSent != null ? " decky-wireguard-status--pulsing" : ""}`}
      style={{
        backgroundColor: stateColors[state],
        borderRadius: "50%",
        flexShrink: 0,
        height: 12,
        position: "relative",
        width: 12,
      }}
    />
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function formatHandshakeAge(timestamp: number | null): string {
  if (timestamp === null) return "Never";
  const age = Math.max(0, Math.floor(Date.now() / 1000 - timestamp));
  if (age < 60) return `${age}s ago`;
  if (age < 3600) return `${Math.floor(age / 60)}m ago`;
  if (age < 86400) return `${Math.floor(age / 3600)}h ago`;
  return `${Math.floor(age / 86400)}d ago`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(1)} ${units[unit]}`;
}

function LoggingControls({ onChange }: { onChange: () => void }) {
  const [settings, setSettings] = useState<LoggingSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const result = await getLoggingSettings();
        if (!result.success) throw new Error(result.error);
        if (active) setSettings(result);
      } catch (failure) {
        if (active) setError(errorMessage(failure));
      }
    })();
    return () => { active = false; };
  }, []);

  const save = async (enabled: boolean, debug: boolean) => {
    setSaving(true);
    setError(null);
    try {
      const result = await setLoggingSettings(enabled, debug);
      if (!result.success) throw new Error(result.error);
      setSettings(result);
      onChange();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <PanelSectionRow>
        <ToggleField
          label="Diagnostic logging"
          description="Anonymized tunnel status and resume events in wireguard-diagnostics.log."
          checked={settings?.enabled ?? false}
          disabled={saving || settings === null}
          onChange={(checked) => void save(checked, false)}
        />
      </PanelSectionRow>
      {settings?.enabled && (
        <PanelSectionRow>
          <ToggleField
            label="Debug logging"
            description="Peer and probe details while the panel is open."
            checked={settings.debug}
            disabled={saving}
            onChange={(checked) => void save(true, checked)}
          />
        </PanelSectionRow>
      )}
      {(error || settings?.logging_error) && (
        <PanelSectionRow>
          <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
            Diagnostics: {error ?? settings?.logging_error}
          </div>
        </PanelSectionRow>
      )}
    </>
  );
}

function Content() {
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pendingUuid, setPendingUuid] = useState<string | null>(null);
  const uiSettings = useUISettings();
  const [selectedUuid, setSelectedUuid] = useSelectedConnection();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [startup, setStartupSettings] = useState<(StartupSettings & { uuid: string }) | null>(null);
  const [startupError, setStartupError] = useState<string | null>(null);
  const [startupSettingsError, setStartupSettingsError] = useState<string | null>(null);
  const [peerHealth, setPeerHealth] = useState<{ uuid: string; peers: PeerHealth[] } | null>(null);
  const [peerHealthError, setPeerHealthError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const refreshing = useRef<Promise<void> | null>(null);
  const mounted = useRef(false);

  const loadProfiles = useCallback(async () => {
    const result = await getProfiles();
    if (!result.success) throw new Error(result.error);
    let settings: StartupSettings | null = null;
    let settingsError: string | null = null;
    if (selectedUuid && result.profiles.some((profile) => profile.uuid === selectedUuid)) {
      try {
        const response = await getStartupSettings(selectedUuid);
        if (!response.success) throw new Error(response.error);
        settings = response;
      } catch (error) {
        settingsError = errorMessage(error);
      }
    }
    if (mounted.current) {
      if (selectedUuid && !result.profiles.some((profile) => profile.uuid === selectedUuid)) {
        setSelectedUuid(null);
      }
      setStartupError(result.startup_error ?? null);
      setStartupSettingsError(settingsError);
      setStartupSettings(settings && selectedUuid
        ? { ...settings, uuid: selectedUuid } : null);
      setProfiles((previous) =>
        previous?.length === result.profiles.length &&
        previous.every((profile, index) => {
          const next = result.profiles[index];
          return next !== undefined && profile.uuid === next.uuid &&
            profile.name === next.name && profile.device === next.device &&
            profile.state === next.state && profile.handshake === next.handshake &&
            profile.handshake_error === next.handshake_error &&
            profile.probe_sent === next.probe_sent &&
            profile.diagnostic_ref === next.diagnostic_ref;
        }) ? previous : result.profiles,
      );
    }
  }, [selectedUuid, setSelectedUuid]);

  const refresh = useCallback(() => {
    if (inFlight.current) return;
    if (refreshing.current) return refreshing.current;
    refreshing.current = (async () => {
      try {
        await loadProfiles();
        if (mounted.current) setError(null);
      } catch (error) {
        if (mounted.current) setError(errorMessage(error));
      } finally {
        refreshing.current = null;
      }
    })();
    return refreshing.current;
  }, [loadProfiles]);

  useEffect(() => {
    mounted.current = true;
    let cancelled = false;
    void (async () => {
      await refreshing.current;
      if (!cancelled) await refresh();
    })();
    return () => {
      cancelled = true;
      mounted.current = false;
    };
  }, [refresh]);

  const refreshInterval = profiles?.some((profile) => profile.handshake === "waiting") ? 1000 : 5000;
  useEffect(() => {
    const timer = window.setInterval(() => void refresh(), refreshInterval);
    return () => window.clearInterval(timer);
  }, [refresh, refreshInterval]);

  const applyChange = async (profile: Profile, action: () => Promise<Result<object>>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setPendingUuid(profile.uuid);
    setError(null);
    await refreshing.current;
    if (!mounted.current) {
      inFlight.current = false;
      return;
    }
    let failure: string | null = null;
    try {
      const result = await action();
      if (!result.success) throw new Error(result.error);
    } catch (error) {
      failure = errorMessage(error);
    }
    try {
      await loadProfiles();
    } catch (error) {
      const refreshError = `Status refresh failed: ${errorMessage(error)}`;
      failure = failure ? `${failure} ${refreshError}` : refreshError;
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setError(failure);
        setBusy(false);
        setPendingUuid(null);
      }
    }
  };

  const selectedProfile = profiles?.find((profile) => profile.uuid === selectedUuid);
  useEffect(() => {
    let cancelled = false;
    let inFlight = false;
    setPeerHealth(null);
    setPeerHealthError(null);
    if (!selectedUuid || selectedProfile?.state !== "connected") {
      return () => {
        cancelled = true;
      };
    }
    const load = async () => {
      if (inFlight || cancelled) return;
      inFlight = true;
      try {
        const result = await getPeerHealth(selectedUuid);
        if (!result.success) throw new Error(result.error);
        if (!cancelled) {
          setPeerHealth({ uuid: selectedUuid, peers: result.peers });
          setPeerHealthError(null);
        }
      } catch (failure) {
        if (!cancelled) setPeerHealthError(errorMessage(failure));
      } finally {
        inFlight = false;
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selectedProfile?.state, selectedUuid]);
  const selectedStartup = startup?.uuid === selectedUuid ? startup : null;
  const transitioning = selectedProfile?.state === "connecting" || selectedProfile?.state === "disconnecting";
  const selectedStatus = error ? "Status unavailable" : pendingUuid === selectedProfile?.uuid
    ? "Applying change..."
    : selectedProfile ? profileLabel(selectedProfile) : "";
  const selectedDescription = `${selectedStatus}${selectedProfile?.device
    ? `${selectedStatus ? " on " : ""}${selectedProfile.device}` : ""}`;

  const indicatorState = (profile: Profile): HandshakeState => {
    if (error) return "unknown";
    if (pendingUuid === profile.uuid) {
      return profile.state === "disconnected" ? "waiting" : "inactive";
    }
    return profile.handshake;
  };

  const cancelButton = (event: GamepadEvent) => {
    event.preventDefault();
    event.stopPropagation();
    setSelectedUuid(null);
  };

  if (settingsOpen) {
    return (
      <Focusable onCancelButton={(event: GamepadEvent) => {
        event.preventDefault();
        event.stopPropagation();
        setSettingsOpen(false);
      }}>
        <PanelSection title="Settings">
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setSettingsOpen(false)}>
              Back to connections
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            <ToggleField
              label="Show advanced settings"
              description="Show advanced editor options and Smart connect wait controls."
              checked={uiSettings.showAdvanced}
              disabled={!uiSettings.loaded || uiSettings.saving}
              onChange={(checked) => void saveUISettings(checked)}
            />
          </PanelSectionRow>
          {uiSettings.error && (
            <PanelSectionRow>
              <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
                Advanced settings: {uiSettings.error}
              </div>
            </PanelSectionRow>
          )}
          {uiSettings.error && !uiSettings.loaded && !uiSettings.loading && (
            <PanelSectionRow>
              <ButtonItem layout="below" onClick={() => void loadUISettings()}>
                Retry loading settings
              </ButtonItem>
            </PanelSectionRow>
          )}
          <LoggingControls onChange={() => void refresh()} />
          <UpdateButton />
        </PanelSection>
      </Focusable>
    );
  }

  const panel = (
    <PanelSection title={selectedUuid === null ? "Connections" : "Manage connection"}>
      <style>{`
        .decky-wireguard-status::after {
          content: "";
          position: absolute;
          inset: 0;
          background-color: inherit;
          border-radius: inherit;
          opacity: 0;
          pointer-events: none;
        }
        .decky-wireguard-status--pulsing::after {
          animation: decky-wireguard-pulse 0.8s ease-out;
        }
        @keyframes decky-wireguard-pulse {
          0% { opacity: 0.5; transform: scale(1); }
          100% { opacity: 0; transform: scale(2.5); }
        }
        @media (prefers-reduced-motion: reduce) {
          .decky-wireguard-status::after { animation: none !important; }
        }
      `}</style>
      {selectedUuid !== null && (
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={() => setSelectedUuid(null)}>
            Back to connections
          </ButtonItem>
        </PanelSectionRow>
      )}
      {error && (
        <PanelSectionRow>
          <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
            {error}
            {profiles !== null && <div>Displayed status may be out of date.</div>}
          </div>
        </PanelSectionRow>
      )}
      {uiSettings.error && (
        <PanelSectionRow>
          <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
            Advanced settings: {uiSettings.error}
          </div>
        </PanelSectionRow>
      )}
      {startupError && (
        <PanelSectionRow>
          <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
            Automatic startup: {startupError} You can still connect manually.
          </div>
        </PanelSectionRow>
      )}
      {profiles === null && !error && (
        <PanelSectionRow>Loading profiles...</PanelSectionRow>
      )}
      {selectedUuid === null && profiles?.length === 0 && (
        <PanelSectionRow>
          No profiles found.
        </PanelSectionRow>
      )}
      {selectedUuid === null && profiles?.map((profile) => (
        <PanelSectionRow key={profile.uuid}>
          <ButtonItem layout="below" onClick={() => setSelectedUuid(profile.uuid)}>
            <span style={{ display: "flex", alignItems: "center", gap: 10, width: "100%" }}>
              <StatusCircle
                state={indicatorState(profile)}
                probeSent={error || pendingUuid === profile.uuid ? null : profile.probe_sent}
              />
              <span style={{ flex: 1, textAlign: "left", overflowWrap: "anywhere" }}>
                {profile.name}
                <span style={{ display: "block", fontSize: "0.8em", opacity: 0.75 }}>
                  {error ? "Status unavailable" : pendingUuid === profile.uuid
                    ? "Applying change..." : profileLabel(profile)}
                  {profile.handshake_error && <span role="alert" style={{ display: "block" }}>
                    {profile.handshake_error}
                  </span>}
                </span>
              </span>
              <FaChevronRight aria-hidden="true" />
            </span>
          </ButtonItem>
        </PanelSectionRow>
      ))}
      {selectedUuid !== null && !selectedProfile && profiles !== null && (
        <PanelSectionRow>Profile no longer available.</PanelSectionRow>
      )}
      {selectedProfile && (
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            label={<span style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <StatusCircle
                state={indicatorState(selectedProfile)}
                probeSent={error || pendingUuid === selectedProfile.uuid ? null : selectedProfile.probe_sent}
              />
              {selectedProfile.name}
            </span>}
            description={[selectedDescription, selectedProfile.handshake_error].filter(Boolean).join(" \u00b7 ")}
            disabled={busy || error !== null || transitioning || selectedProfile.state === "unknown"}
            onClick={() => void applyChange(
              selectedProfile,
              () => setConnection(selectedProfile.uuid, selectedProfile.state !== "connected"),
            )}
          >
            {pendingUuid === selectedProfile.uuid
              ? "Please wait..."
              : transitioning || selectedProfile.state === "unknown"
                ? stateLabels[selectedProfile.state]
                : selectedProfile.state === "connected" ? "Disconnect" : "Connect"}
          </ButtonItem>
        </PanelSectionRow>
      )}
      {selectedProfile && (
        <>
          {selectedProfile.state !== "connected" ? (
            <PanelSectionRow>
              <div style={{ fontSize: "0.85em", opacity: 0.75, padding: "8px 0" }}>
                Available when connected.
              </div>
            </PanelSectionRow>
          ) : peerHealthError ? (
            <PanelSectionRow>
              <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
                Peer details unavailable: {peerHealthError}
              </div>
            </PanelSectionRow>
          ) : peerHealth?.uuid !== selectedProfile.uuid ? (
            <PanelSectionRow>Loading peer details...</PanelSectionRow>
          ) : peerHealth.peers.length === 0 ? (
            <PanelSectionRow>No peer statistics available.</PanelSectionRow>
          ) : (
            <>
              {peerHealth.peers.map((peer, index) => (
                <PanelSectionRow key={peer.public_key}>
                  <div style={{ fontSize: "0.85em", overflowWrap: "anywhere", padding: "8px 0", width: "100%" }}>
                    <div>Peer {index + 1} · {peer.endpoint_ip ?? "No endpoint"}</div>
                    <div style={{ opacity: 0.75 }}>
                      Last handshake: {formatHandshakeAge(peer.last_handshake)}
                    </div>
                    <div style={{ opacity: 0.75 }}>
                      Received: {formatBytes(peer.received_bytes)} · Sent: {formatBytes(peer.sent_bytes)}
                    </div>
                  </div>
                </PanelSectionRow>
              ))}
            </>
          )}
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              onClick={() => {
                Navigation.Navigate(configPath(selectedProfile.uuid));
                Navigation.CloseSideMenus();
              }}
            >
              Edit configuration
            </ButtonItem>
          </PanelSectionRow>
          {startupSettingsError && (
            <PanelSectionRow>
              <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
                Startup settings unavailable: {startupSettingsError}
              </div>
            </PanelSectionRow>
          )}
          <PanelSectionRow>
            <ToggleField
              label="Connect during boot"
              description="Uses NetworkManager autoconnect."
              checked={selectedStartup?.on_boot ?? false}
              disabled={busy || error !== null || selectedStartup === null}
              onChange={(checked) => void applyChange(
                selectedProfile,
                () => setStartup(selectedProfile.uuid, checked ? "on_boot" : "off"),
              )}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <ToggleField
              label="Smart connect"
              description="Waits until the Deck has fully booted and processes known to cause problems are ready, then connects. Will let some traffic through outside the VPN before it decides to connect."
              checked={selectedStartup?.after_boot ?? false}
              disabled={busy || error !== null || selectedStartup === null}
              onChange={(checked) => void applyChange(
                selectedProfile,
                () => setStartup(selectedProfile.uuid, checked ? "after_boot" : "off"),
              )}
            />
          </PanelSectionRow>
          {uiSettings.showAdvanced && selectedStartup?.after_boot && (
            <>
              <PanelSectionRow>
                <ToggleField
                  label="Wait for Steam login"
                  description="Includes Offline Mode."
                  checked={selectedStartup.wait_for_steam}
                  disabled={busy || error !== null}
                  onChange={(checked) => void applyChange(
                    selectedProfile,
                    () => setStartupRequirements(
                      selectedProfile.uuid, checked, selectedStartup.wait_for_internet,
                    ),
                  )}
                />
              </PanelSectionRow>
              <PanelSectionRow>
                <ToggleField
                  label="Wait for internet"
                  description="NetworkManager checks internet on Wi-Fi, Ethernet or mobile data, not VPNs."
                  checked={selectedStartup.wait_for_internet}
                  disabled={busy || error !== null}
                  onChange={(checked) => void applyChange(
                    selectedProfile,
                    () => setStartupRequirements(
                      selectedProfile.uuid, selectedStartup.wait_for_steam, checked,
                    ),
                  )}
                />
              </PanelSectionRow>
            </>
          )}
          {selectedStartup?.waiting && (
            <PanelSectionRow>
              <div role="status" style={{ fontSize: "0.85em", padding: "8px 0" }}>
                {selectedStartup.waiting}
              </div>
            </PanelSectionRow>
          )}
        </>
      )}
      {selectedUuid === null && (
        <>
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              onClick={() => {
                Navigation.Navigate(configPath("new"));
                Navigation.CloseSideMenus();
              }}
            >
              Add connection
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setSettingsOpen(true)}>
              Settings
            </ButtonItem>
          </PanelSectionRow>
        </>
      )}
      {selectedProfile?.diagnostic_ref && (
        <PanelSectionRow>
          <div style={{ fontSize: "0.75em", opacity: 0.5, overflowWrap: "anywhere", paddingTop: 8 }}>
            Log: {[
              selectedProfile.diagnostic_ref,
              ...(selectedProfile.state === "connected" && peerHealth?.uuid === selectedProfile.uuid
                ? peerHealth.peers.flatMap((peer, index) =>
                  peer.diagnostic_ref ? [`Peer ${index + 1} = ${peer.diagnostic_ref}`] : [])
                : []),
            ].join(" · ")}
          </div>
        </PanelSectionRow>
      )}
    </PanelSection>
  );

  // Even a no-op cancel handler consumes B instead of letting Decky close the plugin.
  return <Focusable {...(selectedUuid === null ? {} : { onCancelButton: cancelButton })}>{panel}</Focusable>;
}

export default definePlugin(() => {
  const stopMonitoring = monitorSteamReadiness();
  routerHook.addRoute(CONFIG_ROUTE, ConfigPage, { exact: true });
  return {
    name: "WireGuard",
    titleView: <div className={staticClasses.Title}>WireGuard</div>,
    content: <Content />,
    icon: <FaShieldAlt />,
    onDismount: () => {
      routerHook.removeRoute(CONFIG_ROUTE);
      stopMonitoring();
    },
  };
});
