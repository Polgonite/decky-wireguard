import { callable, definePlugin, routerHook } from "@decky/api";
import {
  ButtonItem, DialogCheckbox, Navigation, PanelSection, PanelSectionRow, staticClasses,
} from "@decky/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { FaChevronRight, FaShieldAlt } from "react-icons/fa";
import { CONFIG_ROUTE, ConfigPage, configPath } from "./config-page";

type ConnectionState = "connected" | "connecting" | "disconnecting" | "disconnected" | "unknown";
type HandshakeState = "inactive" | "waiting" | "established" | "timeout" | "unknown";

interface Profile {
  uuid: string;
  name: string;
  device: string;
  state: ConnectionState;
  handshake: HandshakeState;
  handshake_error: string | null;
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

const getProfiles = callable<[], Result<{ profiles: Profile[]; startup_error?: string }>>("get_profiles");
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
  return profile.state === "connected" || profile.handshake === "timeout"
    ? handshakeLabels[profile.handshake] : stateLabels[profile.state];
}

function StatusCircle({ state }: { state: HandshakeState }) {
  return (
    <span
      aria-hidden="true"
      className="decky-wireguard-status"
      style={{
        backgroundColor: stateColors[state],
        animation: state === "waiting" ? "decky-wireguard-pulse 1.6s ease-in-out infinite" : undefined,
        borderRadius: "50%",
        flexShrink: 0,
        height: 12,
        width: 12,
      }}
    />
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function Content() {
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pendingUuid, setPendingUuid] = useState<string | null>(null);
  const [selectedUuid, setSelectedUuid] = useState<string | null>(null);
  const [startup, setStartupSettings] = useState<(StartupSettings & { uuid: string }) | null>(null);
  const [startupError, setStartupError] = useState<string | null>(null);
  const [startupSettingsError, setStartupSettingsError] = useState<string | null>(null);
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
            profile.handshake_error === next.handshake_error;
        }) ? previous : result.profiles,
      );
    }
  }, [selectedUuid]);

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
  const selectedStartup = startup?.uuid === selectedUuid ? startup : null;
  const transitioning = selectedProfile?.state === "connecting" || selectedProfile?.state === "disconnecting";
  const selectedStatus = error ? "Status unavailable" : pendingUuid === selectedProfile?.uuid
    ? "Applying change..."
    : selectedProfile ? profileLabel(selectedProfile) : "";

  const indicatorState = (profile: Profile): HandshakeState => {
    if (error) return "unknown";
    if (pendingUuid === profile.uuid) {
      return profile.state === "disconnected" ? "waiting" : "inactive";
    }
    return profile.handshake;
  };

  return (
    <PanelSection title={
selectedUuid === null ? "WireGuard connections" : "Manage connection"
    }>
      <style>{`
        @keyframes decky-wireguard-pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.65; transform: scale(0.9); }
        }
        @media (prefers-reduced-motion: reduce) {
          .decky-wireguard-status { animation: none !important; }
        }
      `}</style>
      <PanelSectionRow>
        <ButtonItem
          layout="below"
          onClick={() => {
            if (selectedUuid === null) {
              void refresh();
            } else {
              setSelectedUuid(null);
            }
          }}
          disabled={selectedUuid === null && busy}
        >
          {selectedUuid === null ? (busy ? "Working..." : "Refresh")
            : "Back to connections"}
        </ButtonItem>
      </PanelSectionRow>
      {error && (
        <PanelSectionRow>
          <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>
            {error}
            {profiles !== null && <div>Displayed status may be out of date.</div>}
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
          No WireGuard profiles found. Import a profile into NetworkManager in Desktop Mode first.
        </PanelSectionRow>
      )}
      {selectedUuid === null && profiles?.map((profile) => (
        <PanelSectionRow key={profile.uuid}>
          <ButtonItem layout="below" onClick={() => setSelectedUuid(profile.uuid)}>
            <span style={{ display: "flex", alignItems: "center", gap: 10, width: "100%" }}>
              <StatusCircle state={indicatorState(profile)} />
              <span style={{ flex: 1, textAlign: "left", overflowWrap: "anywhere" }}>
                {profile.name}
                <span style={{ display: "block", fontSize: "0.8em", opacity: 0.75 }}>
                  {error ? "Status unavailable" : pendingUuid === profile.uuid
                    ? "Applying change..." : profileLabel(profile)} · {profile.uuid.slice(0, 8)}
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
        <PanelSectionRow>Profile no longer available. Return to the connection list.</PanelSectionRow>
      )}
      {selectedProfile && (
        <PanelSectionRow>
          <ButtonItem
            layout="below"
            label={<span style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <StatusCircle state={indicatorState(selectedProfile)} />
              {selectedProfile.name}
            </span>}
            description={`${selectedStatus}${selectedProfile.device ? ` on ${selectedProfile.device}` : ""} \u00b7 ${selectedProfile.uuid.slice(0, 8)}${selectedProfile.handshake_error ? ` \u00b7 ${selectedProfile.handshake_error}` : ""}`}
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
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              description="Opens a full-screen editor."
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
            <DialogCheckbox
              controlled
              label="Connect during boot"
              description="Use NetworkManager autoconnect. May delay boot when offline."
              checked={selectedStartup?.on_boot ?? false}
              disabled={busy || error !== null || selectedStartup === null}
              onChange={(checked) => void applyChange(
                selectedProfile,
                () => setStartup(selectedProfile.uuid, checked ? "on_boot" : "off"),
              )}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <DialogCheckbox
              controlled
              label="Connect after boot"
              description="From next boot, connect once when the plugin loads and boot has finished. Disables NetworkManager autoconnect; reloads do not reconnect."
              checked={selectedStartup?.after_boot ?? false}
              disabled={busy || error !== null || selectedStartup === null}
              onChange={(checked) => void applyChange(
                selectedProfile,
                () => setStartup(selectedProfile.uuid, checked ? "after_boot" : "off"),
              )}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <DialogCheckbox
              controlled
              label="Wait for Steam login"
              description="For plugin-managed startup, wait until Steam finishes logging in, including Offline Mode."
              checked={selectedStartup?.wait_for_steam ?? true}
              disabled={busy || error !== null || selectedStartup === null}
              onChange={(checked) => selectedStartup && void applyChange(
                selectedProfile,
                () => setStartupRequirements(
                  selectedProfile.uuid, checked, selectedStartup.wait_for_internet,
                ),
              )}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <DialogCheckbox
              controlled
              label="Wait for internet"
              description="For plugin-managed startup, wait for NetworkManager to verify internet on Wi-Fi, Ethernet, or mobile data, not a VPN."
              checked={selectedStartup?.wait_for_internet ?? true}
              disabled={busy || error !== null || selectedStartup === null}
              onChange={(checked) => selectedStartup && void applyChange(
                selectedProfile,
                () => setStartupRequirements(
                  selectedProfile.uuid, selectedStartup.wait_for_steam, checked,
                ),
              )}
            />
          </PanelSectionRow>
          {selectedStartup?.waiting && (
            <PanelSectionRow>
              <div role="status" style={{ fontSize: "0.85em", padding: "8px 0" }}>
                {selectedStartup.waiting}
              </div>
            </PanelSectionRow>
          )}
        </>
      )}
      <PanelSectionRow>
        <div style={{ fontSize: "0.85em", opacity: 0.75, paddingTop: 8 }}>
          Status refreshes every second while verifying, otherwise every 5 seconds while this panel is open.
          Yellow waits up to 30 seconds for a new handshake or authenticated incoming traffic.
          Green confirms a peer response, not internet access or ongoing peer health.
        </div>
      </PanelSectionRow>
    </PanelSection>
  );
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
