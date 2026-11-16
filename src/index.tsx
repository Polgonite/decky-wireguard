import { callable, definePlugin } from "@decky/api";
import { ButtonItem, PanelSection, PanelSectionRow, staticClasses } from "@decky/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { FaShieldAlt } from "react-icons/fa";

type ConnectionState = "connected" | "connecting" | "disconnecting" | "disconnected" | "unknown";

interface Profile {
  uuid: string;
  name: string;
  device: string;
  state: ConnectionState;
}

type Result<T> = ({ success: true } & T) | { success: false; error: string };

const getProfiles = callable<[], Result<{ profiles: Profile[] }>>("get_profiles");
const setConnection = callable<[uuid: string, connected: boolean], Result<object>>("set_connection");

const stateLabels: Record<ConnectionState, string> = {
  connected: "Connected",
  connecting: "Connecting...",
  disconnecting: "Disconnecting...",
  disconnected: "Disconnected",
  unknown: "Unknown state",
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function Content() {
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pendingUuid, setPendingUuid] = useState<string | null>(null);
  const inFlight = useRef(false);
  const mounted = useRef(false);

  const loadProfiles = useCallback(async () => {
    const result = await getProfiles();
    if (!result.success) throw new Error(result.error);
    if (mounted.current) setProfiles(result.profiles);
  }, []);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    if (mounted.current) setBusy(true);
    try {
      await loadProfiles();
      if (mounted.current) setError(null);
    } catch (error) {
      if (mounted.current) setError(errorMessage(error));
    } finally {
      inFlight.current = false;
      if (mounted.current) setBusy(false);
    }
  }, [loadProfiles]);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
    };
  }, [refresh]);

  const changeConnection = async (profile: Profile) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setPendingUuid(profile.uuid);
    setError(null);
    let failure: string | null = null;
    try {
      const result = await setConnection(profile.uuid, profile.state !== "connected");
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

  return (
    <PanelSection title="WireGuard connections">
      <PanelSectionRow>
        <ButtonItem layout="below" disabled={busy} onClick={() => void refresh()}>
          {busy ? "Working..." : "Refresh"}
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
      {profiles === null && !error && (
        <PanelSectionRow>Loading profiles...</PanelSectionRow>
      )}
      {profiles?.length === 0 && (
        <PanelSectionRow>
          No WireGuard profiles found. Import a profile into NetworkManager in Desktop Mode first.
        </PanelSectionRow>
      )}
      {profiles?.map((profile) => {
        const transitioning = profile.state === "connecting" || profile.state === "disconnecting";
        const status = pendingUuid === profile.uuid ? "Applying change..." : stateLabels[profile.state];
        return (
          <PanelSectionRow key={profile.uuid}>
            <ButtonItem
              layout="below"
              label={profile.name}
              description={`${status}${profile.device ? ` on ${profile.device}` : ""} \u00b7 ${profile.uuid.slice(0, 8)}`}
              disabled={busy || error !== null || transitioning || profile.state === "unknown"}
              onClick={() => void changeConnection(profile)}
            >
              {pendingUuid === profile.uuid
                ? "Please wait..."
                : transitioning || profile.state === "unknown"
                  ? stateLabels[profile.state]
                  : profile.state === "connected" ? "Disconnect" : "Connect"}
            </ButtonItem>
          </PanelSectionRow>
        );
      })}
      <PanelSectionRow>
        <div style={{ fontSize: "0.85em", opacity: 0.75, paddingTop: 8 }}>
          Status comes from NetworkManager and refreshes every 5 seconds while this panel is open.
          Connected does not verify a peer handshake or internet access.
        </div>
      </PanelSectionRow>
    </PanelSection>
  );
}

export default definePlugin(() => ({
  name: "WireGuard",
  titleView: <div className={staticClasses.Title}>WireGuard</div>,
  content: <Content />,
  icon: <FaShieldAlt />,
}));
