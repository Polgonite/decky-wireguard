import { callable, definePlugin } from "@decky/api";
import { ButtonItem, PanelSection, PanelSectionRow, staticClasses } from "@decky/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { FaChevronRight, FaShieldAlt } from "react-icons/fa";

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

const stateColors: Record<ConnectionState, string> = {
  connected: "#66c96b",
  connecting: "#9b9b9b",
  disconnecting: "#9b9b9b",
  disconnected: "#9b9b9b",
  unknown: "#9b9b9b",
};

function StatusCircle({ state }: { state: ConnectionState }) {
  return (
    <span
      aria-hidden="true"
      style={{
        backgroundColor: stateColors[state],
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
  const inFlight = useRef(false);
  const refreshing = useRef<Promise<void> | null>(null);
  const mounted = useRef(false);

  const loadProfiles = useCallback(async () => {
    const result = await getProfiles();
    if (!result.success) throw new Error(result.error);
    if (mounted.current) {
      setProfiles((previous) =>
        previous?.length === result.profiles.length &&
        previous.every((profile, index) => {
          const next = result.profiles[index];
          return next !== undefined && profile.uuid === next.uuid &&
            profile.name === next.name && profile.device === next.device &&
            profile.state === next.state;
        }) ? previous : result.profiles,
      );
    }
  }, []);

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
    await refreshing.current;
    if (!mounted.current) {
      inFlight.current = false;
      return;
    }
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

  const selectedProfile = profiles?.find((profile) => profile.uuid === selectedUuid);
  const transitioning = selectedProfile?.state === "connecting" || selectedProfile?.state === "disconnecting";
  const selectedStatus = error ? "Status unavailable" : pendingUuid === selectedProfile?.uuid
    ? "Applying change..."
    : selectedProfile ? stateLabels[selectedProfile.state] : "";

  return (
    <PanelSection title={selectedUuid === null ? "WireGuard connections" : "Manage connection"}>
      <PanelSectionRow>
        <ButtonItem
          layout="below"
          onClick={() => selectedUuid === null ? void refresh() : setSelectedUuid(null)}
          disabled={selectedUuid === null && busy}
        >
          {selectedUuid === null ? (busy ? "Working..." : "Refresh") : "Back to connections"}
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
      {selectedUuid === null && profiles?.length === 0 && (
        <PanelSectionRow>
          No WireGuard profiles found. Import a profile into NetworkManager in Desktop Mode first.
        </PanelSectionRow>
      )}
      {selectedUuid === null && profiles?.map((profile) => (
        <PanelSectionRow key={profile.uuid}>
          <ButtonItem layout="below" onClick={() => setSelectedUuid(profile.uuid)}>
            <span style={{ display: "flex", alignItems: "center", gap: 10, width: "100%" }}>
              <StatusCircle state={error || pendingUuid === profile.uuid ? "unknown" : profile.state} />
              <span style={{ flex: 1, textAlign: "left", overflowWrap: "anywhere" }}>
                {profile.name}
                <span style={{ display: "block", fontSize: "0.8em", opacity: 0.75 }}>
                  {error ? "Status unavailable" : pendingUuid === profile.uuid
                    ? "Applying change..." : stateLabels[profile.state]} · {profile.uuid.slice(0, 8)}
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
            label={selectedProfile.name}
            description={`${selectedStatus}${selectedProfile.device ? ` on ${selectedProfile.device}` : ""} \u00b7 ${selectedProfile.uuid.slice(0, 8)}`}
            disabled={busy || error !== null || transitioning || selectedProfile.state === "unknown"}
            onClick={() => void changeConnection(selectedProfile)}
          >
            {pendingUuid === selectedProfile.uuid
              ? "Please wait..."
              : transitioning || selectedProfile.state === "unknown"
                ? stateLabels[selectedProfile.state]
                : selectedProfile.state === "connected" ? "Disconnect" : "Connect"}
          </ButtonItem>
        </PanelSectionRow>
      )}
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
