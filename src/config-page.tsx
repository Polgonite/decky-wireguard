import { callable } from "@decky/api";
import {
  ButtonItem, ConfirmModal, DialogBody, Focusable, GamepadEvent, Navigation, PanelSectionRow, showModal,
  staticClasses, useParams,
} from "@decky/ui";
import { SetStateAction, useCallback, useEffect, useRef, useState } from "react";
import { ConnectionEditor } from "./connection-editor";
import {
  AdvancedProperty, draftChanged, EditorDraft, fromDraft, toDraft, WireGuardConfig,
} from "./wireguard-config";

type Result<T> = ({ success: true } & T) | { success: false; error: string };

const getConnectionConfig = callable<
  [uuid: string], Result<{ config: WireGuardConfig; advanced: AdvancedProperty[] }>
>("get_connection_config");
const setConnectionConfig = callable<
  [uuid: string, config: WireGuardConfig, advanced: AdvancedProperty[]], Result<object>
>("set_connection_config");
const getProfiles = callable<[], Result<{ profiles: { uuid: string; state: string }[] }>>("get_profiles");

export const CONFIG_ROUTE = "/decky-wireguard/config/:uuid";

export function configPath(uuid: string): string {
  return CONFIG_ROUTE.replace(":uuid", encodeURIComponent(uuid));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function Message({ error, children }: { error: boolean; children: string }) {
  return (
    <PanelSectionRow>
      <div
        role={error ? "alert" : "status"}
        style={{ color: error ? "#ffb5b5" : undefined, overflowWrap: "anywhere", padding: "8px 0" }}
      >
        {children}
      </div>
    </PanelSectionRow>
  );
}

/** Full-screen page for editing a connection, opened from the quick access panel. */
export function ConfigPage() {
  const { uuid } = useParams<{ uuid: string }>();
  const [draft, setDraft] = useState<EditorDraft | null>(null);
  const [saved, setSaved] = useState<EditorDraft | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const mounted = useRef(true);
  const request = useRef(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async (reset: boolean) => {
    const id = ++request.current;
    setLoading(true);
    setError(null);
    if (reset) {
      setDraft(null);
      setSaved(null);
    }
    try {
      const result = await getConnectionConfig(uuid);
      if (!result.success) throw new Error(result.error);
      if (mounted.current && id === request.current) {
        const loaded = toDraft(result.config, result.advanced);
        setDraft(loaded);
        setSaved(loaded);
        return true;
      }
    } catch (failure) {
      if (mounted.current && id === request.current) setError(errorMessage(failure));
    } finally {
      if (mounted.current && id === request.current) setLoading(false);
    }
    return false;
  }, [uuid]);

  useEffect(() => {
    void load(true);
  }, [load]);

  const save = async () => {
    if (!draft || saving) return;
    let changes: ReturnType<typeof fromDraft>;
    try {
      changes = fromDraft(draft);
    } catch (failure) {
      setError(errorMessage(failure));
      return;
    }
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const result = await setConnectionConfig(uuid, changes.config, changes.advanced);
      if (!result.success) throw new Error(result.error);
    } catch (failure) {
      if (mounted.current) {
        setError(errorMessage(failure));
        setSaving(false);
      }
      return;
    }
    let state: string | undefined;
    try {
      const profiles = await getProfiles();
      if (profiles.success) state = profiles.profiles.find((profile) => profile.uuid === uuid)?.state;
    } catch {
      // The save succeeded; only the reconnect hint depends on the current state.
    }
    if (!mounted.current) return;
    setSaving(false);
    // Reload in place so the editor stays mounted and gamepad focus stays on Save.
    if (await load(false)) {
      setNotice(state === "disconnected"
        ? "Saved."
        : state === undefined
          ? "Saved. If the tunnel is connected, disconnect and reconnect to apply the changes."
          : "Saved. Disconnect and reconnect to apply the changes.");
    }
  };

  const change = useCallback((update: SetStateAction<EditorDraft>) => {
    setError(null);
    setNotice(null);
    setDraft((current) => current && (typeof update === "function" ? update(current) : update));
  }, []);

  const dirty = draft !== null && saved !== null && draftChanged(draft, saved);
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const confirming = useRef(false);

  const leave = useCallback(() => {
    if (!dirtyRef.current) {
      Navigation.NavigateBack();
      return;
    }
    if (confirming.current) return;
    confirming.current = true;
    showModal(
      <ConfirmModal
        strTitle="Discard unsaved changes?"
        strDescription="Your changes to this connection have not been saved."
        strOKButtonText="Discard changes"
        strCancelButtonText="Keep editing"
        bDestructiveWarning
        onOK={() => {
          if (mounted.current) Navigation.NavigateBack();
        }}
      />,
      undefined,
      {
        fnOnClose: () => {
          confirming.current = false;
        },
      },
    );
  }, []);

  const cancelButton = useCallback((event: GamepadEvent) => {
    event.preventDefault();
    event.stopPropagation();
    leave();
  }, [leave]);

  return (
    <div style={{ marginTop: 40, height: "calc(100% - 40px)", overflowY: "auto", background: "#0005" }}>
      <Focusable onCancelButton={cancelButton}>
        <DialogBody style={{ maxWidth: 900, margin: "0 auto", padding: "16px 24px 48px" }}>
          <div className={staticClasses.Title} style={{ fontSize: 24, padding: "8px 0" }}>
            {saved ? `Edit ${saved.config.name}` : "Edit WireGuard connection"}
          </div>
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={leave}>Back</ButtonItem>
          </PanelSectionRow>
          {loading && draft === null && <Message error={false}>Loading configuration...</Message>}
          {error && draft === null && (
            <>
              <Message error>{`Configuration unavailable: ${error}`}</Message>
              <PanelSectionRow>
                <ButtonItem layout="below" disabled={loading} onClick={() => void load(true)}>
                  Retry
                </ButtonItem>
              </PanelSectionRow>
            </>
          )}
          {draft && (
            <>
              <ConnectionEditor draft={draft} onChange={change} disabled={saving} />
              {(error || notice) && <Message error={error !== null}>{error ?? notice ?? ""}</Message>}
              <PanelSectionRow>
                <ButtonItem
                  layout="below"
                  disabled={saving || loading || !dirty}
                  onClick={() => void save()}
                >
                  {saving ? "Saving..." : dirty ? "Save changes" : "No unsaved changes"}
                </ButtonItem>
              </PanelSectionRow>
            </>
          )}
        </DialogBody>
      </Focusable>
    </div>
  );
}
