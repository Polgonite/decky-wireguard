import { callable, openFilePicker } from "@decky/api";
import {
  ButtonItem, ConfirmModal, DialogBody, Focusable, GamepadEvent, PanelSectionRow, showModal,
  staticClasses, useParams,
} from "@decky/ui";
import { SetStateAction, useCallback, useEffect, useRef, useState } from "react";
import { ConnectionEditor } from "./connection-editor";
import { returnToPlugin } from "./plugin-navigation";
import { useUISettings } from "./ui-settings";
import {
  AdvancedProperty, draftChanged, EditorDraft, emptyDraft, fromDraft, importConf, toDraft, WireGuardConfig,
} from "./wireguard-config";

type Result<T> = ({ success: true } & T) | { success: false; error: string };

const getConnectionConfig = callable<
  [uuid: string], Result<{ config: WireGuardConfig; advanced: AdvancedProperty[] }>
>("get_connection_config");
const setConnectionConfig = callable<
  [uuid: string, config: WireGuardConfig, advanced: AdvancedProperty[]], Result<object>
>("set_connection_config");
const getProfiles = callable<[], Result<{ profiles: { uuid: string; state: string }[] }>>("get_profiles");
const createConnectionConfig = callable<
  [config: WireGuardConfig, advanced: AdvancedProperty[]], Result<{ uuid: string }>
>("create_connection_config");
const readConfFile = callable<[path: string], Result<{ text: string }>>("read_conf_file");

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
  const uiSettings = useUISettings();
  const [draft, setDraft] = useState<EditorDraft | null>(null);
  const [saved, setSaved] = useState<EditorDraft | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const mounted = useRef(true);
  const request = useRef(0);
  const savingRef = useRef(false);
  const connectionUuid = useRef<string | null>(uuid === "new" ? null : uuid);
  const [importing, setImporting] = useState(false);
  const importingRef = useRef(false);

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
      if (connectionUuid.current === null) {
        const blank = emptyDraft();
        setDraft(blank);
        setSaved(blank);
        return true;
      }
      const result = await getConnectionConfig(connectionUuid.current);
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
    if (!draft || savingRef.current || importingRef.current) return;
    let changes: ReturnType<typeof fromDraft>;
    try {
      changes = fromDraft(draft);
    } catch (failure) {
      setError(errorMessage(failure));
      return;
    }
    savingRef.current = true;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      if (connectionUuid.current === null) {
        const result = await createConnectionConfig(changes.config, changes.advanced);
        if (!result.success) throw new Error(result.error);
        connectionUuid.current = result.uuid;
      } else {
        const result = await setConnectionConfig(connectionUuid.current, changes.config, changes.advanced);
        if (!result.success) throw new Error(result.error);
      }
      let state: string | undefined;
      try {
        const profiles = await getProfiles();
        if (profiles.success) state = profiles.profiles.find((profile) => profile.uuid === connectionUuid.current)?.state;
      } catch {
        // The save succeeded; only the reconnect hint depends on the current state.
      }
      if (!mounted.current) return;
      // Reload in place so the editor stays mounted and gamepad focus stays on Save.
      if (await load(false)) {
        setNotice(state === "disconnected"
          ? "Saved."
          : state === undefined
            ? "Saved. If connected, reconnect to apply changes."
            : "Saved. Reconnect to apply changes.");
      }
    } catch (failure) {
      if (mounted.current) setError(errorMessage(failure));
    } finally {
      savingRef.current = false;
      if (mounted.current) setSaving(false);
    }
  };

  const change = useCallback((update: SetStateAction<EditorDraft>) => {
    setError(null);
    setNotice(null);
    setDraft((current) => current && (typeof update === "function" ? update(current) : update));
  }, []);

  const importFile = async () => {
    if (savingRef.current || importingRef.current) return;
    importingRef.current = true;
    setImporting(true);
    setError(null);
    setNotice(null);
    try {
      // FILE = 0; Decky's ambient const enum cannot be used with isolatedModules.
      const file = await openFilePicker(0, "/home", true, true, undefined, ["conf"], false, false);
      if (!mounted.current) return;
      const result = await readConfFile(file.realpath);
      if (!result.success) throw new Error(result.error);
      if (!mounted.current || !draft) return;
      const imported = importConf(draft, result.text, file.path.split("/").pop() ?? "");
      change(imported);
      setNotice("Imported. Save to apply. Omitted keys, addresses, DNS and peers were cleared; omitted advanced settings were kept.");
    } catch (failure) {
      if (mounted.current && failure !== "User canceled") setError(errorMessage(failure));
    } finally {
      importingRef.current = false;
      if (mounted.current) setImporting(false);
    }
  };

  const dirty = draft !== null && saved !== null && draftChanged(draft, saved);
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const confirming = useRef(false);

  const leave = useCallback(() => {
    if (savingRef.current || importingRef.current) return;
    if (!dirtyRef.current) {
      returnToPlugin(connectionUuid.current);
      return;
    }
    if (confirming.current) return;
    confirming.current = true;
    showModal(
      <ConfirmModal
        strTitle="Discard unsaved changes?"
        strOKButtonText="Discard changes"
        strCancelButtonText="Keep editing"
        bDestructiveWarning
        onOK={() => {
          if (mounted.current) returnToPlugin(connectionUuid.current);
        }}
      />,
      undefined,
      {
        fnOnClose: () => {
          confirming.current = false;
        },
      },
    );
  }, [uuid]);

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
            {connectionUuid.current === null ? "New WireGuard connection"
              : saved ? `Edit ${saved.config.name}` : "Edit WireGuard connection"}
          </div>
          <PanelSectionRow>
            <ButtonItem layout="below" disabled={saving || importing} onClick={leave}>Back</ButtonItem>
          </PanelSectionRow>
          {uiSettings.error && <Message error>{`Advanced settings: ${uiSettings.error}`}</Message>}
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
              <PanelSectionRow>
                <ButtonItem
                  layout="below"
                  disabled={saving || loading || importing}
                  onClick={() => void importFile()}
                >
                  {importing ? "Importing..." : "Import .conf file"}
                </ButtonItem>
              </PanelSectionRow>
              <ConnectionEditor
                draft={draft}
                onChange={change}
                disabled={saving || importing}
                allowAdvanced={uiSettings.showAdvanced}
              />
              {(error || notice) && <Message error={error !== null}>{error ?? notice ?? ""}</Message>}
              <PanelSectionRow>
                <ButtonItem
                  layout="below"
                  disabled={saving || loading || importing || !dirty}
                  onClick={() => void save()}
                >
                  {saving ? "Saving..." : "Save"}
                </ButtonItem>
              </PanelSectionRow>
            </>
          )}
        </DialogBody>
      </Focusable>
    </div>
  );
}
