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
  AdvancedProperty, draftChanged, EditorDraft, emptyDraft, fromDraft, importConf, rebaseDraft, toDraft, WireGuardConfig,
} from "./wireguard-config";

type Result<T> = ({ success: true } & T) | {
  success: false; error: string; code?: "reload_required" | "uuid_exists"; uuid?: string;
};

const getConnectionConfig = callable<
  [uuid: string], Result<{ config: WireGuardConfig; advanced: AdvancedProperty[]; revision: string }>
>("get_connection_config");
const setConnectionConfig = callable<
  [uuid: string, config: WireGuardConfig, advanced: AdvancedProperty[], revision: string], Result<object>
>("set_connection_config");
const getProfiles = callable<[], Result<{ profiles: { uuid: string; state: string }[] }>>("get_profiles");
const createConnectionConfig = callable<
  [config: WireGuardConfig, advanced: AdvancedProperty[], requestUuid: string], Result<{ uuid: string }>
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
  const [saved, setSaved] = useState<{ draft: EditorDraft; revision: string | null } | null>(null);
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
  const creationId = useRef<string | null>(null);
  const [recovery, setRecovery] = useState<{ uuid: string; duplicate: boolean } | null>(null);
  const recovering = useRef(false);
  const needsReload = connectionUuid.current !== null && draft !== null && !saved?.revision;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async (reset: boolean, recoveryLoad?: {
    uuid: string; keep?: { base: EditorDraft; local: EditorDraft };
  }) => {
    const id = ++request.current;
    setLoading(true);
    setError(null);
    if (reset) {
      setDraft(null);
      setSaved(null);
    }
    try {
      const target = recoveryLoad?.uuid ?? connectionUuid.current;
      if (target === null) {
        const blank = emptyDraft();
        setDraft(blank);
        setSaved({ draft: blank, revision: null });
        return true;
      }
      const result = await getConnectionConfig(target);
      if (!result.success) throw new Error(result.error);
      if (typeof result.revision !== "string" || !result.revision) throw new Error("Missing profile revision.");
      if (mounted.current && id === request.current) {
        const loaded = toDraft(result.config, result.advanced);
        const keep = recoveryLoad?.keep;
        setDraft(keep ? rebaseDraft(keep.base, keep.local, loaded) : loaded);
        connectionUuid.current = target;
        setSaved({ draft: loaded, revision: result.revision });
        setRecovery(null);
        if (recoveryLoad) setNotice(keep ? "Reloaded. Review your edits before saving." : "Reloaded from NetworkManager.");
        return true;
      }
    } catch (failure) {
      if (mounted.current && id === request.current) {
        setError(reset || recoveryLoad ? errorMessage(failure) : `Saved, but the profile could not be reloaded: ${errorMessage(failure)}`);
      }
    } finally {
      if (mounted.current && id === request.current) setLoading(false);
    }
    return false;
  }, [uuid]);

  useEffect(() => {
    void load(true);
  }, [load]);

  const save = async () => {
    if (!draft || needsReload || recovery || recovering.current || savingRef.current || importingRef.current) return;
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
        creationId.current ??= crypto.randomUUID();
        const result = await createConnectionConfig(changes.config, changes.advanced, creationId.current);
        if (!result.success) {
          if (mounted.current && result.code === "uuid_exists" && result.uuid === creationId.current) {
            setRecovery({ uuid: creationId.current, duplicate: true });
          }
          throw new Error(result.error);
        }
        connectionUuid.current = result.uuid;
      } else {
        if (!saved?.revision) throw new Error("Reload the profile before saving.");
        const result = await setConnectionConfig(connectionUuid.current, changes.config, changes.advanced, saved.revision);
        if (!result.success) {
          if (mounted.current && result.code === "reload_required") {
            setRecovery({ uuid: connectionUuid.current, duplicate: false });
          }
          throw new Error(result.error);
        }
      }
      if (!mounted.current) return;
      setSaved({ draft, revision: null });
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

  const recover = async (keep: boolean) => {
    if (!recovery || !saved || !draft || recovering.current || savingRef.current || importingRef.current) return;
    recovering.current = true;
    try {
      await load(false, keep ? { uuid: recovery.uuid, keep: { base: saved.draft, local: draft } } : { uuid: recovery.uuid });
    } finally {
      recovering.current = false;
    }
  };

  const change = useCallback((update: SetStateAction<EditorDraft>) => {
    setError(null);
    setNotice(null);
    setDraft((current) => current && (typeof update === "function" ? update(current) : update));
  }, []);

  const importFile = async () => {
    if (needsReload || recovering.current || savingRef.current || importingRef.current) return;
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

  const dirty = !needsReload && draft !== null && saved !== null && draftChanged(draft, saved.draft);
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const confirming = useRef(false);

  const leave = useCallback(() => {
    if (savingRef.current || importingRef.current || recovering.current || (loading && needsReload)) return;
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
  }, [loading, needsReload]);

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
              : saved ? `Edit ${saved.draft.config.name}` : "Edit WireGuard connection"}
          </div>
          <PanelSectionRow>
            <ButtonItem layout="below" disabled={saving || importing || (loading && (needsReload || !!recovery))} onClick={leave}>Back</ButtonItem>
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
                  disabled={saving || loading || importing || needsReload}
                  onClick={() => void importFile()}
                >
                  {importing ? "Importing..." : "Import .conf file"}
                </ButtonItem>
              </PanelSectionRow>
              <ConnectionEditor
                draft={draft}
                onChange={change}
                disabled={saving || importing || loading || needsReload}
                allowAdvanced={uiSettings.showAdvanced}
              />
              {(error || notice) && <Message error={error !== null}>{error ?? notice ?? ""}</Message>}
              {recovery && (
                <>
                  {!recovery.duplicate && <PanelSectionRow>
                    <ButtonItem layout="below" disabled={loading || importing} onClick={() => void recover(true)}>
                      Reload and keep my edits
                    </ButtonItem>
                  </PanelSectionRow>}
                  <PanelSectionRow>
                    <ButtonItem layout="below" disabled={loading || importing} onClick={() => showModal(
                      <ConfirmModal strTitle="Discard this draft and open the saved profile?"
                        strOKButtonText="Discard draft" strCancelButtonText="Keep draft"
                        bDestructiveWarning onOK={() => { if (mounted.current) void recover(false); }} />,
                    )}>
                      {recovery.duplicate ? "Open existing profile" : "Discard edits and reload"}
                    </ButtonItem>
                  </PanelSectionRow>
                </>
              )}
              {needsReload && !saving && (
                <PanelSectionRow>
                  <ButtonItem layout="below" disabled={loading} onClick={() => void load(false)}>
                    Retry reload
                  </ButtonItem>
                </PanelSectionRow>
              )}
              <PanelSectionRow>
                <ButtonItem
                  layout="below"
                  disabled={saving || loading || importing || !!recovery || !dirty}
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
