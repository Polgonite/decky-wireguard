import { callable } from "@decky/api";
import { useEffect, useSyncExternalStore } from "react";

type Result = { success: true; show_advanced_settings: boolean } | { success: false; error: string };
const getSettings = callable<[], Result>("get_ui_settings");
const setSettings = callable<[showAdvanced: boolean], Result>("set_ui_settings");

interface UISettings {
  showAdvanced: boolean;
  loaded: boolean;
  loading: boolean;
  saving: boolean;
  error: string | null;
}

let settings: UISettings = {
  showAdvanced: false, loaded: false, loading: false, saving: false, error: null,
};
const listeners = new Set<() => void>();
const getSnapshot = () => settings;

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

function update(changes: Partial<UISettings>) {
  settings = { ...settings, ...changes };
  listeners.forEach((listener) => listener());
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function loadUISettings() {
  if (settings.loaded || settings.loading) return;
  update({ loading: true, error: null });
  try {
    const result = await getSettings();
    if (!result.success) throw new Error(result.error);
    update({ showAdvanced: result.show_advanced_settings, loaded: true, loading: false });
  } catch (error) {
    update({ loading: false, error: errorMessage(error) });
  }
}

export async function saveUISettings(showAdvanced: boolean) {
  if (!settings.loaded || settings.loading || settings.saving) return;
  update({ saving: true, error: null });
  try {
    const result = await setSettings(showAdvanced);
    if (!result.success) throw new Error(result.error);
    update({ showAdvanced: result.show_advanced_settings, saving: false });
  } catch (error) {
    update({ saving: false, error: errorMessage(error) });
  }
}

export function useUISettings() {
  const snapshot = useSyncExternalStore(subscribe, getSnapshot);
  useEffect(() => { void loadUISettings(); }, []);
  return snapshot;
}
