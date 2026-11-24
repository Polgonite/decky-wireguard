import { callable } from "@decky/api";
import { useEffect, useSyncExternalStore } from "react";

type Result = {
  success: true;
  show_advanced_settings: boolean;
  include_prereleases: boolean;
  auto_update_check: boolean;
} | { success: false; error: string };
const getSettings = callable<[], Result>("get_ui_settings");
const setSettings = callable<
  [showAdvanced: boolean, includePrereleases: boolean, autoUpdateCheck: boolean], Result
>("set_ui_settings");

export interface UIPreferences {
  showAdvanced: boolean;
  includePrereleases: boolean;
  autoUpdateCheck: boolean;
}

interface UISettings extends UIPreferences {
  loaded: boolean;
  loading: boolean;
  saving: boolean;
  error: string | null;
}

let settings: UISettings = {
  showAdvanced: false, includePrereleases: false, autoUpdateCheck: false,
  loaded: false, loading: false, saving: false, error: null,
};
const listeners = new Set<() => void>();
export const getUISettings = () => settings;

export function subscribeUISettings(listener: () => void) {
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

function preferences(result: Result & { success: true }): UIPreferences {
  return {
    showAdvanced: result.show_advanced_settings,
    includePrereleases: result.include_prereleases,
    autoUpdateCheck: result.auto_update_check,
  };
}

export async function loadUISettings() {
  if (settings.loaded || settings.loading) return;
  update({ loading: true, error: null });
  try {
    const result = await getSettings();
    if (!result.success) throw new Error(result.error);
    update({ ...preferences(result), loaded: true, loading: false });
  } catch (error) {
    update({ loading: false, error: errorMessage(error) });
  }
}

export async function saveUISettings(changes: Partial<UIPreferences>) {
  if (!settings.loaded || settings.loading || settings.saving) return;
  const next: UIPreferences = {
    showAdvanced: settings.showAdvanced,
    includePrereleases: settings.includePrereleases,
    autoUpdateCheck: settings.autoUpdateCheck,
    ...changes,
  };
  update({ saving: true, error: null });
  try {
    const result = await setSettings(next.showAdvanced, next.includePrereleases, next.autoUpdateCheck);
    if (!result.success) throw new Error(result.error);
    update({ ...preferences(result), saving: false });
  } catch (error) {
    update({ saving: false, error: errorMessage(error) });
  }
}

export function useUISettings() {
  const snapshot = useSyncExternalStore(subscribeUISettings, getUISettings);
  useEffect(() => { void loadUISettings(); }, []);
  return snapshot;
}
