import { Navigation, QuickAccessTab } from "@decky/ui";
import { useSyncExternalStore } from "react";

let selectedUuid: string | null = null;
const listeners = new Set<() => void>();

function selectConnection(uuid: string | null) {
  if (selectedUuid === uuid) return;
  selectedUuid = uuid;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

const getSelectedUuid = () => selectedUuid;

export function useSelectedConnection() {
  return [useSyncExternalStore(subscribe, getSelectedUuid), selectConnection] as const;
}

export function returnToPlugin(uuid: string | null) {
  selectConnection(uuid);
  Navigation.NavigateBack();
  Navigation.OpenQuickAccessMenu(QuickAccessTab.Decky);
}
