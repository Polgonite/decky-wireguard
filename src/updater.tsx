import { fetchNoCors, toaster } from "@decky/api";
import { ButtonItem, Navigation, PanelSectionRow, QuickAccessTab } from "@decky/ui";
import { useRef, useState, useSyncExternalStore } from "react";
import { version as installedVersion } from "../package.json";
import { getUISettings, loadUISettings, subscribeUISettings, useUISettings } from "./ui-settings";

const repository = "Polgonite/decky-wireguard";
const releasesURL = `https://api.github.com/repos/${repository}/releases`;
// "Latest" is GitHub's newest published non-prerelease; it stays reachable however many
// development builds are published after it, unlike a fixed-size page of the release list.
const latestStableURL = `${releasesURL}/latest`;
const releaseListURL = `${releasesURL}?per_page=100`;

interface Build {
  version: string;
  url: string;
  hash: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const numeric = "0|[1-9]\\d*";
const identifier = `${numeric}|\\d*[A-Za-z-][0-9A-Za-z-]*`;
const semver = new RegExp(`^(${numeric})\\.(${numeric})\\.(${numeric})(?:-((?:${identifier})(?:\\.(?:${identifier}))*))?$`);

interface Version {
  core: string[];
  prerelease: string[];
}

function parseVersion(version: string): Version | null {
  const match = semver.exec(version);
  return match ? { core: match.slice(1, 4), prerelease: match[4]?.split(".") ?? [] } : null;
}

// Digit strings compare by length then text, so very large run IDs never lose precision.
function compareNumbers(left: string, right: string): number {
  return left.length - right.length || (left < right ? -1 : left > right ? 1 : 0);
}

// SemVer 2.0 precedence. Development tags are X.Y.Z-dev.<run>.<attempt>.sha<commit>, so they
// sort below X.Y.Z and in publication order among themselves.
export function compareVersions(left: string, right: string): number {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) throw new Error(`Cannot compare versions "${left}" and "${right}".`);
  for (let index = 0; index < 3; index++) {
    const difference = compareNumbers(a.core[index] as string, b.core[index] as string);
    if (difference) return difference;
  }
  if (!a.prerelease.length || !b.prerelease.length) return b.prerelease.length - a.prerelease.length;
  for (let index = 0; index < Math.min(a.prerelease.length, b.prerelease.length); index++) {
    const x = a.prerelease[index] as string;
    const y = b.prerelease[index] as string;
    const xNumeric = /^\d+$/.test(x);
    const yNumeric = /^\d+$/.test(y);
    const difference = xNumeric && yNumeric ? compareNumbers(x, y)
      : xNumeric ? -1 : yNumeric ? 1 : x < y ? -1 : x > y ? 1 : 0;
    if (difference) return difference;
  }
  return a.prerelease.length - b.prerelease.length;
}

// Highest installable version, not the newest publication date. Prereleases are only
// considered when the user opted in; GitHub's own prerelease flag is honored as well.
export function latestBuild(data: unknown, includePrereleases = false): Build {
  if (!Array.isArray(data)) throw new Error("GitHub returned an invalid release list.");
  let best: Build | undefined;
  for (const release of data) {
    if (!isRecord(release) || release.draft === true ||
        typeof release.tag_name !== "string" || !Array.isArray(release.assets) ||
        typeof release.published_at !== "string" || !Number.isFinite(Date.parse(release.published_at))) continue;
    const version = release.tag_name.replace(/^v/, "");
    const parsed = parseVersion(version);
    if (!parsed) continue;
    if (!includePrereleases && (release.prerelease !== false || parsed.prerelease.length > 0)) continue;
    const filename = `decky-wireguard-${version}.zip`;
    const url = `https://github.com/${repository}/releases/download/${encodeURIComponent(release.tag_name)}/${filename}`;
    const asset = release.assets.find((asset: unknown) =>
      isRecord(asset) && asset.name === filename && asset.state === "uploaded" &&
      asset.browser_download_url === url,
    );
    if (!isRecord(asset) || (best && compareVersions(version, best.version) <= 0)) continue;
    // Keep the highest build even if its digest is missing; never silently fall back to an older one.
    best = {
      version, url,
      hash: typeof asset.digest === "string" && /^sha256:[a-f0-9]{64}$/.test(asset.digest)
        ? asset.digest.slice(7) : "",
    };
  }
  if (!best) {
    throw new Error(includePrereleases
      ? "No installable WireGuard build was found on GitHub."
      : "No installable stable WireGuard release was found on GitHub.");
  }
  return best;
}

async function fetchJSON(url: string, optional: boolean): Promise<unknown> {
  const response = await fetchNoCors(url, { headers: { Accept: "application/vnd.github+json" } });
  if (optional && response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`GitHub update check failed (HTTP ${response.status}). Try again later.`);
  }
  return response.json();
}

async function fetchReleases(includePrereleases: boolean): Promise<unknown[]> {
  // Stable lookups never page through development releases. Opted-in lookups also read the
  // newest page, which holds the development builds, and the latest stable release explicitly.
  const [latest, list] = await Promise.all([
    fetchJSON(latestStableURL, true),
    includePrereleases ? fetchJSON(releaseListURL, false) : [],
  ]);
  if (!Array.isArray(list)) throw new Error("GitHub returned an invalid release list.");
  return latest === null ? list : [latest, ...list];
}

export type UpdateCheck =
  | { kind: "available"; build: Build }
  | { kind: "current"; version: string }
  | { kind: "newer"; version: string; latest: string };

export async function checkForUpdate(includePrereleases: boolean): Promise<UpdateCheck> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let releases: unknown[];
  try {
    releases = await Promise.race([
      fetchReleases(includePrereleases),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error("GitHub update check timed out. Try again.")), 15000);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
  const build = latestBuild(releases, includePrereleases);
  const difference = compareVersions(build.version, installedVersion);
  if (difference > 0) return { kind: "available", build };
  // Updates never downgrade, including from a development build to an older stable release.
  return difference === 0
    ? { kind: "current", version: installedVersion }
    : { kind: "newer", version: installedVersion, latest: build.version };
}

interface Installer {
  call(
    route: string, artifact: string, name: string, version: string, hash: string, installType: number,
  ): Promise<unknown>;
}

export async function requestLatestBuild(includePrereleases = false): Promise<string> {
  // @decky/api has no public installer; use Decky's guarded native install route.
  const backend = (globalThis as typeof globalThis & { DeckyBackend?: Installer }).DeckyBackend;
  if (typeof backend?.call !== "function") {
    throw new Error("Decky's installer is unavailable. Update Decky Loader or install the ZIP manually.");
  }
  const result = await checkForUpdate(includePrereleases);
  if (result.kind === "current") return `Already running the latest build (${result.version}).`;
  if (result.kind === "newer") {
    return `Installed ${result.version} is newer than the latest ${includePrereleases ? "available" : "stable"} ` +
      `release (${result.latest}). Nothing was installed; updates never downgrade.`;
  }
  const { build } = result;
  if (!build.hash) throw new Error("The latest GitHub build has no SHA-256 digest. Install it manually.");
  // UPDATE = 2 in Decky's PluginInstallType. Decky verifies the hash and reloads the plugin.
  await backend.call("utilities/install_plugin", build.url, "WireGuard", build.version, build.hash, 2);
  return `Confirm ${build.version} in Decky's installation dialog. This panel reloads after installation.`;
}

let availableVersion: string | null = null;
const availableListeners = new Set<() => void>();

function setAvailableVersion(version: string | null) {
  if (availableVersion === version) return;
  availableVersion = version;
  availableListeners.forEach((listener) => listener());
}

function subscribeAvailable(listener: () => void) {
  availableListeners.add(listener);
  return () => { availableListeners.delete(listener); };
}

const startupDelay = 30_000;
const changeDelay = 2_000;
const checkInterval = 12 * 60 * 60 * 1000;
const retryDelay = 10 * 60 * 1000;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// Checks GitHub while the plugin is loaded, but only when the user enabled automatic checks.
// It never installs anything; it toasts once per newly found version.
export function startUpdateMonitor(): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let generation = 0;
  let activeKey: string | null = null;
  let startup = true;
  const notified = new Set<string>();

  const run = async (id: number, includePrereleases: boolean) => {
    let delay = checkInterval;
    try {
      const result = await checkForUpdate(includePrereleases);
      if (stopped || id !== generation) return;
      if (result.kind === "available") {
        const { version } = result.build;
        setAvailableVersion(version);
        if (!notified.has(version)) {
          notified.add(version);
          toaster.toast({
            title: "WireGuard update available",
            body: `Version ${version} is available. Open WireGuard settings to install it.`,
            onClick: () => Navigation.OpenQuickAccessMenu(QuickAccessTab.Decky),
          });
        }
      } else {
        setAvailableVersion(null);
      }
    } catch (error) {
      if (stopped || id !== generation) return;
      console.error("WireGuard update check:", errorMessage(error));
      delay = retryDelay;
    }
    timer = setTimeout(() => void run(id, includePrereleases), delay);
  };

  const apply = () => {
    const settings = getUISettings();
    if (!settings.loaded) return;
    const key = settings.autoUpdateCheck ? String(settings.includePrereleases) : null;
    const wasStartup = startup;
    startup = false;
    if (key === activeKey && !wasStartup) return;
    activeKey = key;
    generation++;
    clearTimeout(timer);
    setAvailableVersion(null);
    if (key === null) return;
    const id = generation;
    timer = setTimeout(() => void run(id, settings.includePrereleases), wasStartup ? startupDelay : changeDelay);
  };

  const unsubscribe = subscribeUISettings(apply);
  void loadUISettings();
  apply();
  return () => {
    stopped = true;
    unsubscribe();
    clearTimeout(timer);
    setAvailableVersion(null);
  };
}

export function UpdateButton() {
  const settings = useUISettings();
  const available = useSyncExternalStore(subscribeAvailable, () => availableVersion);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  // Unreadable settings fall back to the safe stable channel.
  const subscribed = settings.loaded && settings.includePrereleases;

  const update = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setMessage(null);
    setError(null);
    try {
      setMessage(await requestLatestBuild(subscribed));
    } catch (error) {
      setError(error instanceof Error ? error.message : String(error));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  const channel = subscribed
    ? " You are subscribed to development updates." +
      (settings.showAdvanced ? "" : " To unsubscribe, show advanced settings and turn off development updates.")
    : settings.error && !settings.loaded ? " Settings are unavailable, so only stable releases are checked." : "";
  return (
    <PanelSectionRow>
      <ButtonItem
        layout="below"
        description={`Installed: ${installedVersion}.${channel}`}
        disabled={busy}
        onClick={() => void update()}
      >
        {busy ? "Checking for updates..." : "Update to latest build"}
      </ButtonItem>
      {available && !message && !error && (
        <div role="status" style={{ overflowWrap: "anywhere", padding: "8px 0" }}>Update available: {available}.</div>
      )}
      {message && <div role="status" style={{ overflowWrap: "anywhere", padding: "8px 0" }}>{message}</div>}
      {error && <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>{error}</div>}
    </PanelSectionRow>
  );
}
