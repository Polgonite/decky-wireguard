import { fetchNoCors } from "@decky/api";
import { ButtonItem, PanelSectionRow } from "@decky/ui";
import { useRef, useState } from "react";
import { version as installedVersion } from "../package.json";

const repository = "Polgonite/decky-wireguard";
const releasesURL = `https://api.github.com/repos/${repository}/releases?per_page=100`;

interface Build {
  version: string;
  url: string;
  hash: string;
  publishedAt: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function latestBuild(data: unknown): Build {
  if (!Array.isArray(data)) throw new Error("GitHub returned an invalid release list.");
  const builds: Build[] = [];
  for (const release of data) {
    if (!isRecord(release) || release.draft === true ||
        typeof release.tag_name !== "string" || !Array.isArray(release.assets) ||
        typeof release.published_at !== "string") continue;
    const version = release.tag_name.replace(/^v/, "");
    const publishedAt = Date.parse(release.published_at);
    if (!/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(version) || !Number.isFinite(publishedAt)) continue;
    const filename = `decky-wireguard-${version}.zip`;
    const url = `https://github.com/${repository}/releases/download/${encodeURIComponent(release.tag_name)}/${filename}`;
    const asset = release.assets.find((asset: unknown) =>
      isRecord(asset) && asset.name === filename && asset.state === "uploaded" &&
      asset.browser_download_url === url,
    );
    if (!isRecord(asset)) continue;
    // Keep the newest build even if its digest is missing; never silently downgrade.
    builds.push({
      version, url, publishedAt,
      hash: typeof asset.digest === "string" && /^sha256:[a-f0-9]{64}$/.test(asset.digest)
        ? asset.digest.slice(7) : "",
    });
  }
  builds.sort((left, right) => right.publishedAt - left.publishedAt);
  const build = builds[0];
  if (!build) throw new Error("No installable WireGuard build was found on GitHub.");
  return build;
}

interface Installer {
  call(
    route: string, artifact: string, name: string, version: string, hash: string, installType: number,
  ): Promise<unknown>;
}

export async function requestLatestBuild(): Promise<string> {
  // @decky/api has no public installer; use Decky's guarded native install route.
  const backend = (globalThis as typeof globalThis & { DeckyBackend?: Installer }).DeckyBackend;
  if (typeof backend?.call !== "function") {
    throw new Error("Decky's installer is unavailable. Update Decky Loader or install the ZIP manually.");
  }
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let data: unknown;
  try {
    data = await Promise.race([
      (async () => {
        const response = await fetchNoCors(releasesURL, {
          headers: { Accept: "application/vnd.github+json" },
        });
        if (!response.ok) {
          throw new Error(`GitHub update check failed (HTTP ${response.status}). Try again later.`);
        }
        return response.json();
      })(),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error("GitHub update check timed out. Try again.")), 15000);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
  const build = latestBuild(data);
  if (build.version === installedVersion) return `Already running the latest build (${installedVersion}).`;
  if (!build.hash) throw new Error("The latest GitHub build has no SHA-256 digest. Install it manually.");
  // UPDATE = 2 in Decky's PluginInstallType. Decky verifies the hash and reloads the plugin.
  await backend.call("utilities/install_plugin", build.url, "WireGuard", build.version, build.hash, 2);
  return `Confirm ${build.version} in Decky's installation dialog. This panel reloads after installation.`;
}

export function UpdateButton() {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  const update = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setMessage(null);
    setError(null);
    try {
      setMessage(await requestLatestBuild());
    } catch (error) {
      setError(error instanceof Error ? error.message : String(error));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  return (
    <PanelSectionRow>
      <ButtonItem
        layout="below"
        description={`Installed: ${installedVersion}. Includes GitHub development prereleases.`}
        disabled={busy}
        onClick={() => void update()}
      >
        {busy ? "Checking for updates..." : "Update to latest build"}
      </ButtonItem>
      {message && <div role="status" style={{ overflowWrap: "anywhere", padding: "8px 0" }}>{message}</div>}
      {error && <div role="alert" style={{ color: "#ffb5b5", overflowWrap: "anywhere", padding: "8px 0" }}>{error}</div>}
    </PanelSectionRow>
  );
}
