import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { binaryName, parseBinVersion, platformKey, safeVersionDir, sha256Hex } from "./platform";

const maxBinaryBytes = 200 * 1024 * 1024;

/**
 * Returns the hibou binary to run as the language server (ADR-042 §2):
 * the hibou.path setting when set, else the binary the configured server
 * serves, downloaded once per server version and checked against the sha256
 * from /api/v1/bin/version.
 */
export async function resolveBinary(context: vscode.ExtensionContext, server: string | undefined, log: vscode.OutputChannel): Promise<string> {
  const configured = userLevelPath();
  if (configured) return configured;
  if (!server) {
    throw new Error("Set the hibou server URL (or hibou.path) first.");
  }

  const key = platformKey(process.platform, process.arch);
  if (!key) throw new Error(`hibou does not ship a binary for ${process.platform}/${process.arch}; set hibou.path.`);

  const versionResp = await fetchWithTimeout(`${server}/api/v1/bin/version`, 15_000);
  if (!versionResp.ok) throw new Error(`${server}/api/v1/bin/version returned HTTP ${versionResp.status}`);
  const info = parseBinVersion(await versionResp.json());
  const expected = info.sha256[key]?.toLowerCase();
  if (!expected) throw new Error(`The hibou server serves no binary for ${key}; set hibou.path.`);

  const dir = vscode.Uri.joinPath(context.globalStorageUri, "bin", safeVersionDir(info.version)).fsPath;
  const target = path.join(dir, binaryName(process.platform));
  try {
    const existing = await fs.readFile(target);
    if (sha256Hex(existing) === expected) return target;
    log.appendLine(`Cached binary ${target} does not match the server checksum; downloading again.`);
  } catch {
    // not cached yet
  }

  const [os, arch] = key.split("/");
  log.appendLine(`Downloading hibou ${info.version} for ${key} from ${server}`);
  const data = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: `hibou: downloading language server ${info.version}` },
    async () => {
      const resp = await fetchWithTimeout(`${server}/api/v1/bin/${os}/${arch}`, 300_000);
      if (!resp.ok) throw new Error(`binary download returned HTTP ${resp.status}`);
      const declared = Number(resp.headers.get("content-length") ?? "0");
      if (declared > maxBinaryBytes) throw new Error("binary download is larger than expected");
      const buf = new Uint8Array(await resp.arrayBuffer());
      if (buf.byteLength > maxBinaryBytes) throw new Error("binary download is larger than expected");
      return buf;
    },
  );
  const actual = sha256Hex(data);
  if (actual !== expected) {
    throw new Error(`Downloaded binary checksum ${actual} does not match the server's ${expected}; not running it.`);
  }

  await fs.mkdir(dir, { recursive: true });
  const tmp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(tmp, data, { mode: 0o755 });
  await fs.rename(tmp, target);
  void pruneOldVersions(path.dirname(dir), path.basename(dir));
  return target;
}

/** hibou.path is machine-scoped, so a workspace cannot make the editor run
 * a binary of its choice; globalValue is read explicitly all the same. */
function userLevelPath(): string | undefined {
  const inspected = vscode.workspace.getConfiguration("hibou").inspect<string>("path");
  const value = inspected?.globalValue?.trim();
  return value ? value : undefined;
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(url, { signal: ctl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function pruneOldVersions(binRoot: string, keep: string): Promise<void> {
  try {
    for (const entry of await fs.readdir(binRoot)) {
      if (entry !== keep) await fs.rm(path.join(binRoot, entry), { recursive: true, force: true });
    }
  } catch {
    // best effort
  }
}
