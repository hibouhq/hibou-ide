// Pure helpers for fetching the language-server binary from the hibou server.
// No vscode import, so they can be unit-tested with node --test.

import { createHash } from "node:crypto";

/** The "os/arch" key the server uses in /api/v1/bin/version, or undefined
 * when it serves no binary for this platform. */
export function platformKey(platform: string, arch: string): string | undefined {
  const os = ({ linux: "linux", darwin: "darwin", win32: "windows" } as Record<string, string>)[platform];
  const cpu = ({ x64: "amd64", arm64: "arm64" } as Record<string, string>)[arch];
  return os && cpu ? `${os}/${cpu}` : undefined;
}

export function binaryName(platform: string): string {
  return platform === "win32" ? "hibou.exe" : "hibou";
}

export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Normalises a server URL the way the CLI does (ADR-043): https by default,
 * no trailing slash. Returns undefined for unusable input. */
export function normalizeServer(raw: string): string | undefined {
  let s = raw.trim();
  if (!s) return undefined;
  if (!s.includes("://")) s = "https://" + s;
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
  return s.replace(/\/+$/, "");
}

/** Plain http is only acceptable to a loopback server, as in the CLI. */
export function isInsecureRemote(server: string): boolean {
  const url = new URL(server);
  if (url.protocol !== "http:") return false;
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return !(host === "localhost" || host === "::1" || /^127\./.test(host));
}

export interface BinVersion {
  version: string;
  sha256: Record<string, string>;
}

export function parseBinVersion(body: unknown): BinVersion {
  const data = (body as { data?: unknown })?.data as Partial<BinVersion> | undefined;
  if (!data || typeof data.version !== "string" || typeof data.sha256 !== "object" || data.sha256 === null) {
    throw new Error("unexpected /api/v1/bin/version response");
  }
  return { version: data.version, sha256: data.sha256 as Record<string, string> };
}

/** A version string safe to use as a directory name. */
export function safeVersionDir(version: string): string {
  return version.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64) || "unknown";
}
