import { createHash } from "node:crypto";

type Artifact = {
  base_sha: string;
  sha256: string;
  patch: string;
  changes: { path: string; before_sha256: string; after_sha256: string }[];
  units: { id: string }[];
  verification: {
    dependency_files_consistent: boolean;
    selected_vulns_addressed: boolean;
    no_introduced_vulns: boolean;
  }[];
};

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function artifact(value: unknown): value is Artifact {
  return record(value)
    && typeof value.base_sha === "string" && /^[a-f0-9]{40}([a-f0-9]{24})?$/.test(value.base_sha)
    && typeof value.sha256 === "string" && /^[a-f0-9]{64}$/.test(value.sha256)
    && typeof value.patch === "string"
    && Array.isArray(value.changes) && value.changes.length > 0 && value.changes.length <= 200
    && value.changes.every((c: unknown) => record(c) && typeof c.path === "string"
      && typeof c.before_sha256 === "string" && /^[a-f0-9]{64}$/.test(c.before_sha256)
      && typeof c.after_sha256 === "string" && /^[a-f0-9]{64}$/.test(c.after_sha256))
    && Array.isArray(value.units) && value.units.length > 0
    && value.units.every((u: unknown) => record(u) && typeof u.id === "string")
    && Array.isArray(value.verification) && value.verification.length === value.units.length
    && value.verification.every((v: unknown) => record(v)
      && v.dependency_files_consistent === true && v.selected_vulns_addressed === true && v.no_introduced_vulns === true);
}

export function decodeArtifact(text: string): { artifact: Artifact; patch: string } {
  const parsed: unknown = JSON.parse(text);
  if (!artifact(parsed)) throw new Error("Invalid or incompletely verified dependency-patch artifact.");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(parsed.patch)) {
    throw new Error("Invalid patch encoding.");
  }
  const bytes = Buffer.from(parsed.patch, "base64");
  if (!Buffer.from(bytes.toString("utf8"),"utf8").equals(bytes)) {
    throw new Error("Patch is not valid UTF-8 text and cannot be reviewed safely.");
  }
  if (bytes.length === 0 || bytes.length > 32 * 1024 * 1024
    || createHash("sha256").update(bytes).digest("hex") !== parsed.sha256) {
    throw new Error("Patch integrity verification failed.");
  }
  return { artifact: parsed, patch: bytes.toString("utf8") };
}
