export type PlanSelection = {
  unit_ids: string[];
  upgrade_level: string;
  allow_major: boolean;
  version_targets: Record<string, { name: string; mode: string; version: string; allow_prerelease: boolean }[]>;
};

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function selection(value: unknown): value is PlanSelection {
  return record(value)
    && Object.keys(value).every((key) => ["unit_ids", "upgrade_level", "allow_major", "version_targets"].includes(key))
    && Array.isArray(value.unit_ids) && value.unit_ids.length > 0 && value.unit_ids.length <= 50
    && value.unit_ids.every((id: unknown) => typeof id === "string")
    && typeof value.upgrade_level === "string" && ["patch", "minor", "major"].includes(value.upgrade_level)
    && typeof value.allow_major === "boolean"
    && record(value.version_targets)
    && Object.values(value.version_targets).every((targets) => Array.isArray(targets) && targets.length <= 200
      && targets.every((target: unknown) => record(target)
        && Object.keys(target).every((key) => ["name", "mode", "version", "allow_prerelease"].includes(key))
        && typeof target.name === "string" && target.name.length <= 214
        && typeof target.mode === "string" && ["exact", "gossip"].includes(target.mode)
        && typeof target.version === "string" && target.version.length > 0 && target.version.length <= 128
        && typeof target.allow_prerelease === "boolean"));
}

export function parsePlanSelection(value: unknown): PlanSelection {
  if (!selection(value)) throw new Error("Invalid dependency version selection.");
  return value;
}
