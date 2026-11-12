import { strict as assert } from "node:assert";
import { test } from "node:test";
import { parsePlanSelection } from "../remediationSelection";

test("accepts version-choice shapes without duplicating resolution rules", () => {
  const selection = {
    unit_ids: ["web"], upgrade_level: "minor", allow_major: false,
    version_targets: { web: [{ name: "dependency", mode: "exact", version: "1.2.3", allow_prerelease: false }] },
  };
  assert.deepEqual(parsePlanSelection(selection), selection);
});

test("rejects malformed or authority-overriding webview messages", () => {
  const valid = { unit_ids: ["web"], upgrade_level: "minor", allow_major: false, version_targets: {} };
  for (const value of [
    null, {}, { ...valid, root: "/other/repository" }, { ...valid, id: "another-draft" },
    { ...valid, unit_ids: [] }, { ...valid, upgrade_level: "latest" },
    { ...valid, version_targets: { web: [{ name: "dependency", mode: "force", version: "1", allow_prerelease: false }] } },
  ]) assert.throws(() => parsePlanSelection(value));
});
