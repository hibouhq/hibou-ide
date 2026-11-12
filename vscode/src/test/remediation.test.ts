import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { decodeArtifact } from "../remediationArtifact";

function fixture() {
  const patch = Buffer.from("diff --git a/package.json b/package.json\n");
  return {
    base_sha: "a".repeat(40),
    sha256: createHash("sha256").update(patch).digest("hex"),
    patch: patch.toString("base64"),
    changes: [{ path: "package.json", before_sha256: "b".repeat(64), after_sha256: "c".repeat(64) }],
    units: [{ id: "web" }],
    verification: [{ dependency_files_consistent: true, selected_vulns_addressed: true, no_introduced_vulns: true }],
  };
}

test("decodes a hash-verified batch without modifying its bytes", () => {
  const input = fixture();
  const result = decodeArtifact(JSON.stringify(input));
  assert.equal(result.patch, Buffer.from(input.patch, "base64").toString("utf8"));
  assert.deepEqual(result.artifact, input);
});

test("rejects corrupted, invalid and unverified artifacts", () => {
  for (const mutate of [
    (f: ReturnType<typeof fixture>) => { f.sha256 = "0".repeat(64); },
    (f: ReturnType<typeof fixture>) => { f.patch = "!invalid base64!"; },
    (f: ReturnType<typeof fixture>) => { f.patch = ""; },
    (f: ReturnType<typeof fixture>) => { f.verification[0].dependency_files_consistent = false; },
    (f: ReturnType<typeof fixture>) => { f.verification = []; },
    (f: ReturnType<typeof fixture>) => { f.base_sha = "main"; },
    (f: ReturnType<typeof fixture>) => { f.changes = []; },
  ]) {
    const input = fixture();
    mutate(input);
    assert.throws(() => decodeArtifact(JSON.stringify(input)));
  }
  assert.throws(() => decodeArtifact("null"));
  assert.throws(() => decodeArtifact("{"));
});
