import assert from "node:assert/strict";
import { test } from "node:test";
import { countsLabel, Status, statusBar, statusForPath } from "../format";
import { binaryName, isInsecureRemote, normalizeServer, parseBinVersion, platformKey, safeVersionDir, sha256Hex } from "../platform";

test("platformKey maps Node platforms to the server's os/arch keys", () => {
  assert.equal(platformKey("linux", "x64"), "linux/amd64");
  assert.equal(platformKey("darwin", "arm64"), "darwin/arm64");
  assert.equal(platformKey("win32", "x64"), "windows/amd64");
  assert.equal(platformKey("linux", "ia32"), undefined);
  assert.equal(platformKey("freebsd", "x64"), undefined);
  assert.equal(binaryName("win32"), "hibou.exe");
  assert.equal(binaryName("linux"), "hibou");
});

test("sha256Hex", () => {
  assert.equal(sha256Hex(new TextEncoder().encode("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("normalizeServer follows the CLI rules", () => {
  assert.equal(normalizeServer("hibou.example.com"), "https://hibou.example.com");
  assert.equal(normalizeServer(" https://h.example.com/sub/ "), "https://h.example.com/sub");
  assert.equal(normalizeServer("ftp://x"), undefined);
  assert.equal(normalizeServer(""), undefined);
  assert.equal(isInsecureRemote("http://localhost:8080"), false);
  assert.equal(isInsecureRemote("http://127.0.0.1"), false);
  assert.equal(isInsecureRemote("http://[::1]:8080"), false);
  assert.equal(isInsecureRemote("http://hibou.example.com"), true);
  assert.equal(isInsecureRemote("https://hibou.example.com"), false);
});

test("parseBinVersion reads the data envelope and rejects anything else", () => {
  assert.deepEqual(parseBinVersion({ data: { version: "v1.2.3", sha256: { "linux/amd64": "ab" } } }), { version: "v1.2.3", sha256: { "linux/amd64": "ab" } });
  assert.throws(() => parseBinVersion({ version: "v1" }));
  assert.throws(() => parseBinVersion({ data: { version: "v1", sha256: null } }));
  assert.equal(safeVersionDir("../../etc"), ".._.._etc");
  assert.equal(safeVersionDir(""), "unknown");
});

test("status bar reflects counts and the gate", () => {
  const st: Status = {
    root: "/w/app",
    state: "ready",
    repo: { provider: "github", org: "acme", repo: "app" },
    counts: { high: 2, critical: 1, low: 4 },
    gate: { pr: "7", state: "failure", passed: false, reasons: ["1 new high"] },
    snapshot: { id: "s", commit: "0123456789abcdef", ref: "main", createdAt: "2026-10-13T10:00:00Z", atHead: false },
  };
  const view = statusBar(st);
  assert.equal(view.text, "$(shield) 1 critical · 2 high …  $(x) gate");
  assert.equal(view.warning, true);
  assert.match(view.tooltip, /ancestor 01234567 on main/);
  assert.match(view.tooltip, /1 new high/);
  assert.equal(countsLabel({}), "no open findings");
  assert.equal(statusBar({ root: "", state: "signedOut" }).text, "$(sign-in) hibou: sign in");
});

test("statusForPath picks the innermost workspace", () => {
  const a: Status = { root: "/w", state: "ready" };
  const b: Status = { root: "/w/nested", state: "untracked" };
  assert.equal(statusForPath([a, b], "/w/nested/x.go"), b);
  assert.equal(statusForPath([a, b], "/w/other.go"), a);
  assert.equal(statusForPath([a, b], "C:\\elsewhere"), a);
  assert.equal(statusForPath([b], "/w/nestedfile.go"), b); // falls back to the first
});
