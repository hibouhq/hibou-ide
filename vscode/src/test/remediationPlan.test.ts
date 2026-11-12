import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

class Element {
  children: Element[] = [];
  textContent = "";
  className = "";
  value = "";
  checked = false;
  disabled = false;
  hidden = false;
  focused = false;
  readonly events = new Map<string, () => void>();
  constructor(readonly tag: string) {}
  append(...children: Element[]): void { this.children.push(...children); }
  replaceChildren(...children: Element[]): void { this.children = children; }
  addEventListener(event: string, handler: () => void): void { this.events.set(event, handler); }
  setAttribute(): void {}
  focus(): void { this.focused = true; }
  fire(event: string): void { this.events.get(event)?.(); }
}

function harness() {
  const ids = new Map<string, Element>();
  const get = (id: string) => {
    let node = ids.get(id);
    if (!node) { node = new Element(id); ids.set(id, node); }
    return node;
  };
  get("upgrade-level").value = "minor";
  const messages: unknown[] = [];
  let receive: (event: { data: unknown }) => void = () => {};
  const moduleInputs = () => get("modules").children.flatMap((module) => module.children.filter((node) => node.tag === "input"));
  runInNewContext(readFileSync(path.join(__dirname, "../../media/remediation-plan.js"), "utf8"), {
    acquireVsCodeApi: () => ({ getState: () => undefined, setState: () => {}, postMessage: (message: unknown) => messages.push(message) }),
    document: {
      getElementById: get, createElement: (tag: string) => new Element(tag),
      createTextNode: (text: string) => { const node = new Element("text"); node.textContent = text; return node; },
      querySelectorAll: moduleInputs,
    },
    window: { addEventListener: (_event: string, handler: (event: { data: unknown }) => void) => { receive = handler; } },
  });
  return {
    get, messages, moduleInputs,
    send: (data: unknown) => receive({ data }),
    last: () => JSON.parse(JSON.stringify(messages[messages.length - 1])),
  };
}

function prepared(count = 1) {
  return {
    id: "draft", root: "/repo", base_sha: "a".repeat(40), manager_version: "11.0.0",
    manager_path: "/usr/bin/npm", runtime_version: "v22.0.0", unavailable: [],
    units: [{
      id: "web", manifest: "web/package.json", vulns: ["TEST-1"],
      direct_packages: Array.from({ length: count }, (_, i) => ({
        name: `package-${i}`, version: "1.0.0", recommended_version: "1.0.1", can_select_version: true, declared: "^1.0.0",
      })),
    }],
  };
}

test("plan defaults to automatic without claiming resolved targets", () => {
  const h = harness();
  assert.equal(h.last().type, "ready");
  h.send({ type: "prepared", prepared: prepared() });
  assert.equal(h.get("generate").disabled, false);
  assert.match(h.get("versions").children[0].children[3].children[1].textContent, /Resolved during generation/);
  h.get("generate").fire("click");
  assert.deepEqual(h.last().selection, { unit_ids: ["web"], version_targets: {}, upgrade_level: "minor", allow_major: false });
});

test("exact version choices survive pagination and revising a failed draft", () => {
  const h = harness();
  h.send({ type: "prepared", prepared: prepared(41) });
  assert.equal(h.get("versions").children.length, 40);
  const mode = h.get("versions").children[0].children[2].children[0];
  mode.value = "exact"; mode.fire("change");
  const input = h.get("versions").children[0].children[3].children[0];
  input.value = "1.0.5"; input.fire("input");
  h.get("next").fire("click");
  assert.equal(h.get("versions").children.length, 1);
  h.get("previous").fire("click");
  assert.equal(h.get("versions").children[0].children[3].children[0].value, "1.0.5");
  h.send({ type: "error", message: "constraint conflict" });
  assert.equal(h.get("generate").disabled, true);
  h.send({ type: "revised", prepared: { ...prepared(41), id: "new-draft" } });
  h.get("generate").fire("click");
  assert.deepEqual(h.last().selection.version_targets.web, [{ name: "package-0", mode: "exact", version: "1.0.5", allow_prerelease: false }]);
});

test("major upgrades need explicit acknowledgment and excluded modules stay excluded", () => {
  const h = harness();
  const data = prepared();
  data.units.push({ ...data.units[0], id: "other", manifest: "other/package.json" });
  h.send({ type: "prepared", prepared: data });
  h.moduleInputs()[1].checked = false; h.moduleInputs()[1].fire("change");
  h.get("upgrade-level").value = "major"; h.get("upgrade-level").fire("change");
  const before = h.messages.length;
  h.get("generate").fire("click");
  assert.equal(h.messages.length, before);
  assert.equal(h.get("error").hidden, false);
  h.get("allow-major").checked = true;
  h.get("generate").fire("click");
  assert.deepEqual(h.last().selection.unit_ids, ["web"]);
  assert.equal(h.last().selection.allow_major, true);
});

test("apply or export failure does not invalidate a generated patch", () => {
  const h = harness();
  h.send({ type: "prepared", prepared: prepared() });
  h.send({ type: "readyArtifact" });
  h.send({ type: "reviewError", message: "affected file has local changes" });
  assert.equal(h.get("review").hidden, false);
  assert.equal(h.get("generate").disabled, true);
  assert.match(h.get("status").textContent, /still ready/);
});

test("unavailable-only plans cannot generate an empty batch", () => {
  const h = harness();
  h.send({ type: "prepared", prepared: { ...prepared(), units: [], unavailable: ["uv.lock: unsupported adapter"] } });
  assert.equal(h.get("generate").disabled, true);
  assert.equal(h.get("unavailable-block").hidden, false);
  assert.equal(h.get("unavailable").children[0].textContent, "uv.lock: unsupported adapter");
});
