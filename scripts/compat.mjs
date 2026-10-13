// Compatibility check: starts `hibou lsp` and checks the initialize handshake
// against the protocol versions the extensions support (PROTOCOL.md).
//
//   node scripts/compat.mjs /path/to/hibou
//
// Exits 0 with a warning when the binary predates `hibou lsp`.

import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const binary = process.argv[2];
if (!binary) {
  console.error("usage: node scripts/compat.mjs <hibou binary>");
  process.exit(2);
}

const vscodeSupported = Number(/export const supportedProtocol = (\d+);/.exec(readFileSync(new URL("../vscode/src/extension.ts", import.meta.url), "utf8"))?.[1]);
const jetbrainsSupported = Number(/const val SUPPORTED_PROTOCOL = (\d+)/.exec(readFileSync(new URL("../jetbrains/src/main/kotlin/com/hibouhq/hibou/ide/LanguageServer.kt", import.meta.url), "utf8"))?.[1]);
if (!vscodeSupported || !jetbrainsSupported) {
  console.error("could not read the supported protocol versions from the sources");
  process.exit(2);
}

if (spawnSync(binary, ["lsp", "--help"], { stdio: "ignore" }).status !== 0) {
  console.log(`::warning::${binary} has no 'lsp' command (hibou release before IDE support); nothing to check`);
  process.exit(0);
}

const child = spawn(binary, ["lsp"], { stdio: ["pipe", "pipe", "inherit"], env: { ...process.env, HIBOU_SERVER: "", HIBOU_TOKEN: "" } });
const timer = setTimeout(() => fail("no initialize response within 15s"), 15_000);
let buf = Buffer.alloc(0);

function send(msg) {
  const data = Buffer.from(JSON.stringify(msg));
  child.stdin.write(`Content-Length: ${data.length}\r\n\r\n`);
  child.stdin.write(data);
}

function fail(msg) {
  console.error(`::error::${msg}`);
  child.kill();
  process.exit(1);
}

child.stdout.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  for (;;) {
    const sep = buf.indexOf("\r\n\r\n");
    if (sep < 0) return;
    const len = Number(/Content-Length: (\d+)/i.exec(buf.subarray(0, sep).toString())?.[1]);
    if (buf.length < sep + 4 + len) return;
    const msg = JSON.parse(buf.subarray(sep + 4, sep + 4 + len).toString());
    buf = buf.subarray(sep + 4 + len);
    if (msg.id === 1) check(msg);
    if (msg.id === 2) {
      send({ jsonrpc: "2.0", method: "exit" });
      clearTimeout(timer);
    }
  }
});

child.on("exit", (code) => {
  if (code !== 0) fail(`hibou lsp exited with ${code} after shutdown/exit`);
  console.log("hibou lsp handshake OK");
});

function check(msg) {
  if (msg.error) fail(`initialize failed: ${JSON.stringify(msg.error)}`);
  const hibou = msg.result?.capabilities?.experimental?.hibou;
  if (!hibou || typeof hibou.protocol !== "number") fail("initialize result has no capabilities.experimental.hibou.protocol");
  const required = ["hibou/status", "hibou/findings", "hibou/login/start", "hibou/login/wait"];
  const missing = required.filter((r) => !hibou.requests?.includes(r));
  if (missing.length) fail(`server does not advertise ${missing.join(", ")}`);
  for (const [client, supported] of [["vscode", vscodeSupported], ["jetbrains", jetbrainsSupported]]) {
    if (hibou.protocol > supported) fail(`server speaks protocol ${hibou.protocol}; the ${client} client only supports up to ${supported}`);
  }
  console.log(`server ${msg.result.serverInfo?.version ?? "?"}: protocol ${hibou.protocol}, ${hibou.requests.length} requests`);
  send({ jsonrpc: "2.0", id: 2, method: "shutdown" });
}

send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { processId: process.pid, rootUri: null, capabilities: {}, initializationOptions: {} } });
