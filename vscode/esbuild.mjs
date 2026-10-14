import { cpSync, mkdirSync } from "node:fs";
import * as esbuild from "esbuild";

// The panel webview uses VS Code's own icon font.
mkdirSync("dist/codicons", { recursive: true });
for (const file of ["codicon.css", "codicon.ttf"]) {
  cpSync(`node_modules/@vscode/codicons/dist/${file}`, `dist/codicons/${file}`);
}

const production = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

const ctx = await esbuild.context({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node20",
  outfile: "dist/extension.js",
  external: ["vscode"],
  minify: production,
  sourcemap: !production,
  legalComments: "external",
  logLevel: "info",
});

if (watch) {
  await ctx.watch();
} else {
  await ctx.rebuild();
  await ctx.dispose();
}
