# hibou IDE extensions

[hibou](https://hibouhq.com) security findings in your editor, on the lines
where they were found.

| Directory | Editors | Store |
|---|---|---|
| [`vscode/`](vscode/) | VS Code, Cursor, Windsurf, VSCodium, code-server, Theia | [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=hibouhq.hibou), [Open VSX](https://open-vsx.org/extension/hibouhq/hibou) |
| [`jetbrains/`](jetbrains/) | IntelliJ IDEA, GoLand, PyCharm, WebStorm, Rider, CLion, PhpStorm, RubyMine, Android Studio | [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/35258-hibou) |

Setup and features: https://hibouhq.com/latest/guide/ide-extensions/

Both are thin clients of `hibou lsp`, the language server built into the
`hibou` binary. The extensions download it from the user's hibou server, so it
always matches that server's version; [PROTOCOL.md](PROTOCOL.md) is the
contract that lets one extension version work with older and newer servers.

## Development

```sh
cd vscode && npm ci && npm run typecheck && npm test && npm run package
cd jetbrains && gradle test buildPlugin      # JDK 21, Gradle 9.8
node scripts/compat.mjs /path/to/hibou       # handshake with a hibou binary
```

## Releasing

Both plugins share one version. To release, publish a GitHub Release with a
new tag `vX.Y.Z` (Releases → Draft a new release → Generate release notes),
or:

```sh
gh release create vX.Y.Z --generate-notes
```

The Release workflow runs CI, attaches the VSIX and the plugin ZIP to the
release, and publishes to Open VSX (trusted publishing, no token) and the JetBrains
Marketplace (secrets `JETBRAINS_*` in the `marketplace` environment).

Manual steps:

- Visual Studio Marketplace: upload `hibou-vscode.vsix` from the GitHub
  Release on https://marketplace.visualstudio.com/manage/publishers/hibouhq
  (New extension the first time, then `…` → Update).
- JetBrains Marketplace, first version only: upload the plugin ZIP on
  https://plugins.jetbrains.com (JetBrains reviews new plugins).

## License

GNU AGPL-3.0, see [LICENSE](LICENSE).
