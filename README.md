# hibou IDE extensions

[hibou](https://hibouhq.com) security findings in your editor, on the lines
where they were found.

| Directory | Editors | Store |
|---|---|---|
| [`vscode/`](vscode/) | VS Code, Cursor, Windsurf, VSCodium, code-server, Theia | Visual Studio Marketplace, Open VSX |
| [`jetbrains/`](jetbrains/) | IntelliJ IDEA, GoLand, PyCharm, WebStorm, Rider, CLion, PhpStorm, RubyMine, Android Studio | JetBrains Marketplace |

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

Push a tag `vX.Y.Z`. CI builds both extensions, checks compatibility with the
latest hibou release, and publishes to each store whose secrets are set
(`VSCE_PAT`, `OVSX_PAT`, `JETBRAINS_*`, in the `marketplace` environment).
Versions `0.x` go out as VS Code pre-releases.

## License

GNU AGPL-3.0, see [LICENSE](LICENSE).
