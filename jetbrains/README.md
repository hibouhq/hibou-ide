# hibou for IntelliJ-based IDEs

The IntelliJ Platform client of hibou ADR-042 (IntelliJ IDEA, GoLand, PyCharm,
WebStorm, Rider, CLion, PhpStorm, RubyMine, Android Studio). It runs the same
language server as the VS Code extension (`hibou lsp`) through
[LSP4IJ](https://github.com/redhat-developer/lsp4ij), so diagnostics, hover and
quick fixes come from the server. The plugin adds sign-in, the status bar
widget, the Findings tool window, the coverage gutter, the opt-in staged-changes
secret check (Tools › hibou), the `.hibou.yaml` schema
and the two client-side commands (`hibou.suppress`, `hibou.triage`) that need a
dialog.

> **Status:** written but not yet compiled. The first CI run (`.github/workflows/ci.yml`)
> is its first build. LSP4IJ API names to check there if it fails:
> `StreamConnectionProvider.getInitializationOptions(VirtualFile?)`,
> `LanguageServerManager.getLanguageServer/stop/start`, `LSPCommandAction.commandPerformed`,
> `LSPIJUtils.applyWorkspaceEdit/toUriAsString/findResourceFor`.

## Build

Needs JDK 21 and Gradle 9.8 (no wrapper is checked in):

```sh
gradle test buildPlugin      # build/distributions/hibou-intellij-<version>.zip
gradle runIde                # sandbox IDE with the plugin and LSP4IJ
gradle verifyPlugin          # compatibility against recommended IDE builds
```

`pluginSinceBuild = 242` (2024.2) is the oldest platform LSP4IJ supports and
keeps the current Android Studio baseline in range.
