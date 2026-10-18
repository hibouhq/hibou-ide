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

## Build

Needs JDK 21 and Gradle 9.8 (no wrapper is checked in):

```sh
gradle test buildPlugin      # build/distributions/hibou-intellij-<version>.zip
gradle runIde                # sandbox IDE with the plugin and LSP4IJ
gradle verifyPlugin          # compatibility against recommended IDE builds
```

`pluginSinceBuild = 251` (2025.1) is the oldest supported IDE; current
Android Studio is still in range.
