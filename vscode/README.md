# hibou for VS Code

Shows [hibou](https://hibouhq.com) security findings in the files
they were found in. Works in VS Code and its derivatives (Cursor, Windsurf,
VSCodium, code-server, Theia).

- **Diagnostics** on the lines each scanner reported, moved onto your edited
  working copy with git. A finding whose code you changed stays visible and
  is marked "may already be fixed" until the next scan confirms it.
- **Hover** with rule, CWE, CVSS, EPSS, KEV, reachability and a link to hibou.
- **Quick fixes**: suppress with the scanner's own directive and a required
  justification (`// #nosec G101 -- reason`, `nosemgrep`, `eslint-disable-next-line`,
  `# nosec`, `gitleaks:allow`); accept the risk; mark a false positive; dispute a
  suppression. Triage needs a token with `triage:write` and the org admin role;
  otherwise the finding opens in the browser.
- **Check staged changes for secrets** (opt-in, Source Control title bar):
  sends `git diff --cached` to the hibou server, which scans it and stores
  nothing. Off until you agree; `hibou.secretCheck.enabled` is user-level only.
- **Findings view**, **status bar** (open findings and the PR's gate verdict),
  optional **coverage gutter**, and `.hibou.yaml` validation (with the Red Hat
  YAML extension).

No source code is sent to the hibou server.

## Setup

1. `hibou: Set Server URL` (or reuse the server from `hibou login`).
2. `hibou: Sign In` opens your browser with a one-time code (device login). The
   result is a read-only token stored in the editor's secret storage. Servers
   that predate device login ask for an API key instead.

The extension downloads the `hibou` binary matching your server's version from
the server itself and checks its sha256 before running it. Set `hibou.path` to
use a local binary instead. Both settings are user-level only: a workspace
cannot choose the binary the editor runs. hibou does not run in untrusted
workspaces, because it runs git there.

## Development

```sh
npm ci
npm run typecheck && npm test
npm run package        # hibou-<version>.vsix
```

The language server is `hibou lsp`, shipped with each hibou release; the
extension downloads it from your server. The extension ↔ server contract is
described in `PROTOCOL.md` at the root of the hibou-ide repository.
