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
  suppression. Triage needs the org admin role and a token with
  `triage:write`; without them the quick fixes offer to triage in the browser.
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
   result is a token stored in the editor's secret storage. It is read-only
   unless you pick **Read-only + triage** on the approval page, which lets an
   org admin triage from the editor. Servers that predate device login ask for
   an API key instead.

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
## Dependency patch review

**hibou: Review and Apply Dependency Patch** opens a trusted Hibou JSON patch
artifact in a read-only diff preview. After explicit confirmation, the language
server verifies the patch digest, exact base commit, affected files and unsaved
buffers before applying the batch. It does not upload source, stage changes,
commit or push. Build/tests are not run. Verification fields describe the
generator's checks; they are not an origin signature.

The import command requires the `hibou/remediationApply` capability.
Plain Git patches remain applicable with normal Git tooling; this
review action requires the JSON artifact's base/hash/file metadata.

**hibou: Prepare Batch Dependency Fixes** discovers committed independent npm
package-lock v3 modules and uses installed local Node/npm after explicit
workspace/execution consent. The review workspace supports Automatic, fresh
deps.dev suggestions and exact direct-dependency versions, module selection,
explicit major/prerelease choices, safe regeneration and read-only diff review.
Both original and generated lockfiles undergo strict native verification.
Unsupported manager/configuration layouts are explained; no manager is silently
substituted and no executable is downloaded.

**Create PR with Hibou** is a separately confirmed action for installations and
tokens with the required managed-generation/publication rights. It regenerates
the choices on Hibou at the same accessible source commit and requires review
of the managed diff before publishing. The local patch/source is not uploaded.

Managed execution requires an explicitly enabled, qualified Kubernetes workload
profile and a matching live controller. It is disabled by default.
Local generation/review/apply is unaffected; the extension reports the server's
readiness reason and never falls back to running package managers in the API pod.
