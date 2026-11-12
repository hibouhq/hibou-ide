# hibou IDE protocol

The extensions in this repository are clients of `hibou lsp`, the language
server built into the `hibou` binary (`internal/lsp` in hibouhq/hibou). The
binary ships with each hibou release and the extensions download it from the
user's own server, so **the server side always matches the user's hibou
version, while the extensions update from the stores on their own schedule.**
One extension version therefore talks to every hibou version still in use.

This file is the contract between the two. Standard LSP 3.18 covers
diagnostics, hover and code actions; everything hibou-specific is below.

## Versioning

`initialize` returns:

```jsonc
{
  "capabilities": {
    "experimental": {
      "hibou": {
        "protocol": 1,                       // incremented on incompatible changes only
        "requests": ["hibou/status", "…"]    // hibou/* requests this server answers
      }
    }
  }
}
```

Rules:

- **Additive change** (new request, new optional field): add it to `requests`
  on the server; the protocol number does not change. Clients check `requests`
  before offering the feature and say "upgrade hibou" when it is missing.
- **Incompatible change** (renamed request, changed meaning or required field):
  increment `protocol`, and keep answering the previous protocol for at least
  one release cycle where possible.
- **Clients** support every protocol from 1 to their `supportedProtocol`
  (`vscode/src/extension.ts`, `SUPPORTED_PROTOCOL` in
  `jetbrains/.../LanguageServer.kt`). A server with a higher protocol gets an
  "update the extension" warning; a server without the `hibou` block is not a
  hibou language server.
- A `-32601` (method not found) answer means the server predates the request;
  clients turn it into "upgrade hibou".

CI (`scripts/compat.mjs`) starts `hibou lsp` from the latest hibou release and
checks this handshake.

## Startup

The client spawns `hibou lsp` with:

- `HIBOU_SERVER`: server URL (also in `initializationOptions.server`).
- `HIBOU_TOKEN`: the token from the IDE's secret store, **never** on the
  command line.

`initializationOptions`:

| Field | Type | Meaning |
|---|---|---|
| `server` | string | hibou base URL |
| `clientId` | `hibou-vscode` \| `hibou-intellij` | device-login client (ADR-043) |
| `clientName` | string | device name shown on the approval page |
| `org`, `repo` | string | override git-remote detection (`provider/slug`, repo slug) |
| `pollSeconds` | number | server poll interval, minimum 30 |
| `showSuppressed` | bool | also show suppressed and accepted findings |
| `secretCheck` | bool | user consented to `hibou/secretCheck` |

## Requests (client → server)

| Request | Params | Result |
|---|---|---|
| `hibou/status` | — | `Status[]`, one per git work tree |
| `hibou/findings` | `{uri?, root?, query?}`; `root` limits the list to one work tree (a `Status.root`); `query` is the web UI's filter language, evaluated by the server | `{findings: PanelFinding[], error?}`; positions mapped onto the current code (open buffer or file on disk); `error` explains an invalid query |
| | | A secret whose flagged lines no longer exist in the code has `history: true` (and `commit`, where it was found) and no `uri`: it is not underlined, but stays listed, since it remains in git history. |
| `hibou/cweSets` | — | the server's CWE lists and categories, `{version, sets: [{slug, name, kind, member_count}], categories: [...]}` (filter completion for `cwe-set:` / `cwe-category:`) |
| `hibou/cweSearch` | `{query, roots?}` | CWE catalog entries matching an id or title, `{version, entries: [{id, name, abstraction, …}]}`; `roots` with an empty query lists the pillars |
| `hibou/presets` | — | `{presets: [{id, name, query}], error?}`: the user's findings search presets (read-only; servers before ADR-042 answer `error`) |
| `hibou/refresh` | — | `Status[]` after re-querying hibou |
| `hibou/login/start` | — | `{userCode, verificationUri, verificationUriComplete, expiresIn}`; error `-32901` = server predates device login |
| `hibou/login/wait` | — | `{token, tokenName?, user?, expiresAt?}`; the client stores `token` |
| `hibou/login/cancel` | — | — |
| `hibou/logout` | — | revokes the IDE's own token, forgets it |
| `hibou/setToken` | `{token}` | verifies and installs a pasted token |
| `hibou/suppressionEdit` | `{uri, fingerprint, line, reason}` | `WorkspaceEdit` inserting the scanner's native directive |
| `hibou/triage` | `{uri, fingerprint, action, reason?, expiresInDays?}`, action ∈ `accept`, `false_positive`, `reopen`, `dispute`, `undispute` | `{ok, message, webUrl?}`; `webUrl` set when the token cannot triage |
| `hibou/coverage` | `{uri}` | `{covered[], uncovered[], partial[], commit?, message?}`, 0-based current lines |
| `hibou/secretCheck` | `{root?}` | `{block, findings[], message}`; sends the staged diff, stores nothing server-side |
| `hibou/remediationApply` | `{root, artifact}` | `{already_applied}`; explicitly applies a reviewed dependency batch to the exact base HEAD. Artifact contains `base_sha`, SHA-256, base64 `patch`, before/after hashes for each changed file, unit results and mandatory verification outcomes. Rejects staged/working-tree changes to affected files, unsaved buffers, undeclared patch paths and invalid hashes. No upload, commit, staging or push. Clients must check advertised support and confirm workspace trust, source trust and user review. Artifact verification fields are generator reports, not a cryptographic signature of origin. Generation, exact-version selection and managed execution are not implied by this apply capability. |
| `hibou/remediationPrepare` | `{root, consent_local, manifests?, vulns?, upgrade_level?}` | Local draft `{id, root, base_sha, branch, manager_version, manager_path, runtime_version, units[], unavailable[], expires_at}`. Initial qualified adapter: independent public npm package-lock v3. Reads committed inputs, discovers installed tools after consent, sends PURLs to Hibou, never uploads source or installs tools. |
| `hibou/remediationGenerate` | `{root, id, unit_ids, version_targets?, upgrade_level?, allow_major?}` | Verified JSON artifact. `version_targets` maps unit IDs to `{name, mode: exact|gossip, version, allow_prerelease}` arrays; omit for Automatic. The backend validates versions, policy, fresh Gossip recommendations and final resolved targets. Generation uses temporary local workspaces; no working-tree edit. Requests are cancellable; closing the review tab cancels an active local generation. |
| `hibou/remediationRevise` | `{root, id}` | New draft ID at the same unchanged HEAD/profile; existing artifacts/generation requests remain immutable. Preserves valid unit selection context; fresh source/suggestions require Prepare again. |
| `hibou/remediationManagedGenerate` | `{root, local_id, target_branch, consent_managed}` | Managed ready artifact plus `{job_id, revision, repository, target_branch, proposal_branch}`. Explicitly regenerates saved local choices through managed jobs at the same server-accessible commit; no local artifact/source upload. Requires managed capability/permissions and consent. Returned managed diff must be reviewed independently. |
| `hibou/remediationManagedPublish` | `{root, job_id, revision, sha256}` | Forge PR `{number, title, html_url}`. Only for a managed artifact generated/reviewed in this session at the matching revision/digest; server rechecks authorization, organization consent, forge permissions, artifact readiness and target head. No automatic merge/tag/release. |

## Notifications (client → server)

| Notification | Params |
|---|---|
| `hibou/repositories` | `{roots: [uri or path]}`: repositories the client knows (VS Code: the git extension's list, as in Source Control). The server tracks them in addition to its own shallow scan for nested checkouts. |

## Notifications (server → client)

| Notification | Params |
|---|---|
| `hibou/statusChanged` | one `Status` |

`Status`: `{root, state, message?, server?, user?, repo?{provider,org,repo}, webUrl?, branch?, snapshot?{id,commit,ref,createdAt,atHead}, counts?, truncated?, gate?{pr,state,passed,reasons?,url?}}`,
with `state` ∈ `unconfigured`, `signedOut`, `untracked`, `noSnapshot`, `ready`, `error`.

## Client-side commands

Code actions may carry commands the server does not advertise in
`executeCommandProvider`; the client implements them because they need a
dialog:

| Command | Argument | Client does |
|---|---|---|
| `hibou.suppress` | `{uri, fingerprint, line}` | asks for a justification, calls `hibou/suppressionEdit`, applies the edit |
| `hibou.triage` | `{uri, fingerprint, action}` | asks for a reason (and expiry for `accept`), calls `hibou/triage` |

Server-side commands, advertised in `executeCommandProvider` under the
`hibou.server.*` prefix so they never collide with the extensions' own
`hibou.*` commands: `hibou.server.openFinding [fingerprint]` (opens the browser
via `window/showDocument`), `hibou.server.refresh`.
