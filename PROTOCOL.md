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
| `hibou/findings` | `{uri?}` | `PanelFinding[]` for one document or all |
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

Server-side commands: `hibou.openFinding [fingerprint]` (opens the browser via
`window/showDocument`), `hibou.refresh`.
