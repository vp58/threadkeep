# Disco Party dual Discord orchestrator security review

Date: 2026-08-29

Scope: Claude `#claude` orchestrator, Codex `#chatgpt` orchestrator, shared Discord infrastructure, ChatGPT subscription authentication, requested full-access mode, shared Vault skills, migration, monitoring, and public-channel behavior on an Apple M5 Max Mac.

## Executive decision

**Code decision: conditional pass for independent destination-trust and execution-authority modes, including public danger-full-access after exact documented risk acceptance.**

**Deployment decision: HOLD.** No live service, token, LaunchAgent, tmux session, Discord configuration, commit, push, or website deployment was changed by this review. Live activation requires the owner's exact approval and the supervised acceptance sequence in this document.

The design can support the intended topology in two declared authority modes:

- Claude remains on its dedicated bot and public `#claude` channel.
- Codex uses a different dedicated bot and public `#chatgpt` channel.
- Only the exact configured owner can trigger Codex work.
- Discord events arrive through persistent Gateway WebSockets. Normal message handling is not a cron poll.
- Codex uses the official App Server in Codex CLI `0.151.0`, `gpt-5.6-sol`, OpenAI provider, Ultra reasoning, and a separate managed ChatGPT login. It refuses API-key mode.
- Workspace-write uses the reviewed root-denied, agent-network-denied profile. Danger-full-access requires the exact operator acknowledgment and may be paired with either `public` or `owner_private`; execution authority is independent of destination trust.
- Optional `owner_private` requires a truly private parent channel: `@everyone` View Channel denied, exact member View allows for the configured guild owner and dedicated bridge, no other role or member View allow, and no other effective reader.
- Skill-finder, ELI5, VinayTalks, and triage come from the same canonical Vault source used by Claude. Full mode also injects the canonical Vault `CLAUDE.md` bootstrap from outside its isolated working directory. No Codex-specific skill or instruction copy is maintained.
- Codex loads the exact canonical command-safety, written-text, and outbound-deny hooks from the Vault. Disco Party binds their complete file closure and verifies App Server discovery and run events.
- No Slack, email, or other third-party outbound sender is installed.

The most important full-access result is an accepted residual risk, not a containment claim. OpenAI's Hooks documentation describes hooks as guardrails rather than a complete security boundary. Exact Codex CLI `0.151.0` behavior confirms that a `PreToolUse` hook blocks only when it successfully returns exit code 2. Process launch failures, timeouts, kills, malformed output, serialization failures, and other hook errors allow the tool to continue. App Server can detect the failed event and stop later work, but it cannot undo a shell command or patch that already ran. Private directories, file modes, hashes, bot separation, isolated login state, and Hooks improve integrity and reduce mistakes. The acknowledgment authorizes full mode operationally; it does not isolate the same-user process. Channel trust governs Discord visibility separately.

## Security board method

The review used three independent engineering lanes plus final integration review:

1. **Protocol and migration lane** reviewed Claude listener takeover, queue durability, runtime pinning, tmux health, message-gap recovery, and rollback behavior.
2. **Codex control-plane lane** reviewed App Server policy, ChatGPT authentication, shared skills, installer behavior, model and schema pinning, and real `0.151.0` protocol behavior.
3. **Red-team lane** attacked Discord identity binding, approval semantics, HTTP and WebSocket transport, heartbeat liveness, path boundaries, replay behavior, and same-user containment claims.
4. **Integration lane** reconciled the design, code, documentation, ELI5 artifact, current official documentation, and combined verification.

The board biased toward fail-closed behavior. Unknown identities, permissions, configuration layers, protocol requests, skill paths, delivery outcomes, migration state, and credential modes stop or quarantine work instead of guessing.

## Architecture under review

```text
PUBLIC DISCORD SERVER

#claude                                      #chatgpt
  |                                           |
  v                                           v
Claude Discord plugin                    Dedicated Codex Gateway
  |                                           |
  v                                           v
interactive listener tmux                exact owner and route checks
  |                                           |
  v                                           v
durable queue and markdown               private SQLite job ledger
  |                                           |
  v                                           v
Claude Agent worker                      bounded Codex App Server pool
  |                                           |
  v                                           v
public Discord thread                    public output filter
                                              |
                                              v
                                         public Discord thread
```

Claude's tmux session is the live listener and an observability surface. Codex runs headlessly under launchd; its optional tmux session is a read-only monitor. Closing the Codex monitor does not stop the worker.

## Protected assets

| Asset | Why it matters | Main controls | Remaining risk |
| --- | --- | --- | --- |
| Discord bot tokens | Let a process act as each bot | Separate Keychain accounts, dedicated bots, no argv or disk secrets, environment minimization, direct Keychain-to-process Claude launch | Same-user full access may inspect process memory or environment or query Keychain; a leaked token works outside Disco Party |
| Owner identity | Authorizes Codex ingress and Claude review buttons | Immutable Discord snowflake checks, exact guild, channel, application, bot, event, and message type binding | Owner Discord account takeover defeats this boundary |
| ChatGPT credential | Gives Codex subscription access | Isolated `CODEX_HOME`, exact official keyring backend, no API key, filesystem-credential rejection, `account/read` binding | Same-user full access may query Keychain; keyring is separation, not hard containment |
| Disco Party code and config | Define authorization and runtime behavior | Workspace overlap rejection, path ownership checks, runtime pins, isolated config, untrusted project roots | Same-user full access can alter user-owned control files |
| Conversation state | Prevents context loss and duplicate work | Durable queue, SQLite transactions, leases, fencing, policy fingerprints, append-once markers | Full compromise can alter state; uncertain external effects cannot always be undone |
| Discord output | May expose local or private data | Mention suppression, best-effort credential, card, and public-mode personal-detail masking, size limits | Redact-never-withhold filtering is not a confidentiality boundary and may miss sensitive material |
| Shared Vault skills | Become trusted per-turn instructions | Exact four-skill allowlist, full closure hash, path and ownership validation, policy binding, skill-finder on every turn, per-turn rechecks | Same-user full access can race or modify skills during an active turn |
| Canonical Vault P0 rules | Define approval, credential, preview, tool-routing, and publishing constraints | Exact six-section extraction, private mode `0400` snapshot, source and snapshot hashes, heading-drift rejection, Codex per-turn validation | Same-user full access can alter user-owned policy or bridge code and may attempt a change-and-restore race |
| Canonical Vault hooks | Add command, written-text, and outbound-deny checks to supported local tools | Exact three-hook allowlist, private isolated `hooks.json`, complete script-closure hash, `hooks/list` attestation, run-event monitoring, bounded timeouts | Framework or process failures can fail open; hosted and specialized tool paths may not run hooks |
| Outbound credentials | Could create third-party side effects | No outbound sender installed; obsolete watcher removed | A model with full access may reach unrelated same-user credentials unless stronger OS isolation is added |

## Trust boundaries

### Discord boundary

Claude's channel remains public for visibility. Codex may use public visibility or optional `owner_private`; neither setting changes its exact owner-only execution admission. Claude's plugin receives an exact per-channel allowlist containing only the owner and an empty direct-message allowlist. Codex admission requires the exact configured owner, guild, channel or managed child thread, bot, application, event type, and message type. Bots, webhooks, direct messages, non-owner users, empty content, and unrelated threads are ignored.

Preflight verifies the bot's effective permissions and its visibility inventory. The bot may see only `#chatgpt`, its exact parent category when required by Discord, and active public children beneath that channel. Any unrelated visible channel, category, private thread, announcement thread, or unrelated public thread stops startup or runtime.

The bot requires only the operational permission set. Broad guild management and extra channel capabilities fail closed. The `@everyone` overwrite explicitly denies thread creation and management, and only the configured bot's exact member overwrite restores public-thread creation. Role or other-member restorations fail closed. Public trust keeps `@everyone` View Channel effective. Owner-private trust instead requires an explicit `@everyone` View deny, exact member View allows only for the configured guild owner and dedicated bridge, no other role or member View allow, and no other effective reader. Runtime checks repeat after relevant Discord events and periodically.

### Local machine boundary

Safe mode uses a custom root-deny, temporary-directory-deny, agent-network-off permission profile scoped to one workspace. Full mode selects OpenAI's `:danger-full-access` profile and removes local sandbox restrictions only after the exact acknowledgment passes. Either destination-trust mode may select either execution profile. A separate operating-system identity or process broker remains the stronger containment design.

Both modes still run as the logged-in macOS user. Disco Party's isolated directories are separation within that account, not a separate security principal.

### Model-provider boundary

Claude and Codex use their official subscription clients. Codex requires managed ChatGPT authentication and refuses an OpenAI API key. Disco Party never converts ChatGPT OAuth material into an API credential or sends the Discord token to App Server.

Disco Party requires exact Keychain mode and rejects filesystem credential artifacts. It hashes the nonsecret email and plan facts returned by the authenticated App Server into durable policy without logging the email. The official Codex client, macOS Keychain, and OpenAI service own credential storage and upstream authentication.

### Third-party content boundary

Every Discord message, repository file, webpage, attachment, tool result, and externally retrieved item remains untrusted task content. Workspace `AGENTS.md` and fallback project instruction files are disabled for the headless Codex bridge. Only Disco Party's built-in instructions, the exact four canonical shared skills, and the separately validated instruction file may enter the trusted instruction plane. In full mode, the canonical Vault `CLAUDE.md` is selected automatically when no other trusted instruction file is configured.

## Findings and remediation

Severity reflects the intended full-access, public-channel deployment.

| Severity | Finding | Disposition |
| --- | --- | --- |
| Critical | HTTP clients could follow a Discord redirect while preserving a bot Authorization header | Fixed. Production Discord REST clients use direct no-proxy openers and reject every redirect before a credential can cross origins. Regression tests cover redirect refusal. |
| Critical | The legacy marker watcher did not bind every identity, action, target, and draft field | Hardened as standalone code, then removed from the supported production path. The installer removes its service and installs no outbound sender. |
| High | A Discord review reference could be mistaken for a durable send capability | Fixed in code instructions and docs. The reference is labeled review evidence only. External sends remain disabled without a separate one-time receipt gate. |
| High | The Claude Gateway sent heartbeats without requiring Discord OP 11 acknowledgment | Fixed. Missing ACK before the next interval aborts the socket and forces reconnect. Normal ACK and missing-ACK behavior have regression tests. |
| High | Codex workspace selection could overlap the canonical shared-skill source | Fixed. Bidirectional lexical, canonical, and inode overlap is rejected in runtime config and installer validation. Tests cover equal, ancestor, descendant, and macOS alias cases. |
| High | VinayTalks routing missed several common asset and artifact requests | Fixed. Deterministic routing covers diagrams, images, video, decks, documents, one-pagers, reports, PDFs, presentations, spreadsheets, worksheets, graphics, and sites while ordinary read, explain, review, summarize, and status turns remain text-only. |
| High | A half-completed Claude takeover could lose safe queued work or create dual processing | Fixed with explicit legacy validation, late quiesce, backup, gap reconciliation, listener drain handshake, digest-bound plan, ambiguity quarantine, and rollback fences. Live cutover remains pending. |
| High | Discord Gateway redirects could expose a bot token | Fixed for Codex and Claude with explicit no-redirect WebSocket clients and trusted Codex resume URL validation. |
| Critical | The first Claude compatibility design materialized a plaintext plugin `.env` | Fixed before deployment. The launcher now validates private state, reads Keychain only as its final credential step, and replaces itself with the pinned Claude process. The token is never placed in argv or on disk. Stale plugin `.env` files block launch and are removed during controlled install or uninstall. Same-user process-memory and Keychain access remain residual risks. |
| Critical | The first Codex authentication design forced plaintext file-store `auth.json` | Fixed before deployment. The isolated config now requires exact `keyring`, disables filesystem secret storage, keeps canonical macOS `HOME` for default Keychain access, and rejects `auth.json` and sibling artifacts throughout startup and turns. |
| High | The Codex installer and runtime retained a Discord bot-token environment fallback | Fixed before deployment. Production reads the Codex bot token only from its dedicated Keychain account. Interactive installation accepts a silent terminal input, while non-interactive installation requires a pre-provisioned Keychain item or the separately reviewed Keychain-to-Keychain legacy import. |
| High | Public members could create arbitrary threads and expand the bot's managed-thread inventory | Fixed before deployment. The verifier requires an explicit `@everyone` deny for Manage Threads, Create Public Threads, and Create Private Threads; requires Create Public Threads to be restored only by the configured bot's member overwrite; and rejects role, bot-role, and other-member restoration paths. Guild owners and Administrator members remain trusted because Discord lets them bypass channel overwrites. |
| High | Canonical Vault P0 rules could diverge between unattended Claude and Codex workers | Fixed. Disco Party mechanically derives one private snapshot from the six canonical P0 sections, rejects heading or content drift, binds the source and snapshot hashes, revalidates around every Codex turn, and supplies the same derived policy to Claude at launcher startup. |
| Critical | Official Codex `PreToolUse` hooks fail open when the hook framework or process fails outside the supported exit-code-2 denial path | Accepted only for explicit danger-full-access after the exact acknowledgment. Disco Party binds and attests the exact three canonical hooks as defense in depth, rejects their reported failures, and uses a deny-only outbound hook. Workspace-write retains its sandbox boundary regardless of destination trust. |
| Critical | The first shared-hook design executed canonical workspace scripts directly from an unsandboxed hook process, so the hook working directory and Python environment could influence imports before validation ran | Fixed before deployment. Disco Party binds the complete source closure, publishes a private content-addressed snapshot outside every writable root, requires exact modes and single-link files, and invokes absolute `/usr/bin/python3 -I -S` commands. Hostile working-directory and environment regression tests cover module shadowing and startup customization. Hooks remain guardrails; full mode accepts rather than removes their residual failure risk. |
| Medium | One serial Codex model worker would make unrelated Discord threads block each other | Fixed with a bounded one-through-four worker pool, default three. SQLite claims allow independent destinations to overlap while serializing one destination and blocking unresolved uncertain work. Built-in multi-agent remains disabled because the bridge cannot yet attest descendant lifecycle or hook events. |
| Medium | App Server's online skill-root documentation does not match installed `0.151.0` schema behavior | Compensated. Disco Party uses an exact private four-link bridge and verifies the real `skills/list` result instead of relying on the ignored field. Skill-finder discovers the broader canonical Vault through ordinary full-mode shell and file access. |
| Medium | App Server advertises `thread/items/list`, but installed `0.151.0` returns method-not-supported | Documented. Disco Party does not use unavailable item pagination as verification evidence. |
| Medium | Full-access language implied ChatGPT desktop Browser and Computer Use parity | Corrected. Full mode grants broad command authority but no first-class visual desktop host in this bridge. |
| Medium | Public-output filtering could be read as complete DLP | Corrected. It is best-effort redact-never-withhold masking for common patterns and excessive output, not a secrecy guarantee or confidentiality boundary. |
| Low | Production Python used an `assert` for an idempotency invariant | Fixed with an explicit runtime failure. |
| Low | Some subprocesses invoked generic `python3` instead of the verified runtime | Fixed by using `sys.executable` in production queue paths. |

## Discord transport and liveness

Both providers use Discord's event-driven Gateway, not a message-polling cron.

- A long-lived WebSocket receives new messages and interactions.
- Heartbeats keep the connection alive.
- Discord OP 11 heartbeat acknowledgments are required.
- Missing acknowledgments force reconnect rather than leaving a half-open listener.
- Gateway resume is attempted when a valid session and sequence exist.
- REST history reconciliation closes gaps from a durable cursor after reconnect.
- Dispatch work is separated from socket reading so slow REST, model, or storage work cannot starve heartbeats.
- Bounded queues fail closed by reconnecting and reconciling instead of dropping events silently.
- Persistent IDENTIFY budgets reduce restart-loop risk.

## ChatGPT subscription authentication

Disco Party uses a separately scoped Codex login rather than the user's normal `~/.codex` state:

1. The installer keeps canonical macOS `HOME` for Keychain access and creates a private isolated `CODEX_HOME`.
2. The isolated config sets `forced_login_method = "chatgpt"`.
3. The isolated config sets `cli_auth_credentials_store = "keyring"` and `features.secret_auth_storage = false`.
4. `OPENAI_API_KEY`, bot tokens, proxy credentials, and unrelated launchd secrets are removed from child environments.
5. Any `auth.json` or sibling filesystem credential artifact fails closed before and after login, initialization, account reads, refresh handling, and turns.
6. `codex login status` must report ChatGPT.
7. App Server `account/read` must return type `chatgpt`, a nonempty email, and a supported plan.
8. A domain-separated hash of the email and plan is included in the durable policy fingerprint without logging the email.

This uses the user's ChatGPT subscription entitlement. It does not call the OpenAI API with a manually supplied key.

## App Server and bleeding-edge features

Disco Party deliberately opts into the official experimental App Server capability because the owner accepted official bleeding-edge OpenAI features. It compensates for protocol maturity with strict pinning:

- Codex CLI `0.151.0`
- exact launcher and native arm64 binary hashes
- complete generated experimental schema bundle hash
- expected server request method set
- `gpt-5.6-sol`
- provider `openai`
- Ultra reasoning
- model fallback disabled

Unknown server requests fail closed. Interactive approval, elicitation, and unexpected tool paths receive explicit deny, abort, empty, or unsuccessful responses. Disco Party never calls App Server's user-initiated `thread/shellCommand`, which the official documentation states runs outside the sandbox.

An updated Codex CLI is not accepted automatically. Each update requires schema generation, request review, pin changes, unit tests, real preflight, and live Discord acceptance.

### Canonical lifecycle-hook guardrails

Disco Party derives the reviewed canonical Vault hook closure into a content-addressed private read-only runtime snapshot outside every writable root. Its isolated user-level `hooks.json` contains exactly three synchronous `PreToolUse` definitions and points only to that snapshot:

1. The command-safety validator for supported Bash tools.
2. The written-text validator for supported Bash and `apply_patch` tools.
3. The outbound-send validator in an explicit Disco Party deny-only mode.

The bridge binds the canonical source closure, sealed snapshot, manifest, and hook configuration. Snapshot directories are mode `0500`; files are single-link mode `0400`; commands use absolute `/usr/bin/python3 -I -S` paths and do not import from the working directory. Before startup and around turns, `hooks/list` must report the exact source path, source type, command, anchored matcher, timeout, current definition hash, enabled state, and expected trust state with no errors, warnings, plugin hooks, managed hooks, or extra entries. Hook start and completion notifications are monitored, and failed, stopped, malformed, or unexpected runs abort further work.

These checks detect drift and ordinary validator failures. They do not turn Hooks into authorization. OpenAI documents that hosted tools are not hooked and specialized paths can opt out. The tested CLI also permits a tool to continue when the hook process or framework fails outside a successful exit-code-2 denial. A later App Server abort cannot reverse an effect that already happened. Disco Party therefore uses Hooks only as guardrails. Danger-full-access proceeds only after explicit acceptance of that residual risk.

## Why full computer access requires acceptance

OpenAI's official permission model says `:danger-full-access` removes local sandbox restrictions. In this bridge that means broad same-user command authority, including shell, filesystem, process, and command-based network access where macOS permits it. A prompt-injected process could bypass instructions and Hooks by making a raw network connection, invoking an unhooked path, modifying same-user controls, or exploiting a hook failure. Exact operator acknowledgment does not change that technical boundary. Disco Party permits the mode only after the exact acknowledgment, independently of whether the destination is public or owner-private.

It does not add a visual host. OpenAI documents Browser as unavailable in Codex CLI and provides Computer Use through a separate ChatGPT desktop plugin with Screen Recording, Accessibility, app approvals, and its own host process. Disco Party's App Server client supplies no such host and sends an empty `dynamicTools` list.

Therefore, in the current design:

- Workspace-write Codex runs local commands only inside the reviewed workspace profile and can use either destination trust setting.
- Danger-full-access Codex may use either destination trust setting after the exact acknowledgment, accepting same-user and hook-failure risk.
- It cannot use the official first-class Browser or Computer Use capability through this Discord bridge.
- Adding visual desktop control later requires a separate design and security review.

### The defensible path to broader capability

No current official OpenAI setting makes unattended same-user full access fail closed. The next design should preserve useful reach by brokering specific capabilities:

1. Run App Server under a separate non-admin macOS service user with that user's own ChatGPT Keychain login and `account/read` binding.
2. Keep agent filesystem roots narrow and agent-tool network disabled.
3. Keep Discord tokens, third-party credentials, authorization state, and policy code under a different identity the model worker cannot read or modify.
4. Expose only narrow deny-by-default operations through reviewed App Server dynamic tools or a local broker. Each request must bind the exact action, destination, content hash, owner, expiry, and one-time receipt.
5. Keep Hooks as audit and supported-path guardrails. Do not use them as the broker's authorization decision.
6. Treat visual desktop access as a separate product and threat model. OpenAI's documented Computer Use host belongs to the desktop plugin and requires Screen Recording, Accessibility, and per-app approval. It is not a documented headless App Server capability.

This is not unrestricted access to the primary login session. That restriction is what creates a real security boundary.

## Shared canonical Vault skills

The Vault remains the single source of truth. Claude uses its canonical `.claude/skills` link. Codex's isolated skill directory contains exactly four absolute links:

- `skill-finder`
- `eli5`
- `marketing/websites/vinaytalks`
- `triage`

Disco Party rejects extra entries, redirected links, symlinked skill content, hardlinked files, unsafe owners or modes, oversized closures, unsupported file types, and unstable descriptor reads. It hashes every regular file in all four closures, binds the manifest to durable policy, requires `skills/list` to return exactly those four canonical paths, revalidates before each turn, and rechecks immediately after `turn/start`.

The same Vault also supplies the six canonical P0 policy sections. Disco Party locates them by exact heading, rejects missing, reordered, renamed, or additional P0 sections, writes a private mode `0400` derived snapshot, and binds source path and hash plus snapshot path and hash into the Codex policy fingerprint. Codex validates the seal before and after each turn. Claude validates the same seal before its Keychain read at launcher startup and appends the snapshot to listener and Agent subagent system prompts. That Claude prompt inheritance is defense in depth, not deterministic per-turn containment.

Routing behavior is deterministic:

- Every request injects skill-finder so it can search and load the broader canonical Vault library through ordinary full-mode shell and file access.
- ELI5 requests inject both ELI5 and VinayTalks.
- Asset and artifact creation injects VinayTalks.
- Triage requests inject triage.

Full mode automatically uses the canonical Vault `CLAUDE.md` as its hash-bound external trusted instruction file when no separate file is configured. Project documents, bundled skills, apps, plugins, ambient MCP servers, skill search, multi-agent, Browser, and Computer Use remain disabled in the unattended bridge. Skill-finder uses the existing canonical Vault through normal full-access file and shell paths instead of those ambient capability surfaces.

Residual risk remains in full mode because the skill source and worker share one macOS user. Hash checks detect drift at admission and narrow the race, but they are not immutable execution snapshots or OS containment.

## Approval and external-action posture

### Claude

Claude can post an exact draft with native buttons. The router binds the review to the owner, application, guild, bot, channel, message, interaction, action, target, draft SHA-256, binding digest, and expiry. The waiting request consumes the marker and returns a review reference.

That reference does not authorize an outbound side effect. Disco Party installs no sender, and the obsolete marker-watcher service is removed. A future gate must mint and consume a short-lived one-time private receipt under a lock, recompute the exact content and destination, reject replay, keep content out of argv, and hold outbound credentials outside the model process. A separate OS identity is the recommended boundary for a full-access worker.

### Codex

App Server approval requests are denied. Trusted instructions require Codex to return an exact draft or action manifest and wait for a later owner-authenticated message that explicitly approves that exact action, target, and content.

This is a behavioral workflow contract. It is not cryptographic authorization. The restricted profile, deny-only outbound hook, and absence of an installed sender reduce exposure, but high-impact actions still require a deterministic gate outside the model process. Do not enable external sends, financial operations, destructive administration, or unrestricted mode without that boundary.

## Durable execution and duplicate-effect controls

### Codex

- Accepted events enter SQLite before model work.
- Jobs have leases and fencing generations.
- One through four App Server slots run concurrently, default three.
- SQLite claims serialize one Discord destination while allowing independent destinations to overlap.
- A running or uncertain job blocks later work in that same destination.
- Stale or lost workers cannot complete a job after losing ownership.
- Expired running jobs become `uncertain` instead of rerunning automatically.
- Delivery content is persisted before Discord POST.
- Discord nonces are reused only within the supported window.
- Older ambiguous deliveries search destination history for an exact bot, nonce, and content match.
- An unresolved POST is quarantined instead of posted again.
- Policy changes invalidate stale job, thread, session, and delivery routing.

### Claude

- Intake is persisted before dispatch side effects.
- Conversation transcript appends use one-time markers and locks.
- Spawn and delivery states are durable and fail closed on ambiguous effects.
- Public responses use stable Discord nonces and readback reconciliation.
- Legacy takeover drains safe pre-dispatch rows through the normal listener path before committing cutover.
- Ambiguous legacy states require exact count-bound operator acknowledgment and remain preserved for manual review.

No design can undo an arbitrary external action that completed before a process crashed. That is why automatic third-party sends remain disabled.

## Migration and rollback posture

The existing private Claude and Codex services must not run concurrently with replacements that consume the same messages.

The takeover design:

1. Inspects exact legacy labels, commands, processes, databases, and tmux state.
2. Computes a read-only migration plan and digest.
3. Requires exact acknowledgment for ambiguous claimed or dispatched rows.
4. Quiesces the old runtime only inside the maintenance boundary.
5. Creates private SQLite and raw backups plus a reversible row snapshot and manifest.
6. Recomputes the plan after quiesce and refuses drift.
7. Reconciles the Discord gap.
8. Uses a fresh challenge-bound listener handshake to drain all safe pre-dispatch rows.
9. Proves no resumable safe row remains before committing.
10. Starts the replacement and requires fresh readiness.

Once the replacement accepts new work, automatic rollback to the old consumer is forbidden because dual processing could duplicate effects. No live takeover has been performed in this review.

## Monitoring and incident response

Claude:

- `tmux attach -t discoparty-chat` opens the actual listener.
- The healthcheck validates the exact session, directory, command, process tree, and readiness token.

Codex:

- `tmux attach -t discoparty-codex` opens a read-only monitor.
- `PYTHONPATH=. python3 -m codex_discord_bridge.monitor --once` renders one snapshot.
- The monitor shows accepted owner input, job states, and sanitized Codex delivery content.
- Closing the monitor does not stop the LaunchAgent.

Incident priorities:

1. Disable or rotate the affected Discord bot token.
2. Stop only the affected provider after capturing state.
3. Preserve SQLite, logs, readiness state, takeover markers, and process identity.
4. Treat running, spawned, dispatched, attempted, or uncertain work as potentially effectful.
5. Do not rerun ambiguous work automatically.
6. Revoke the isolated ChatGPT login if credential compromise is suspected.
7. Review Discord owner account security and MFA.

## Verification evidence

The following evidence was collected on the local audit branch without changing live services:

- Codex unit suite: 199 passed, 1 opt-in live canary skipped.
- Codex installer scratch, reinstall, rollback, and legacy smoke suite: passed.
- Codex uninstaller suite: passed.
- Earlier real Codex CLI `0.151.0` App Server probe: canonical ELI5 and VinayTalks paths were discovered and explicit skill items were accepted using ChatGPT subscription authentication. The current four-skill bridge and danger-full-access bootstrap remain live release canaries.
- Disposable real Codex CLI `0.151.0` `hooks/list` canary: exactly three enabled user hooks with the sealed commands and matchers, no extra hook, and the expected `untrusted` discovery status under the explicit one-invocation trust bypass.
- Canonical shared-hook guard suite: 5 passed. Command detector suite: 16 passed.
- Claude Gateway suite after heartbeat, redirect, and permission fixes: 179 passed.
- Claude durable queue suite: 114 passed.
- Claude takeover suite: 33 passed.
- Codex direct HTTP and WebSocket transport tests: 6 passed with resource warnings treated as errors.
- Dependency audit: no known vulnerabilities reported from `requirements.txt`.
- Secret scan: three signatures were triaged to a token variable passed into a function, an import beside token-handling code, and an intentionally seeded AWS-shaped test value. No verified production secret was found.
- Static review: no high-severity Bandit finding; medium findings were inspected, with redirect handling producing the real remediation above.
- Independent read-only hook and full-access review confirmed the restricted design, sealed interpreter paths, and exact real-CLI hook discovery. The follow-up owner-parity review enabled full mode behind the exact acknowledgment while separating destination trust from execution authority. Same-user tampering and upstream hook failure remain documented accepted risks for that mode.
- VinayTalks page build: 43 pages built successfully.
- ELI5 page browser QA: desktop and mobile layouts, no horizontal overflow, research disclosure behavior, and console cleanliness checked locally.

These are local audit results. Live authentication, Discord permission, service readiness, concurrency, and message-path canaries remain explicit release gates.

The exact changed-file surface and the reason for each group are recorded in [the implementation inventory](IMPLEMENTATION_INVENTORY_2026-08-29.md).

## Residual risks requiring owner acceptance

| Risk | Current treatment | Can code inside this design eliminate it? |
| --- | --- | --- |
| Same-user full-access compromise | Explicit warning, isolated state, hashes, path checks, no automatic sender | No. Use a separate OS identity or dedicated machine boundary. |
| Owner Discord account takeover | Exact owner binding and recommended MFA | No. Account security and recovery remain external. |
| Public-channel disclosure | Best-effort redact-never-withhold filter, mention suppression, public-safe summaries | No. Public output is not confidential. Use a verified owner-private channel or avoid sensitive work. |
| Discord owner or Administrator thread creation | Exact owner ingress still blocks model execution, but Discord administrators bypass channel overwrites and can expand visible thread inventory | No. Restrict Administrator and guild-owner trust operationally. |
| Policy or skill mutation during an active full-access turn | Derived policy snapshot, source and closure hashes, checks around turns | No. A same-user process can still target user-owned code or attempt a change-and-restore race. Use an OS boundary. |
| Hook launch, timeout, kill, or framework failure | Exact hook allowlist, script-closure binding, `hooks/list` attestation, event monitoring, workspace-write default, explicit owner acknowledgment for full mode | No. Official Hooks are guardrails and can fail open. |
| Prompt injection within allowed authority | Trusted control plane, untrusted content rules, narrow safe mode | No complete guarantee. Reduce authority and add deterministic external gates. |
| Experimental App Server drift | Exact version, binary, schema, and request pins | It can stop unsafe drift, but each upgrade still needs human review. |
| No visual desktop host | Truthful limitation, dynamic tools disabled | Add only through a new reviewed host design. |
| Unknown external effect before crash | Uncertain states and no automatic retry | No generic rollback exists for arbitrary third-party systems. |

## Release gate

Do not activate until every item is complete:

- [x] Final combined unit, installer, syntax, static, dependency, secret, and diff checks pass.
- [ ] The owner approves the exact commit and deployment action.
- [ ] The owner approves the exact Claude maintenance and takeover boundary.
- [ ] The isolated `CODEX_HOME` completes official Sign in with ChatGPT through exact Keychain mode and reports the intended account.
- [ ] No `auth.json` or sibling filesystem credential artifact exists before or after login and live canaries.
- [ ] `OPENAI_API_KEY` is absent.
- [ ] The exact Apple M5 Max, Codex CLI `0.151.0`, native binary, launcher, schema, model, provider, and Ultra pins pass.
- [ ] Claude and Codex use different dedicated bots, Keychain accounts, and channels with their declared trust settings.
- [ ] Both Discord accounts and the ChatGPT account use MFA where available.
- [ ] Codex preflight proves owner, bot, application, guild, channel, permission, and visibility boundaries.
- [ ] The `@everyone` thread deny and exact bot-member Create Public Threads restoration pass, with no role or other-member restoration.
- [ ] Public trust keeps the `@everyone` View baseline effective, or owner-private trust proves the exact `@everyone` View deny, owner and bridge member allows, absence of all other View allows, and absence of every other effective reader.
- [ ] The Codex workspace does not overlap Disco Party control paths or the shared-skill root.
- [ ] The canonical Vault P0 source and private snapshot match the exact bound seal.
- [ ] The canonical hook source closure, private read-only runtime snapshot, manifest, and isolated `hooks.json` match policy, with no path back into a writable root.
- [ ] App Server `hooks/list` reports the exact source, source path, commands, matchers, timeouts, enabled states, current hashes, and expected trust states with no errors, warnings, or extra hooks.
- [ ] A live supported-tool canary proves a deterministic exit-code-2 hook denial, and a simulated hook failure proves the bridge aborts further work while recording the result as potentially effectful.
- [ ] Three configured worker slots become ready, two independent-thread canaries overlap, and same-thread canaries remain ordered.
- [ ] The configuration uses the reviewed restricted permission profile, or danger-full-access passes the exact acknowledgment independently of channel trust.
- [ ] Danger-full-access has a supervised live canary that confirms the external canonical Vault bootstrap and all four bound skills without claiming Browser, Computer Use, ambient MCP, apps, plugins, skill search, or multi-agent support.
- [ ] No outbound sender or obsolete marker-watcher service is loaded.
- [ ] Claude takeover backup, reconciliation, safe-row drain, and readiness complete without ambiguity.
- [ ] An owner message in `#claude` gets an eyes reaction, public thread, and Claude reply.
- [ ] An owner message in `#chatgpt` gets an eyes reaction, public thread, Codex reply, and context-aware follow-up.
- [ ] A non-owner message in `#chatgpt` produces no reaction, thread, job, or model turn.
- [ ] A non-owner message in `#claude` produces no reaction, thread, queue row, or model turn.
- [ ] The Codex monitor shows the owner input, job state, and sanitized delivered reply.
- [ ] Gateway reconnect and process restart canaries preserve continuity without duplicate replies.
- [ ] Sensitive-output canaries demonstrate best-effort redact-never-withhold behavior without treating public output as confidential, and ambiguous-approval canaries fail safely.
- [ ] Rollback conditions and the point after which rollback is forbidden are understood.

## Latest official references checked

- OpenAI Codex App Server: https://learn.chatgpt.com/docs/app-server
- OpenAI Codex Hooks: https://learn.chatgpt.com/docs/hooks
- OpenAI Codex authentication: https://learn.chatgpt.com/docs/auth
- OpenAI permissions: https://learn.chatgpt.com/docs/permissions
- OpenAI Browser: https://learn.chatgpt.com/docs/browser
- OpenAI Computer Use: https://learn.chatgpt.com/docs/computer-use
- OpenAI ChatGPT and Codex changelog, including Codex CLI `0.151.0`: https://learn.chatgpt.com/docs/changelog
- Discord Gateway: https://docs.discord.com/developers/events/gateway
- Discord Gateway events: https://docs.discord.com/developers/events/gateway-events
- Claude Code channels: https://code.claude.com/docs/en/channels
- Claude Code permissions: https://code.claude.com/docs/en/permissions

## Final recommendation

Proceed only after the owner's explicit deployment approval and the remaining live release gates. Workspace-write remains the safer default. Danger-full-access may be staged on a public or owner-private destination only after the exact risk acceptance and supervised canaries. The exact official OpenAI Hooks are valuable shared guardrails, but their documented and tested fail-open cases mean this is accepted same-user risk rather than containment. Public output remains nonconfidential despite best-effort redaction.

For materially stronger containment, run the model worker as a separate macOS user, service identity, or dedicated machine boundary, keep outbound credentials and high-impact capabilities in another service, and expose only narrow one-time operations across that boundary. That changes the design from unrestricted same-user access to brokered capabilities, which is the security property the current request actually needs.
