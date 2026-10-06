# dsh-native-env-v2

This bundle adds an explicit per-session DSH-to-DSH environment bridge while keeping the legacy `env/*` wire compatible.

- `env2/hello`, `env2/list`, `env2/call`, `env2/cancel`, `env2/status`, and `env2/tools-changed` negotiate runtime metadata, capabilities, tool revisions, and message limits.
- TCP, SSH stdio, and pairing continue to use the existing authenticated transport shape.
- A closed or broken wire is fail-closed: pending calls reject, remote shadows are removed, and reconnect never replays an old call or silently uses local tools.
- `dsh-native-env-v2/public` is an opt-in component. It starts an in-process loopback relay and a Cloudflare Quick Tunnel, then advertises only the relay's `wss://…/v2/relay` endpoint. The DSH Web page and browser API are not exposed.
- `dsh-native-env-v2/full` is an opt-in per-profile policy component. Entered sessions re-list their peer and shadow every serializable remote tool; local `env_enter`, `env_exit`, `env_status`, `env_invite` and the registry-reserved `run_code` controls remain local so the session can leave safely.
- The bundle patch is intentionally inert until peers/listeners are configured. The old `dsh-native-env` package remains independent.

Legacy profile discovery is read-only and appears in `env_status` as a copyable migration hint.

Both optional components are disabled by default. Public access uses the pairing invite/device-card credential and the existing v2 end-to-end encrypted channel; it does not add a second Web login. Disabling either row stops the tunnel or returns active session bindings to the normal denylist and does not delete pairing state.

The public/full components require the controller. Public startup downloads the official cloudflared binary into `$DSH_HOME/native-env-v2/bin` when needed (or reuses an installed/pocket binary). `cloudflaredPath` can select an existing executable. It reports ready only after the edge connection is registered; new public DNS names may take time to resolve. The local controller registers invitations and waits for guests over loopback. Turning the component off closes its relay and tunnel and revokes that public relay's invitations. It does not change system firewall or DNS settings.

Full access removes the bridge's default exclusions; it does not elevate OS privileges or bypass the remote runtime's permissions. Profile `exclude` rules still apply. UI, screen, orchestration and attachment tools are forwarded as serialized remote calls; this switch does not add adapters for remote windows, attachment references or local UI prompts. Turning it off immediately blocks queued newly-disallowed calls and refreshes entered sessions; calls already executing remotely can finish under the remote runtime's own cancellation policy.

DSH 0.1.7-rc.2 discovers the browser client from a package-root host row. The bundle therefore mounts the controller via `dsh-native-env-v2` (the `/controller` export remains a compatible alias), so the pairing page and status controls are still loaded after splitting the components.

With the controller enabled, open **Settings → DSH Native Env v2** for pairing, connection status, and the public/full access state. The page uses the same top-level `settings.section` extension as dsh-pocket and follows the plugin lifecycle: disabling the bundle/controller removes the entry, and re-enabling restores it. Component switches remain in the plugin manager.
