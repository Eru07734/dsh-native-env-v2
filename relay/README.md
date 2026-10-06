# dsh-native-env-relay

The rendezvous service for `dsh-native-env-v2`'s pairing transport: it brings two DSH
machines together and then forwards frames it cannot read.

## What this process can and cannot see

This is the only question that matters about a relay, so it is answered first.

| | |
|---|---|
| **Can see** | an invite id, the role names (`host` / `guest`), your IP addresses, when you connected, how much traffic you sent, and the **size and timing** of messages. It also holds the invite secret for the invite's lifetime, because it is the verifier for the rendezvous proof. |
| **Cannot see** | any tool name, argument, file path, file content, tool result, or machine name. Everything after the pairing handshake is AES-256-GCM sealed with a key the relay never receives — the ephemeral X25519 exchange happens inside the forwarded payloads, so the relay could not derive it even if it tried. |

There is no env method name anywhere in this process's code path, and no branch that
inspects a payload beyond its length. `test/relay.test.mjs` asserts this by capturing
what the relay actually forwards and checking that none of it is JSON and none of it
contains the tool argument that was sent.

**What the relay deliberately does not do** is authenticate the two machines to each
other. It authorizes the rendezvous and forwards bytes; the machines authenticate each
other with Ed25519 signatures, and the guest checks the host against the fingerprint
pinned in the invite. A relay that lies, replays, or substitutes its own keys is
therefore DETECTED by the guest rather than trusted. That division is what makes
"self-host a relay, or use someone else's" a tractable choice instead of a leap of
faith.

The relay does hold the invite secret for the invite's lifetime, and that is the
honest caveat: it is enough to join the rendezvous, but **not** enough to impersonate
the host, because it cannot forge the host's signature against the pinned fingerprint.

## Run it

```sh
node main.js
```

It prints the one line an operator needs — the channel base to put in
`relayUrls` — and carries no invite id and no secret. Defaults: bind `127.0.0.1:8931`,
no TLS.

There are no npm dependencies. The relay imports the plugin's own `ws.js` (RFC 6455
framing) and `relay-protocol.js` (the message contract) by **relative path**, so one
copy of each is what is deployed and tested. Keep the repository layout, or copy
`plugins/dsh-native-env-v2/lib/` alongside `relay/` as the Dockerfile does.

## Configure it

Everything comes from the environment, and every default is the conservative one: a
misconfigured `docker run` cannot expose the relay by accident.

| Variable | Default | Meaning |
|---|---|---|
| `DSH_RELAY_HOST` | `127.0.0.1` | Bind address. Set `0.0.0.0` behind a proxy, or the container's address in Docker. |
| `DSH_RELAY_PORT` | `8931` | Bind port. `0` lets the OS choose. |
| `DSH_RELAY_TLS_CERT` / `DSH_RELAY_TLS_KEY` | unset | Serve `wss://` directly instead of behind a proxy. Both or neither. |
| `DSH_RELAY_INVITE_TTL_MS` | `600000` | Default invite lifetime. A client may request less; never more than 7 days. |
| `DSH_RELAY_MAX_FRAME_BYTES` | `1048576` | Per-frame ceiling. An env payload needs ~460 KiB at the default result cap. |
| `DSH_RELAY_MAX_CONNECTIONS` | `512` | Total concurrent connections. |
| `DSH_RELAY_MAX_CONNECTIONS_PER_IP` | `8` | Per-address ceiling. Raise it if a whole site shares one NAT address. |
| `DSH_RELAY_MAX_AUTH_FAILURES_PER_IP` | `20` | Failed rendezvous proofs one address may produce inside the window. **This is what makes a nine-digit device code safe to display**: 10^9 is enumerable, so guessing has to cost something. |
| `DSH_RELAY_AUTH_FAILURE_WINDOW_MS` | `60000` | The window those failures are counted over. |
| `DSH_RELAY_MESSAGES_PER_SECOND` | `400` | Per-connection rate limit (with a one-second burst). |
| `DSH_RELAY_JOIN_TIMEOUT_MS` | `15000` | How long a connection may take to send its `join`. |
| `DSH_RELAY_MAX_INVITES` | `10000` | Concurrent invites. |
| `DSH_RELAY_MAX_HTTP_BODY_BYTES` | `8192` | Registration body ceiling. |
| `DSH_RELAY_TRUST_PROXY` | `0` | Trust `X-Forwarded-For` for logs and per-IP limits. Only set this behind a proxy you control — otherwise a client can forge its own address. |
| `DSH_RELAY_LOG_LEVEL` | `info` | `silent`, `info`, or `debug`. |

## Logging

One JSON object per line. Every field is passed explicitly at the call site, so no
future field can leak into the log by being spread; invite ids are truncated to eight
characters; the invite secret, the payloads, and the full request URL are never
logged. A test asserts that.

## Deploy with Docker

```sh
docker build -f relay/Dockerfile -t dsh-native-env-relay .
docker run -d --name dsh-relay -p 8931:8931 \
  -e DSH_RELAY_HOST=0.0.0.0 \
  -e DSH_RELAY_LOG_LEVEL=info \
  dsh-native-env-relay
```

That serves **plain `ws://`**, which is only acceptable on a network you control. For
anything reachable from the internet, terminate TLS: either mount a certificate and
set `DSH_RELAY_TLS_CERT`/`DSH_RELAY_TLS_KEY`, or put a reverse proxy in front and keep
the relay on `127.0.0.1`.

### Behind nginx

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    # The WebSocket channel. The upgrade headers are what make this a relay rather
    # than a static site; without them the handshake fails with a plain 400.
    location /v2/relay/ {
        proxy_pass http://127.0.0.1:8931;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Invite registration and the health check are ordinary requests.
    location / {
        proxy_pass http://127.0.0.1:8931;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Then run the relay with `DSH_RELAY_TRUST_PROXY=1` so the per-address limits and the
logs see the client's real address.

## Deploy with systemd

See `systemd/dsh-native-env-relay.service`. It assumes a `dsh-relay` user and the
repository at `/opt/dsh-native-env-v2`; adjust both, then:

```sh
sudo systemctl enable --now dsh-native-env-relay
curl -s http://127.0.0.1:8931/healthz
```

`/healthz` is unauthenticated and returns counts only — no invite id, no secret — so a
load balancer can use it without credentials.

## The protocol, briefly

Both ends connect to `/v2/relay/<inviteId>` and speak JSON messages over the
WebSocket:

```
client → relay   join       v, inviteId, role, nonce
relay  → client  challenge  a fresh nonce
client → relay   auth       HMAC-SHA-256(inviteSecret, "relay|inviteId|role|clientNonce|serverNonce")
relay  → client  waiting | ready      (ready once both roles are present)
either way       peer       one OPAQUE payload for the other end
relay  → client  presence   the other end arrived or left
relay  → client  error      invite-unknown | invite-expired | role-taken | auth-failed | …
```

Invites are registered over `POST /v2/invites` with `{ v, inviteId, secret, expiresAt }`.
Registering an id that is already live is refused rather than replacing it — otherwise
anyone who observed an invite id (it travels in the WebSocket path, so a proxy log is
enough) could re-register it with their own secret and take over the rendezvous.

**One exception, and it exists for the device card.** A registration that presents the
same secret is idempotent (a host restarting and reclaiming its own slot), and one that
presents the slot's PREVIOUS secret as `previousSecret` replaces the secret. That second
case is what lets a device code stay STABLE while its password rotates: without it, a
refresh could not reuse the nine-digit code until the old slot expired, which would
defeat the point of a stable code. Neither exception helps an attacker — both require a
secret only the current holder knows.

A role that disconnects frees its slot, and **the slot survives until its TTL**. That
is what makes a dropped connection a reconnect rather than a dead invite. It grants
nothing to an attacker, because claiming a free role still requires the invite secret —
which is exactly the property that makes the invite a credential for its whole
lifetime, and the reason the default TTL is ten minutes.

## Device codes versus invite ids

Both are the same thing to this process: an opaque slot key matched by
`^[0-9a-z]{4,64}$`, paired with a secret that a client must prove. The difference is on
the client side, and it is a security difference the relay should be honest about:

| | |
|---|---|
| **A 32-hex invite id** | comes from a QR code or link whose fragment also carries the host's identity FINGERPRINT, so the guest verifies the host and a hostile relay is detected. |
| **A nine-digit device code** | is typed by a human, so there is nowhere to carry a fingerprint. The two machines instead display a six-digit short code derived from the session key; a relay in the middle derives two different keys, so the two screens disagree and the humans catch it. A user who skips that comparison is trusting the relay. |

The relay's part in the typed mode is the throttle: `DSH_RELAY_MAX_AUTH_FAILURES_PER_IP`
is what stands between a nine-digit code and enumeration. Lower it, not raise it, if you
are unsure. A relay that answered unlimited guesses would make the card unsafe to put on
a screen.

## Test

```sh
node --test test/relay.test.mjs
```

Tests over the real relay, the real WebSocket endpoint, the real pairing
handshake and the real env wire: two machines pair and speak the env protocol; every
forwarded payload is ciphertext; the log contains no secret and no tool argument; an
unknown invite, a wrong secret, a taken role and an expired invite are each refused by
name; a nine-digit device code registers, re-registers idempotently, rotates only with
proof of the previous secret, and is throttled per address after repeated bad guesses.

## Operational notes

- **Memory-only by design.** Invites live for their TTL and no longer, so a restart
  simply forgets every invite — the correct failure mode for a rendezvous service, and
  why clients treat `invite-unknown` as "make a new invite" rather than retrying.
- **One relay, both machines.** Each side must reach the SAME relay, which the invite
  names, so there is no discovery problem and no way for the two ends to end up on
  different hosts.
- **A relay outage does not corrupt anything.** Both clients retry with backoff, and a
  session that had entered a peer fails loudly on its next tool call rather than
  silently running locally.

## License

MIT, like the plugin.
