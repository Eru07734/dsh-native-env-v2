/**
 * dsh-native-env-v2 / client — the browser half: pairing, in the Web UI.
 *
 * Three surfaces, each in a slot that already allocates the space it needs:
 *
 *   - `settings.section` — a top-level settings page: connection state, "create an
 *     invite", the QR code, the copyable token, revoke, and the disclaimer gate.
 *   - `sidebar.footer.action` — a compact status pill, so a user can see whether a
 *     machine is paired without opening settings.
 *   - `shell.overlay` — the QR / token modal, a frame-wide layer with no owner,
 *     which is exactly what a modal needs.
 *
 * Everything it shows comes from the host half's authenticated routes
 * (`/api/native-env-v2/v2/...`). This file computes no state of its own and folds no
 * session events: the host decides what is true, the browser renders it.
 *
 * Module format: this is a plain-JavaScript bundle for the harness module loader.
 * It must use `window.__ModuleLoader__.load({ id, factory })` and take its
 * dependencies through the factory's `require`; there is no module resolver in the
 * browser and no bundler here. Only `react` and `react/jsx-runtime` are required —
 * deliberately NOT `@deepseek-ai/dsh-client-ui-primitives`, whose contents change
 * without notice and which this plugin's plain JS cannot type-check. The controls
 * below are written out by hand and styled with the host's theme tokens.
 *
 * The QR modal deliberately lives at module scope as a tiny store rather than in
 * shared context: the page and the overlay are different slots with different
 * owners, and a three-method store is a smaller thing than a context provider that
 * has to be threaded through both.
 */

window.__ModuleLoader__.load({
  id: 'dsh-native-env-v2',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const react = require('react')
    const jsx = require('react/jsx-runtime')

    /** The host half's route prefix; must match `lib/host-api.js`. */
    const API = '/api/native-env-v2/v2'

    /** How often the state is re-read while a page is open. */
    const POLL_MS = 4000

    // ── a tiny shared store for the invite modal ──────────────────────────────
    //
    // The page creates an invite; the overlay draws it. They are separate slot
    // entries with separate owners, so the value they share cannot come from React
    // context. Subscribing to one module-level cell is smaller and has no teardown
    // to get wrong.

    const inviteStore = (() => {
      let value = null
      const listeners = new Set()
      return {
        get: () => value,
        set: (next) => {
          value = next
          for (const listener of listeners) listener(value)
        },
        subscribe: (listener) => {
          listeners.add(listener)
          return () => listeners.delete(listener)
        },
      }
    })()

    /** Subscribe to the invite modal's value. */
    function useInvite() {
      const [value, setValue] = react.useState(inviteStore.get())
      react.useEffect(() => inviteStore.subscribe(setValue), [])
      return value
    }

    // ── data ─────────────────────────────────────────────────────────────────

    /**
     * Read one host API route.
     * @param path - the route path after the prefix.
     * @param options - `{ method, body }`.
     * @returns the parsed JSON body.
     */
    async function call(path, options) {
      const init = { method: options?.method ?? 'GET', headers: { Accept: 'application/json' } }
      if (options?.body !== undefined) {
        init.headers['Content-Type'] = 'application/json'
        init.body = JSON.stringify(options.body)
      }
      const response = await fetch(`${API}${path}`, init)
      const text = await response.text()
      let body
      try {
        body = JSON.parse(text)
      } catch {
        throw new Error(`HTTP ${String(response.status)}: ${text.slice(0, 200)}`)
      }
      if (!response.ok || body?.ok === false) throw new Error(body?.message ?? `HTTP ${String(response.status)}`)
      return body
    }

    /**
     * Poll the host's pairing state while a component is mounted.
     *
     * The poll pauses while the tab is hidden: this is a status display, and waking
     * up to ask about it every four seconds in a background tab is pure cost.
     * @returns `{ state, error, refresh }`.
     */
    function useEnvState(prefix = '') {
      const [value, setValue] = react.useState({ state: null, error: '' })

      const pull = react.useCallback(async () => {
        try {
          const body = await call(`${prefix}/state`)
          setValue({ state: body.state, error: '' })
        } catch (error) {
          setValue((previous) => ({ state: previous.state, error: error instanceof Error ? error.message : String(error) }))
        }
      }, [prefix])

      react.useEffect(() => {
        let alive = true
        const tick = () => {
          if (alive && document.visibilityState !== 'hidden') void pull()
        }
        void pull()
        const timer = window.setInterval(tick, POLL_MS)
        const onVisible = () => {
          if (document.visibilityState === 'visible') void pull()
        }
        document.addEventListener('visibilitychange', onVisible)
        return () => {
          alive = false
          window.clearInterval(timer)
          document.removeEventListener('visibilitychange', onVisible)
        }
      }, [pull])

      return { state: value.state, error: value.error, refresh: pull }
    }

    // ── shared styling helpers ───────────────────────────────────────────────

    /** The host's surface styling, expressed only in theme tokens. */
    const cardStyle = {
      border: '1px solid var(--dsw-alias-border-l1)',
      borderRadius: '10px',
      background: 'var(--dsw-alias-bg-layer-1)',
      padding: '12px 14px',
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
    }

    /** The host's muted label styling. */
    const mutedStyle = { color: 'var(--dsw-alias-label-secondary)', fontSize: '12px' }

    /** A button styled like the host's secondary controls. */
    function buttonStyle(disabled) {
      return {
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: '8px',
        background: 'transparent',
        color: 'var(--dsw-alias-label-primary)',
        padding: '5px 10px',
        fontSize: '12px',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
      }
    }

    /** A primary button, for the one action the page is about. */
    function primaryButtonStyle(disabled) {
      return {
        border: '1px solid var(--dsw-alias-brand-primary)',
        borderRadius: '8px',
        background: 'var(--dsw-alias-brand-primary)',
        color: 'var(--dsw-alias-bg-base)',
        padding: '6px 12px',
        fontSize: '12px',
        fontWeight: 600,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
      }
    }

    /**
     * One row of a key/value list.
     * @param props.label / props.value - the pair.
     * @returns the row element.
     */
    function Row(props) {
      return jsx.jsxs('div', {
        style: { display: 'flex', gap: '10px', alignItems: 'baseline' },
        children: [
          jsx.jsx('span', { style: { ...mutedStyle, minWidth: '104px' }, children: props.label }),
          jsx.jsx('span', { style: { fontSize: '12px', wordBreak: 'break-all' }, children: props.value }),
        ],
      })
    }

    /** A status dot with the state's colour. */
    function Dot(props) {
      const color =
        props.tone === 'ok'
          ? 'var(--dsw-alias-state-success-primary)'
          : props.tone === 'warn'
            ? 'var(--dsw-alias-state-warn-primary)'
            : props.tone === 'error'
              ? 'var(--dsw-alias-state-error-primary)'
              : 'var(--dsw-alias-state-idle-primary)'
      return jsx.jsx('span', {
        style: { width: '7px', height: '7px', borderRadius: '50%', background: color, flex: '0 0 auto', display: 'inline-block' },
      })
    }

    // ── the disclaimer gate ──────────────────────────────────────────────────

    /**
     * The disclaimer, with the accept control.
     *
     * The text is fetched from the host rather than bundled so there is exactly one
     * copy of the wording in the product — a second copy in this file would drift,
     * and the version the user accepted must be the version the host recorded.
     *
     * @param props.onAccepted - called after the acceptance is recorded.
     * @returns the gate element.
     */
    function TermsGate(props) {
      const [text, setText] = react.useState('')
      const [busy, setBusy] = react.useState(false)
      const [error, setError] = react.useState('')

      react.useEffect(() => {
        let alive = true
        call(`${props.apiBase ?? ''}/terms?locale=${encodeURIComponent(typeof navigator === 'undefined' ? '' : navigator.language ?? '')}`)
          .then((body) => {
            if (alive) setText(body.text)
          })
          .catch((failure) => {
            if (alive) setError(failure instanceof Error ? failure.message : String(failure))
          })
        return () => {
          alive = false
        }
      }, [props.apiBase])

      const accept = react.useCallback(async () => {
        setBusy(true)
        setError('')
        try {
          await call(`${props.apiBase ?? ''}/terms/accept`, { method: 'POST', body: { role: props.role ?? 'host' } })
          props.onAccepted?.()
        } catch (failure) {
          setError(failure instanceof Error ? failure.message : String(failure))
        } finally {
          setBusy(false)
        }
      }, [props])

      return jsx.jsxs('div', {
        style: { ...cardStyle, borderColor: 'var(--dsw-alias-state-warn-primary)' },
        children: [
          jsx.jsxs('div', {
            style: { display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600, fontSize: '13px' },
            children: [jsx.jsx(Dot, { tone: 'warn' }), 'Read this before pairing'],
          }),
          jsx.jsx('pre', {
            style: {
              margin: 0,
              maxHeight: '260px',
              overflow: 'auto',
              whiteSpace: 'pre-wrap',
              fontSize: '11px',
              lineHeight: 1.5,
              color: 'var(--dsw-alias-label-secondary)',
              background: 'var(--dsw-alias-bg-layer-2)',
              borderRadius: '8px',
              padding: '10px',
            },
            children: text.length > 0 ? text : 'loading…',
          }),
          error.length > 0 ? jsx.jsx('div', { style: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '12px' }, children: error }) : null,
          jsx.jsx('div', {
            style: { display: 'flex', gap: '8px' },
            children: [
              jsx.jsx('button', { type: 'button', style: primaryButtonStyle(busy || text.length === 0), disabled: busy || text.length === 0, onClick: accept, children: busy ? 'Saving…' : 'I have read this and I accept (使用即表示我已阅读并接受)' }),
            ],
          }),
        ],
      })
    }

    // ── the device card ──────────────────────────────────────────────────────

    /**
     * Fetch and keep one device card.
     *
     * The card is created as soon as the disclaimer has been accepted, without a
     * button press, because that is the remote-desktop model people already have: the
     * machine is reachable, and the password is simply on screen. Refreshing mints a
     * new password while the device code stays put.
     *
     * @param active - whether this half can create a card at all.
     * @returns `{ card, error, busy, create }`.
     */
    function useDeviceCard(active) {
      const [card, setCard] = react.useState(null)
      const [error, setError] = react.useState('')
      const [busy, setBusy] = react.useState(false)

      const create = react.useCallback(async (refresh) => {
        setBusy(true)
        setError('')
        try {
          const body = await call('/device-card', { method: 'POST', body: refresh === true ? { refresh: true } : {} })
          setCard(body.card)
        } catch (failure) {
          setError(failure instanceof Error ? failure.message : String(failure))
        } finally {
          setBusy(false)
        }
      }, [])

      react.useEffect(() => {
        if (!active || card !== null || busy) return
        void create(false)
      }, [active, card, busy, create])

      return { card, error, busy, create }
    }

    /**
     * Seconds until an expiry, updated once a second.
     * @param expiresAt - the epoch ms, or `undefined`.
     * @returns the remaining seconds (never below zero).
     */
    function useCountdown(expiresAt) {
      const [remaining, setRemaining] = react.useState(0)
      react.useEffect(() => {
        if (expiresAt === undefined) return undefined
        const update = () => setRemaining(Math.max(0, Math.round((expiresAt - Date.now()) / 1000)))
        update()
        const timer = window.setInterval(update, 1000)
        return () => window.clearInterval(timer)
      }, [expiresAt])
      return remaining
    }

    /** A copy-to-clipboard button that reports success in place. */
    function CopyButton(props) {
      const [copied, setCopied] = react.useState(false)
      const copy = react.useCallback(async () => {
        try {
          await navigator.clipboard.writeText(props.value)
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1500)
        } catch {
          setCopied(false)
        }
      }, [props.value])
      return jsx.jsx('button', {
        type: 'button',
        style: { ...buttonStyle(false), flex: '0 0 auto' },
        onClick: copy,
        children: copied ? '已复制 Copied' : props.label ?? '复制 Copy',
      })
    }

    /** One big, selectable, monospace value — the thing a human reads off the screen. */
    function BigValue(props) {
      return jsx.jsxs('div', {
        style: { display: 'flex', alignItems: 'center', gap: '8px' },
        children: [
          jsx.jsx('code', {
            style: {
              flex: 1,
              fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
              fontSize: props.small === true ? '16px' : '24px',
              letterSpacing: props.small === true ? '1px' : '2px',
              fontWeight: 600,
              padding: '6px 10px',
              borderRadius: '8px',
              background: 'var(--dsw-alias-bg-layer-2)',
              border: '1px solid var(--dsw-alias-border-l1)',
              userSelect: 'all',
              overflowWrap: 'anywhere',
            },
            children: props.value,
          }),
          jsx.jsx(CopyButton, { value: props.copyValue ?? props.value }),
        ],
      })
    }

    /**
     * The device card and, below it, the optional QR invite.
     *
     * This is the shape a user knows from remote-desktop software: a stable device code,
     * a temporary password next to it, and an expiry. The QR code is demoted to a
     * secondary action because a desktop usually has no camera — and because the QR path
     * is the one that PINS the host, it is offered rather than hidden, with that
     * difference stated.
     *
     * @param props.active - whether this half can create a card.
     * @param props.busy - whether some other action is in flight.
     * @param props.invites - the live QR invites.
     * @param props.onAction - runs one action and refreshes the state.
     * @param props.onShowQr - opens the QR overlay.
     * @returns the panel element.
     */
    function DeviceCardPanel(props) {
      const { card, error, busy, create } = useDeviceCard(props.active)
      const remaining = useCountdown(card?.expiresAt)

      if (!props.active) {
        return jsx.jsxs('div', {
          style: cardStyle,
          children: [
            jsx.jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
              jsx.jsx('span', { style: { fontSize: '13px', fontWeight: 600 }, children: 'Device card / 设备代码' }),
            ] }),
            jsx.jsx('div', {
              style: mutedStyle,
              children:
                'Pairing is not active in this profile, or this half is a guest. Set `mode: pairing` and a `relayUrls` entry on the native-env-v2 row to show a card here.',
            }),
          ],
        })
      }

      const expired = card !== null && remaining <= 0
      return jsx.jsxs('div', {
        style: cardStyle,
        children: [
          jsx.jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
            jsx.jsx('span', { style: { fontSize: '13px', fontWeight: 600 }, children: 'Device card / 设备代码' }),
            jsx.jsxs('span', {
              style: { ...mutedStyle, marginLeft: 'auto', color: expired ? 'var(--dsw-alias-state-error-primary)' : 'var(--dsw-alias-label-secondary)' },
              children: card === null ? '准备中…' : expired ? '密码已过期，请刷新' : `有效期 ${String(Math.floor(remaining / 60))}:${String(remaining % 60).padStart(2, '0')}`,
            }),
          ] }),
          jsx.jsx('div', {
            style: mutedStyle,
            children: '在另一台机器上运行 /env connect，输入下面两个值（或在该机器的设置页里填写）。设备代码固定不变，密码会轮换。',
          }),
          error.length > 0
            ? jsx.jsx('div', { style: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '12px' }, children: error })
            : null,
          card === null
            ? jsx.jsx('div', { style: mutedStyle, children: busy ? '正在创建…' : '(none)' })
            : jsx.jsxs(react.Fragment, {
                children: [
                  jsx.jsxs('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px' }, children: [
                    jsx.jsx('div', { style: { ...mutedStyle, fontWeight: 600 }, children: '设备代码 Device code' }),
                    jsx.jsx(BigValue, { value: card.displayCode }),
                  ] }),
                  jsx.jsxs('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px' }, children: [
                    jsx.jsx('div', { style: { ...mutedStyle, fontWeight: 600 }, children: '临时密码 Password' }),
                    jsx.jsx(BigValue, { value: card.displayPassword, small: true }),
                  ] }),
                  jsx.jsx('div', {
                    style: mutedStyle,
                    children:
                      'The password is a credential until it expires. A typed pairing cannot pin this host the way a QR code does — ' +
                      'compare the short code shown on both machines after connecting.',
                  }),
                ],
              }),
          jsx.jsxs('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap' }, children: [
            jsx.jsx('button', {
              type: 'button',
              style: primaryButtonStyle(busy),
              disabled: busy,
              onClick: () => create(true),
              children: busy ? '刷新中…' : '刷新密码 Refresh password',
            }),
            jsx.jsx('button', {
              type: 'button',
              style: buttonStyle(props.busy),
              disabled: props.busy,
              onClick: () =>
                props.onAction(async () => {
                  const created = await call('/invites', { method: 'POST', body: {} })
                  props.onShowQr({ uri: created.uri, invite: created.invite })
                }),
              children: '扫码配对 Show QR',
            }),
          ] }),
          jsx.jsx('div', {
            style: mutedStyle,
            children:
              'A QR invite carries this host\'s identity fingerprint, so a relay in the middle is detected. Prefer it when the other ' +
              'machine can see a QR code.',
          }),
          props.invites.length > 0
            ? jsx.jsxs('div', {
                style: { display: 'flex', flexDirection: 'column', gap: '6px' },
                children: props.invites.map((invite) =>
                  jsx.jsxs(
                    'div',
                    {
                      style: { display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' },
                      children: [
                        jsx.jsx(Dot, { tone: invite.state === 'waiting-for-peer' ? 'ok' : 'idle' }),
                        jsx.jsx('span', { style: { fontFamily: 'monospace' }, children: invite.mode === 'code' ? invite.deviceCode : invite.inviteIdPrefix }),
                        jsx.jsx('span', { style: mutedStyle, children: `${invite.mode === 'code' ? '设备代码' : '二维码邀请'} · ${invite.state}` }),
                        invite.uri === undefined
                          ? null
                          : jsx.jsx('button', {
                              type: 'button',
                              style: { ...buttonStyle(false), marginLeft: 'auto' },
                              onClick: () => props.onShowQr(invite),
                              children: 'Show QR',
                            }),
                      ],
                    },
                    invite.inviteId,
                  ),
                ),
              })
            : null,
        ],
      })
    }

    /**
     * Join another machine by typing its device code and password.
     *
     * Present on BOTH halves: on a guest it is the only way in, and on a host it lets
     * one machine pair with another host from the same UI.
     *
     * @param props.relay - the relay this machine is configured with, shown because a
     *   typed code cannot name one and the two machines must agree.
     * @returns the form element.
     */
    function JoinByCode(props) {
      const [code, setCode] = react.useState('')
      const [password, setPassword] = react.useState('')
      const [busy, setBusy] = react.useState(false)
      const [message, setMessage] = react.useState('')

      const submit = react.useCallback(async () => {
        setBusy(true)
        setMessage('')
        try {
          const body = await call(`${props.apiBase ?? ''}/join`, { method: 'POST', body: { deviceCode: code, password } })
          setMessage(`已发起配对 · ${body.status?.connected === true ? '已连接' : '连接中…'}`)
        } catch (failure) {
          setMessage(failure instanceof Error ? failure.message : String(failure))
        } finally {
          setBusy(false)
        }
      }, [code, password, props.apiBase])

      return jsx.jsxs('div', {
        style: cardStyle,
        children: [
          jsx.jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
            jsx.jsx('span', { style: { fontSize: '13px', fontWeight: 600 }, children: '用代码连接 / Pair with a code' }),
          ] }),
          jsx.jsx('div', {
            style: mutedStyle,
            children:
              '输入另一台机器上显示的设备代码和临时密码。设备代码需要中继来解析，所以这台机器必须已经配置了同一个中继' +
              (props.relay === undefined ? '（当前未配置）。' : `：${props.relay}。`),
          }),
          jsx.jsxs('div', { style: { display: 'flex', gap: '8px', flexWrap: 'wrap' }, children: [
            jsx.jsx('input', {
              value: code,
              onChange: (event) => setCode(event.target.value),
              placeholder: '123 456 789',
              inputMode: 'numeric',
              'aria-label': 'device code',
              style: { flex: '1 1 140px', padding: '6px 8px', borderRadius: '8px', border: '1px solid var(--dsw-alias-border-l1)', background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--dsw-alias-label-primary)', fontFamily: 'ui-monospace, monospace' },
            }),
            jsx.jsx('input', {
              value: password,
              onChange: (event) => setPassword(event.target.value),
              placeholder: 'XXXX-XXXX-XXXX',
              'aria-label': 'pairing password',
              style: { flex: '1 1 160px', padding: '6px 8px', borderRadius: '8px', border: '1px solid var(--dsw-alias-border-l1)', background: 'var(--dsw-alias-bg-layer-2)', color: 'var(--dsw-alias-label-primary)', fontFamily: 'ui-monospace, monospace' },
            }),
            jsx.jsx('button', {
              type: 'button',
              style: primaryButtonStyle(busy || code.length === 0 || password.length === 0),
              disabled: busy || code.length === 0 || password.length === 0,
              onClick: submit,
              children: busy ? '连接中…' : '连接 Connect',
            }),
          ] }),
          message.length > 0 ? jsx.jsx('div', { style: { ...mutedStyle, userSelect: 'text' }, children: message }) : null,
        ],
      })
    }

    /**
     * The Native Env settings page.
     * @returns the page element.
     */
    function ServerPanel() {
      const { state, error, refresh } = useEnvState('/server')
      if (state === null) return jsx.jsxs('div', {
        style: cardStyle,
        children: [
          jsx.jsx('strong', { children: 'DSH Native Env v2 服务器' }),
          jsx.jsx('div', { style: mutedStyle, children: error.startsWith('HTTP 404')
            ? '服务器未开启，可在插件管理器中启用。'
            : error || '正在读取服务器状态…' }),
        ],
      })
      const guest = state.guest
      return jsx.jsxs('div', { style: cardStyle, children: [
        jsx.jsx('strong', { children: 'DSH Native Env v2 服务器' }),
        jsx.jsx(Row, { label: '服务器状态', value: guest.connected ? '已连接控制器' : '运行中，等待配对' }),
        jsx.jsx(Row, { label: '服务器指纹', value: guest.fingerprint }),
        error ? jsx.jsx('div', { style: mutedStyle, children: error }) : null,
        guest.terms?.accepted === true
          ? jsx.jsx(JoinByCode, { apiBase: '/server', relay: state.relays?.[0] ?? guest.invite?.relay })
          : jsx.jsx(TermsGate, { apiBase: '/server', role: 'guest', onAccepted: refresh }),
      ] })
    }

    function NativeEnvPage() {
      const { state, error, refresh } = useEnvState()
      const [busy, setBusy] = react.useState(false)
      const [actionError, setActionError] = react.useState('')

      const run = react.useCallback(
        async (operation) => {
          setBusy(true)
          setActionError('')
          try {
            await operation()
            await refresh()
          } catch (failure) {
            setActionError(failure instanceof Error ? failure.message : String(failure))
          } finally {
            setBusy(false)
          }
        },
        [refresh],
      )

      if (state === null) {
        return jsx.jsxs('div', {
          style: cardStyle,
          children: [
            jsx.jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'center' }, children: [jsx.jsx(Dot, { tone: error ? 'error' : 'idle' }), 'DSH Native Env v2'] }),
            jsx.jsx('div', { style: mutedStyle, children: error.length > 0 ? error : 'reading the host state…' }),
          ],
        })
      }

      const termsAccepted = state.terms?.accepted === true
      const pairingInactive = state.host === null
      const peers = Array.isArray(state.peers) ? state.peers : []
      const invites = Array.isArray(state.invites) ? state.invites : []
      const connected = peers.filter((peer) => peer.connected)
      const enabled = state.enabled !== false

      return jsx.jsxs('div', {
        style: { display: 'flex', flexDirection: 'column', gap: '12px' },
        children: [
          // ── status ──
          jsx.jsxs('div', {
            style: cardStyle,
            children: [
              jsx.jsxs('div', {
                style: { display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600, fontSize: '13px' },
                children: [
                  jsx.jsx(Dot, { tone: pairingInactive ? 'warn' : connected.length > 0 ? 'ok' : 'idle' }),
                  'DSH Native Env v2',
                  jsx.jsx('span', { style: { ...mutedStyle, marginLeft: 'auto' }, children: state.mode }),
                ],
              }),
              jsx.jsxs('label', {
                style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', marginTop: '8px', cursor: busy ? 'wait' : 'pointer' },
                children: [
                  jsx.jsxs('span', { children: [jsx.jsx('strong', { children: enabled ? 'Enabled' : 'Disabled' }), jsx.jsx('span', { style: { ...mutedStyle, marginLeft: '8px' }, children: 'restart required' })] }),
                  jsx.jsx('input', { type: 'checkbox', checked: enabled, disabled: busy, onChange: (event) => run(() => call('/enabled', { method: 'POST', body: { enabled: event.target.checked } })) }),
                ],
              }),
              jsx.jsx(Row, { label: '公网可连', value: state.public?.phase === 'ready' ? state.public.relay : state.public?.phase === 'error' ? `启动失败：${state.public.error}` : state.public?.enabled ? '正在启动公网入口…' : '关闭' }),
              jsx.jsx(Row, { label: '可完全访问', value: state.fullAccess === true ? '开启（保留本地退出控制及配置排除项）' : '关闭（使用默认工具筛选）' }),
              pairingInactive
                ? jsx.jsx('div', { style: mutedStyle, children: 'Pairing is not active in this profile. Set `mode: pairing` and a `relayUrls` entry on the native-env-v2 row.' })
                : jsx.jsxs(react.Fragment, {
                    children: [
                      jsx.jsx(Row, { label: 'this host', value: `${state.host.label} · ${state.host.fingerprint}` }),
                      jsx.jsx(Row, { label: 'relay', value: (state.host.relays ?? []).join(', ') || '(none configured)' }),
                      jsx.jsx(Row, { label: 'connected', value: connected.length === 0 ? 'no machine is paired' : connected.map((peer) => peer.name).join(', ') }),
                    ],
                  }),
              actionError.length > 0
                ? jsx.jsx('div', { style: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '12px' }, children: actionError })
                : null,
            ],
          }),

          // ── the gate, or the device card ──
          !termsAccepted
            ? jsx.jsx(TermsGate, { onAccepted: refresh })
            : jsx.jsx(DeviceCardPanel, {
                active: state.host !== null,
                busy,
                invites,
                onAction: run,
                onShowQr: (invite) => inviteStore.set({ uri: invite.uri, invite }),
              }),

          // ── this machine joining someone else ──
          jsx.jsx(ServerPanel, {}),

          // ── peers ──
          jsx.jsxs('div', {
            style: cardStyle,
            children: [
              jsx.jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
                jsx.jsx('span', { style: { fontSize: '13px', fontWeight: 600 }, children: 'Paired machines' }),
                jsx.jsx('span', { style: { ...mutedStyle, marginLeft: 'auto' }, children: `${String(connected.length)}/${String(peers.length)} connected` }),
              ] }),
              peers.length === 0
                ? jsx.jsx('div', { style: mutedStyle, children: 'No machine has paired with this host yet.' })
                : peers.map((peer) =>
                    jsx.jsxs(
                      'div',
                      {
                        style: { display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', flexWrap: 'wrap' },
                        children: [
                          jsx.jsx(Dot, { tone: peer.connected ? 'ok' : 'idle' }),
                          jsx.jsx('span', { style: { fontWeight: 600 }, children: peer.name }),
                          jsx.jsx('span', { style: mutedStyle, children: peer.label ?? '' }),
                          jsx.jsx('span', { style: mutedStyle, children: peer.connected ? `${peer.platform ?? '?'} · ${String(peer.toolCount ?? 0)} tools` : (peer.disconnectReason ?? 'offline') }),
                          // The short code a human compares. Marked as unpinned when the
                          // pairing came from a typed card, because that is precisely when
                          // the comparison is load-bearing rather than a belt-and-braces
                          // extra.
                          peer.connected && typeof peer.sas === 'string'
                            ? jsx.jsx('span', {
                                style: { ...mutedStyle, color: peer.pinned === true ? 'var(--dsw-alias-label-secondary)' : 'var(--dsw-alias-state-warn-primary)' },
                                children: peer.pinned === true ? `短码 ${peer.sas}` : `短码 ${peer.sas} · 与对端核对`,
                              })
                            : null,
                          jsx.jsx('button', {
                            type: 'button',
                            style: { ...buttonStyle(busy), marginLeft: 'auto' },
                            disabled: busy,
                            onClick: () => run(async () => call('/peers/revoke', { method: 'POST', body: { peer: peer.name } })),
                            children: 'Forget',
                          }),
                        ],
                      },
                      peer.name,
                    ),
                  ),
              jsx.jsx('div', {
                style: mutedStyle,
                children:
                  'Entering a paired machine runs that session\u2019s read/write/edit/glob/grep and shell tools ON THAT MACHINE, under ITS own approval and sandbox policy.',
              }),
            ],
          }),
        ],
      })
    }

    // ── the sidebar pill ─────────────────────────────────────────────────────

    /**
     * The compact sidebar status.
     * @param props.wide - whether the sidebar is expanded (an owner prop).
     * @returns the pill element.
     */
    function NativeEnvPill(props) {
      const { state } = useEnvState()
      const peers = Array.isArray(state?.peers) ? state.peers : []
      const connected = peers.filter((peer) => peer.connected).length
      const invites = Array.isArray(state?.invites) ? state.invites : []
      const tone = connected > 0 ? 'ok' : invites.length > 0 ? 'warn' : 'idle'
      const label = connected > 0 ? `${String(connected)} paired` : invites.length > 0 ? 'waiting' : 'not paired'
      const title =
        connected > 0
          ? `Native Env: ${peers.filter((peer) => peer.connected).map((peer) => peer.name).join(', ')}`
          : invites.length > 0
            ? 'Native Env: an invite is waiting for the other machine'
            : 'Native Env: no machine is paired'

      return jsx.jsxs('div', {
        title,
        style: {
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: props.wide ? '6px 8px' : '6px',
          fontSize: '11px',
          color: 'var(--dsw-alias-label-secondary)',
          justifyContent: props.wide ? 'flex-start' : 'center',
        },
        children: [jsx.jsx(Dot, { tone }), props.wide ? jsx.jsx('span', { children: `Native Env · ${label}` }) : null],
      })
    }

    // ── the invite modal ─────────────────────────────────────────────────────

    /**
     * The QR / token modal.
     *
     * Rendered from `shell.overlay`, which is click-through: the scrim below opts
     * back into pointer events so the modal is usable and the layer underneath is
     * not made unreachable for anything else that uses it.
     *
     * @returns the modal element or null.
     */
    function InviteOverlay() {
      const value = useInvite()
      const [copied, setCopied] = react.useState(false)
      const [remaining, setRemaining] = react.useState(0)

      const expiresAt = value?.invite?.expiresAt
      react.useEffect(() => {
        if (expiresAt === undefined) return undefined
        const update = () => setRemaining(Math.max(0, Math.round((expiresAt - Date.now()) / 1000)))
        update()
        const timer = window.setInterval(update, 1000)
        return () => window.clearInterval(timer)
      }, [expiresAt])

      const close = react.useCallback(() => {
        setCopied(false)
        inviteStore.set(null)
      }, [])

      react.useEffect(() => {
        if (value === null) return undefined
        // Escape closes it: the same behaviour the host's own modals have, and the
        // reason this is a modal and not a page.
        const onKey = (event) => {
          if (event.key === 'Escape') close()
        }
        document.addEventListener('keydown', onKey)
        return () => document.removeEventListener('keydown', onKey)
      }, [value, close])

      if (value === null) return null

      const copy = async () => {
        try {
          await navigator.clipboard.writeText(value.uri)
          setCopied(true)
        } catch {
          setCopied(false)
        }
      }

      const expired = remaining <= 0

      return jsx.jsxs('div', {
        style: {
          position: 'fixed',
          inset: 0,
          background: 'var(--dsw-alias-bg-overlay)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '24px',
          zIndex: 60,
        },
        onClick: close,
        children: [
          jsx.jsxs('div', {
            onClick: (event) => event.stopPropagation(),
            style: { ...cardStyle, background: 'var(--dsw-alias-bg-layer-1)', maxWidth: '460px', width: '100%' },
            children: [
              jsx.jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
                jsx.jsx('span', { style: { fontSize: '14px', fontWeight: 600 }, children: 'Pairing invite / 配对邀请' }),
                jsx.jsx('button', { type: 'button', style: { ...buttonStyle(false), marginLeft: 'auto' }, onClick: close, children: 'Close' }),
              ] }),
              jsx.jsx('div', {
                style: { ...mutedStyle, color: expired ? 'var(--dsw-alias-state-error-primary)' : 'var(--dsw-alias-label-secondary)' },
                children: expired
                  ? 'This invite has expired. Close this and create a new one.'
                  : `Expires in ${String(Math.floor(remaining / 60))}m ${String(remaining % 60)}s · host ${value.invite?.fingerprint ?? ''}`,
              }),
              // The QR is fetched from the host so the secret is drawn server-side and
              // never has to be handed to a component as an image payload. The white
              // backing is not theming: a QR code needs contrast to be scannable, so
              // it keeps its own colours in both light and dark mode.
              jsx.jsx('div', {
                style: { display: 'flex', justifyContent: 'center', background: '#ffffff', borderRadius: '8px', padding: '10px' },
                children: jsx.jsx('img', {
                  src: `${API}/qr.svg?invite=${encodeURIComponent(value.invite?.inviteId ?? '')}`,
                  width: 260,
                  height: 260,
                  alt: 'Pairing QR code',
                  style: { imageRendering: 'pixelated' },
                }),
              }),
              jsx.jsx('textarea', {
                readOnly: true,
                value: value.uri,
                rows: 3,
                onFocus: (event) => event.target.select(),
                style: {
                  width: '100%',
                  fontFamily: 'monospace',
                  fontSize: '11px',
                  borderRadius: '8px',
                  border: '1px solid var(--dsw-alias-border-l1)',
                  background: 'var(--dsw-alias-bg-layer-2)',
                  color: 'var(--dsw-alias-label-primary)',
                  padding: '8px',
                  resize: 'vertical',
                },
              }),
              jsx.jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'center' }, children: [
                jsx.jsx('button', { type: 'button', style: primaryButtonStyle(false), onClick: copy, children: copied ? 'Copied' : 'Copy token' }),
                jsx.jsx('span', {
                  style: mutedStyle,
                  children: 'Paste it into /env connect on the other machine. Treat it as a password.',
                }),
              ] }),
            ],
          }),
        ],
      })
    }

    /** The client services this module needs. */
    const inject = ['slots']

    /**
     * Register the three surfaces.
     * @param ctx - the client root context.
     */
    function apply(ctx) {
      // Like dsh-pocket, contribute directly to the settings menu. Slot injection
      // scopes this entry to the plugin lifecycle, including disable/re-enable.
      ctx.slots.inject('settings.section', () =>
        ctx.slots.register({ name: 'settings.section', id: 'native-env-v2', order: 2, label: 'DSH Native Env v2' }, NativeEnvPage),
      )
      ctx.slots.inject('sidebar.footer.action', () =>
        ctx.slots.register({ name: 'sidebar.footer.action', id: 'native-env-v2', order: 40, label: 'Native Env v2' }, NativeEnvPill),
      )
      ctx.slots.inject('shell.overlay', () =>
        ctx.slots.register({ name: 'shell.overlay', id: 'native-env-v2-invite', order: 40 }, InviteOverlay),
      )
    }

    exports.apply = apply
    exports.inject = inject
    exports.NativeEnvPage = NativeEnvPage
    exports.NativeEnvPill = NativeEnvPill
    exports.InviteOverlay = InviteOverlay
    exports.inviteStore = inviteStore
    return module.exports
  },
})
