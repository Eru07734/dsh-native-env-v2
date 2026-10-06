/**
 * dsh-native-env / host-api — the pairing surface the Web UI talks to.
 *
 * A QR code has to be displayed somewhere, and the place a user is already looking
 * is the harness Web UI. These routes let the browser half ask the host half for an
 * invite, read the connection state, revoke things, and fetch the QR image — without
 * the browser ever holding a secret it does not need.
 *
 * Authentication is NOT implemented here and that is deliberate: the routes are
 * registered through `connection.fetch`, which applies the harness's own Host/Origin
 * fence and browser authentication before any handler runs. Re-implementing a check
 * here would create a second, weaker gate that a future change could accidentally
 * become the only one.
 *
 * What the routes deliberately never return:
 *
 *   - the pairing secret (it lives only inside the invite URI and the credential
 *     store), so the QR SVG is fetched by INVITE ID and rendered server-side rather
 *     than the URI being handed to the browser to draw;
 *   - any stored identity key material;
 *   - a full relay URL with credentials in it.
 *
 * The state document is a projection, not a dump: every field is named here, so a
 * field added to a peer object cannot leak into the browser by being spread.
 *
 * @module dsh-native-env/host-api
 */

import { renderTermsText, TERMS_VERSION } from './terms.js'

/** The route prefix this plugin owns. */
export const API_PREFIX = '/api/native-env-v2/v2'
/** Server routes must not compete with the controller in the same runtime. */
export const SERVER_API_PREFIX = `${API_PREFIX}/server`

/** A JSON response with no caching. */
function json(body, status = 200) {
  const text = JSON.stringify(body)
  return new Response(text, {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

/** An error response in the shape the client half expects. */
function fail(code, message, status = 400) {
  return json({ ok: false, code, message }, status)
}

/**
 * Read one JSON request body.
 *
 * Bounded on purpose: this endpoint is reachable from a browser, and an unbounded
 * body read is a trivial way to make a host allocate.
 *
 * @param request - the fetch request.
 * @param maxBytes - the ceiling.
 * @returns `{ ok: true, body }` or `{ ok: false, code, message }`.
 */
async function readJsonBody(request, maxBytes = 64 * 1024) {
  let text
  try {
    text = await request.text()
  } catch (error) {
    return { ok: false, code: 'body-unreadable', message: String(error?.message ?? error) }
  }
  if (text.length > maxBytes) return { ok: false, code: 'body-too-large', message: 'the request body is too large' }
  if (text.trim().length === 0) return { ok: true, body: {} }
  try {
    const body = JSON.parse(text)
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      return { ok: false, code: 'bad-body', message: 'the request body must be a JSON object' }
    }
    return { ok: true, body }
  } catch (error) {
    return { ok: false, code: 'bad-body', message: `the request body is not JSON: ${String(error?.message ?? error)}` }
  }
}

/**
 * Register every pairing route.
 *
 * @param options.ctx - the plugin context (needs the `connection` service).
 * @param options.facade - the operations, supplied by whichever half is mounted:
 *   `state()`, `termsStatus()`, `acceptTerms()`, `createInvite()`, `revokeInvite()`,
 *   `revokePeer()`, `inviteSvg()`, and optionally `join()`.
 * @param options.logger - optional `{ info, warn }`.
 * @returns the disposers, or an empty array when the connection service is absent.
 */
export function registerHostApi(options) {
  const { ctx, facade, logger, prefix = API_PREFIX } = options
  const connection = ctx.get?.('connection')
  if (connection === undefined || typeof connection.fetch?.register !== 'function') {
    // Not an error: a headless guest profile has no browser surface at all, and the
    // plugin still works through its commands there.
    logger?.info?.('native-env: the connection service is not mounted, so the pairing Web API is unavailable (commands still work)')
    return []
  }

  const disposers = []
  /** Register one route and keep its disposer. */
  const route = (path, methods, handler, name) => {
    let disposer
    try {
      disposer = connection.fetch.register({ path, methods, requestBody: 'buffered', fetch: handler })
    } catch (error) {
      // Release only this registration attempt, never another component's routes.
      for (const dispose of disposers.splice(0).reverse()) dispose()
      throw error
    }
    disposers.push(() => {
      try { void Promise.resolve(disposer()).catch(() => {}) } catch {}
    })
    logger?.info?.(`native-env: route ${methods.join('/')} ${path} (${name})`)
  }

  route(
    `${prefix}/state`, ['GET'], async () => json({ ok: true, state: await facade.state() }), 'pairing state')

  route(`${prefix}/enabled`, ['POST'], async (request) => {
    const parsed = await readJsonBody(request)
    if (!parsed.ok || typeof parsed.body.enabled !== 'boolean') return fail('bad-enabled', 'enabled must be a boolean')
    if (typeof facade.setEnabled !== 'function') return fail('unsupported', 'Native Env enable switch is unavailable')
    await facade.setEnabled(parsed.body.enabled)
    return json({ ok: true, enabled: parsed.body.enabled, restartRequired: true })
  }, 'enable switch')

  route(
    `${prefix}/terms`,
    ['GET'],
    async (request) => {
      const url = new URL(request.url)
      const locale = url.searchParams.get('locale') ?? ''
      return json({
        ok: true,
        version: TERMS_VERSION,
        status: facade.termsStatus(),
        text: renderTermsText({ locale }),
      })
    },
    'disclaimer text',
  )

  route(
    `${prefix}/terms/accept`,
    ['POST'],
    async (request) => {
      const parsed = await readJsonBody(request)
      if (!parsed.ok) return fail(parsed.code, parsed.message)
      try {
        const record = facade.acceptTerms(parsed.body.role)
        return json({ ok: true, accepted: record })
      } catch (error) {
        return fail('accept-failed', String(error?.message ?? error), 500)
      }
    },
    'accept the disclaimer',
  )

  route(
    `${prefix}/invites`,
    ['POST'],
    async (request) => {
      const parsed = await readJsonBody(request)
      if (!parsed.ok) return fail(parsed.code, parsed.message)
      try {
        const created = await facade.createInvite({ ttlMs: parsed.body.ttlMs })
        // The URI is returned because the user must be able to copy it, but it is
        // the ONLY place in this API a secret appears, and only to the owner of the
        // authenticated browser session that just created it.
        return json({ ok: true, uri: created.uri, invite: created.status })
      } catch (error) {
        return fail(error?.code ?? 'invite-failed', String(error?.message ?? error))
      }
    },
    'create an invite',
  )

  // The device card routes exist only where a device card does: a GUEST half has no
  // `createDeviceCard`, and registering a route that could only ever answer "not
  // supported" would be a worse contract than not having it.
  if (typeof facade.createDeviceCard === 'function') {
    route(
      `${prefix}/device-card`,
      ['POST'],
      async (request) => {
        const parsed = await readJsonBody(request)
        if (!parsed.ok) return fail(parsed.code, parsed.message)
        try {
          const created = await facade.createDeviceCard({ ttlMs: parsed.body.ttlMs, refresh: parsed.body.refresh === true })
          // The password IS returned, and this is the one route where a credential
          // legitimately crosses to the browser: it is the owner's own authenticated
          // session, and a device card nobody can read is not a device card.
          return json({ ok: true, card: created.card, status: created.status })
        } catch (error) {
          return fail(error?.code ?? 'device-card-failed', String(error?.message ?? error))
        }
      },
      'create or refresh a device card',
    )
  }

  route(
    `${prefix}/invites/revoke`,
    ['POST'],
    async (request) => {
      const parsed = await readJsonBody(request)
      if (!parsed.ok) return fail(parsed.code, parsed.message)
      const stopped = facade.revokeInvite(parsed.body.inviteId)
      return json({ ok: true, stopped })
    },
    'revoke an invite',
  )

  route(
    `${prefix}/peers/revoke`,
    ['POST'],
    async (request) => {
      const parsed = await readJsonBody(request)
      if (!parsed.ok) return fail(parsed.code, parsed.message)
      const revoked = await facade.revokePeer(parsed.body.peer)
      return json({ ok: true, revoked })
    },
    'revoke a peer',
  )

  route(
    `${prefix}/qr.svg`,
    ['GET'],
    async (request) => {
      const url = new URL(request.url)
      const svg = facade.inviteSvg(url.searchParams.get('invite') ?? undefined)
      if (svg === undefined) return new Response('no such invite', { status: 404, headers: { 'Cache-Control': 'no-store' } })
      // Served as an image so the browser can render it in an <img>; the markup is
      // generated here and never round-trips through the client.
      return new Response(svg, {
        status: 200,
        headers: { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'no-store' },
      })
    },
    'invite QR code',
  )

  if (typeof facade.join === 'function' || typeof facade.joinWithCode === 'function') {
    route(
      `${prefix}/join`,
      ['POST'],
      async (request) => {
        const parsed = await readJsonBody(request)
        if (!parsed.ok) return fail(parsed.code, parsed.message)
        // One route, two shapes: a pasted URI, or the device code and password a human
        // read off the other machine. The body decides, because requiring two routes
        // would make a UI's "connect" button choose between them instead of the user
        // simply typing what they have.
        const deviceCode = typeof parsed.body.deviceCode === 'string' ? parsed.body.deviceCode : ''
        const password = typeof parsed.body.password === 'string' ? parsed.body.password : ''
        try {
          if (deviceCode.length > 0 || password.length > 0) {
            if (typeof facade.joinWithCode !== 'function') return fail('not-supported', 'this half cannot join with a device code')
            const joined = await facade.joinWithCode({ deviceCode, password })
            return json({ ok: true, status: joined.status })
          }
          if (typeof facade.join !== 'function') return fail('not-supported', 'this half cannot join an invite URI')
          const joined = await facade.join(String(parsed.body.uri ?? ''))
          return json({ ok: true, status: joined.status })
        } catch (error) {
          return fail(error?.code ?? 'join-failed', String(error?.message ?? error))
        }
      },
      'join an invite or a device card',
    )
  }

  return disposers
}
