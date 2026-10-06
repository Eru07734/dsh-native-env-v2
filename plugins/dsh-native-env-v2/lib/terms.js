/**
 * dsh-native-env / terms — the disclaimer a user must acknowledge before pairing.
 *
 * A takeover moves a session's filesystem and shell onto another machine, and the
 * pairing transport reaches that machine through a third-party relay over the open
 * internet. Both halves of that sentence carry consequences a user cannot infer
 * from a button labelled "connect", so the text below states them plainly and the
 * gate is enforced in code rather than in a README nobody opens.
 *
 * Two properties matter about how this file is used:
 *
 *   1. **The version is part of the record.** `TERMS_VERSION` is stored with the
 *      acceptance, so editing this text invalidates every previous acceptance and
 *      the user is asked again. A disclaimer that can be changed after the fact
 *      without re-consent is decoration.
 *   2. **The text is data, not markup.** Both the host API and the browser half
 *      render these strings as text, so there is nothing to escape and no way for
 *      a translation to introduce markup.
 *
 * Editing rules for this file: do not remove a consequence, and bump
 * `TERMS_VERSION` whenever a sentence changes meaning. The English text is the
 * reference; the Chinese text is a translation and must stay equivalent — if the
 * two ever disagree, the difference is a defect.
 *
 * This is a product risk notice, NOT legal advice. Before publishing a public
 * relay, the maintainer must have the final wording reviewed for the relevant
 * jurisdiction and must fill in the operator identity, contact, and governing law,
 * which this file deliberately leaves to the deployment (see `TERMS_OPERATOR`).
 *
 * @module dsh-native-env/terms
 */

/**
 * The version of the wording below.
 *
 * Bump on EVERY change to the text. Stored acceptances carry this value, and a
 * mismatch is what makes the user acknowledge the new wording.
 *
 * Version 2 added the device-code section: a typed pairing trusts the relay in a way
 * a QR pairing does not, and a user who accepted version 1 was never told that.
 */
export const TERMS_VERSION = 2

/**
 * Facts about the operator of the relay a user is about to trust.
 *
 * Left empty on purpose: a template that silently ships a placeholder operator
 * name is worse than one that shows the user that the operator has not identified
 * itself. A deployment fills these in, and a user who sees the `unspecified`
 * values should treat that as the warning it is.
 */
export const TERMS_OPERATOR = Object.freeze({
  /** The legal entity or person operating the relay. */
  entity: '',
  /** How to reach the operator about this service. */
  contact: '',
  /** The jurisdiction whose law the notice is written for. */
  jurisdiction: '',
  /** Where the operator publishes its data-handling policy. */
  privacyUrl: '',
})

/** The placeholder shown for an operator field the deployment left empty. */
export const TERMS_UNSPECIFIED = 'not specified by the relay operator'

/**
 * The consequence sections, one item each.
 *
 * Kept as a list rather than one wall of text so a UI can render them as separate
 * bullets — a disclaimer presented as a single paragraph is one users scroll past.
 */
export const TERMS_SECTIONS_EN = Object.freeze([
  {
    title: 'What this feature does',
    body:
      'It forwards remote tool calls between two DeepSeek Harness instances you control, so that one session\u2019s ' +
      'file and shell tools execute on the OTHER machine. After you enter a peer, that session\u2019s read, write, ' +
      'edit, glob, grep and shell tools keep their names but act on the remote machine.',
  },
  {
    title: 'What the remote machine can reach',
    body:
      'Remote tools can read, create, modify and DELETE files, execute commands with the privileges of the account ' +
      'running the remote harness, and reach whatever that account can reach on its network. Nothing on that machine ' +
      'is protected from a tool call the remote runtime itself permits.',
  },
  {
    title: 'Which policy applies',
    body:
      'Once a session enters a peer, YOUR local approval settings and filesystem sandbox no longer govern those ' +
      'tools: the REMOTE runtime\u2019s own policy does. Tools that only make sense locally (asking you a question, ' +
      'reading an image, delegating to subagents, web access) deliberately stay local.',
  },
  {
    title: 'The invite is a credential',
    body:
      'A pairing QR code or token authorises a connection for as long as it is valid. Anyone who obtains it before ' +
      'it expires may be able to claim the other side of the pairing. Treat it like a password: do not post it, do ' +
      'not leave it on screen, and revoke it when you are done.',
  },
  {
    title: 'What the relay can and cannot see',
    body:
      'The relay carries your connection. It can see your IP addresses, when you connected, how much traffic you ' +
      'sent, and the SIZE and TIMING of messages. It also holds the invite secret for the invite\u2019s lifetime. ' +
      'Everything after the pairing handshake is end-to-end encrypted, so the relay does not receive your tool ' +
      'names, arguments, file paths, file contents or results.',
  },
  {
    title: 'Two ways to pair, and they are not equally strong',
    body:
      'A QR code or invite link carries the host\u2019s identity fingerprint, so the other machine verifies it is talking to ' +
      'the machine you meant even if the relay is hostile. A DEVICE CODE and temporary password cannot carry a fingerprint ' +
      '\u2014 a human types them, so there is nothing to pin \u2014 which means that in that mode you are trusting the RELAY ' +
      'not to sit in the middle. After a device-code pairing, both machines display a six-digit short code: compare them. ' +
      'If they differ, something IS in the middle and you must disconnect. A user who skips that comparison has no ' +
      'protection in that mode beyond the relay\u2019s honesty. Everything the relay forwards is still end-to-end ' +
      'encrypted; what the typed mode cannot prove is WHO is on the other end.',
  },
  {
    title: 'No warranty',
    body:
      'This feature and any relay reachable from it are provided as is, without warranty of any kind. Availability ' +
      'is not guaranteed, and the relay may change, break, rate-limit or disappear without notice. You are ' +
      'responsible for your own key material, relay deployment, TLS configuration, firewall rules, backups, and ' +
      'compliance with the rules that apply to the data you move.',
  },
  {
    title: 'Limitation of liability',
    body:
      'To the maximum extent permitted by applicable law, the authors and operators of this software and relay are ' +
      'not liable for data loss, data disclosure, system damage, service interruption, misuse of credentials, or any ' +
      'indirect or consequential loss arising from use of this feature, even if advised of the possibility.',
  },
  {
    title: 'Your authority to connect',
    body:
      'By continuing you confirm that you are authorised to control BOTH machines and that you accept the risks ' +
      'above. Do not use this in a production or high-sensitivity environment before completing your own security ' +
      'review.',
  },
])

/** The same sections in Chinese. Must stay equivalent to {@link TERMS_SECTIONS_EN}. */
export const TERMS_SECTIONS_ZH = Object.freeze([
  {
    title: '这个功能做什么',
    body:
      '它在你自己控制的两台 DeepSeek Harness 之间转发远程工具调用，让某个会话的文件与 shell 工具在另一台机器上执行。' +
      '进入 peer 之后，该会话的 read、write、edit、glob、grep 与 shell 工具名称不变，但实际作用于远端机器。',
  },
  {
    title: '远端机器能被触及的范围',
    body:
      '远端工具可以读取、创建、修改和删除文件，以远端 harness 运行账号的权限执行命令，并访问该账号在其网络上能访问的一切。' +
      '只要远端运行时自身允许，这台机器上没有任何东西能免于工具调用。',
  },
  {
    title: '适用哪一套策略',
    body:
      '一旦某个会话进入 peer，你本地的审批设置与文件系统沙箱就不再管辖这些工具，改由远端运行时自己的策略管辖。' +
      '只在本地有意义的工具（向你提问、读取图片、委派子代理、联网访问）会有意留在本地。',
  },
  {
    title: '邀请码就是凭据',
    body:
      '配对的二维码或 token 在其有效期内就是一条连接授权。任何在过期前拿到它的人都可能占掉配对的另一侧。' +
      '请像对待密码一样对待它：不要外发、不要留在屏幕上、用完即撤销。',
  },
  {
    title: '中继能看到什么、不能看到什么',
    body:
      '中继承载你的连接。它能看到你的 IP 地址、连接时间、流量大小以及消息的大小与时间特征，并在邀请有效期内持有邀请密钥。' +
      '配对握手之后的一切都是端到端加密的，因此中继不会收到你的工具名、参数、文件路径、文件内容或结果。',
  },
  {
    title: '两种配对方式，强度并不相同',
    body:
      '二维码或邀请链接里带着主机的身份指纹，因此即使中继作恶，另一台机器也能确认自己连的就是你指定的那台。' +
      '而“设备代码 + 临时密码”是人手输入的，无处安放指纹，所以在该模式下你是在信任中继不会插入中间人。' +
      '用设备代码配对成功后，两台机器都会显示一个六位短码：请核对它们是否一致。若不一致，说明确实有人在中间，必须断开。' +
      '跳过这一步的用户，在该模式下除了中继的诚实之外没有任何保护。中继转发的内容仍然是端到端加密的，' +
      '手输模式无法证明的是“对面到底是谁”。',
  },
  {
    title: '不作任何担保',
    body:
      '本功能以及任何可被访问的中继均按现状提供，不附带任何形式的担保。可用性不作保证，中继可能变更、故障、限流或在无通知的情况下消失。' +
      '密钥保管、中继部署、TLS 配置、防火墙规则、备份，以及你所传输数据需要遵守的规定，都由你自己负责。',
  },
  {
    title: '责任限制',
    body:
      '在适用法律允许的最大范围内，本软件与中继的作者及运营者不对数据丢失、数据泄露、系统损坏、服务中断、凭据被滥用，' +
      '以及因使用本功能产生的任何间接或后果性损失承担责任，即使已被告知此类可能性。',
  },
  {
    title: '你确认有权连接',
    body:
      '继续使用即表示你确认自己有权控制这两台机器，并接受上述风险。在完成你自己的安全评估之前，请勿在生产或高敏感环境中使用。',
  },
])

/**
 * Render the notice as plain text for a terminal or a command receipt.
 *
 * @param options.locale - `zh` for Chinese; anything else is English.
 * @param options.includeOperator - whether to append the operator block.
 * @returns the notice as text, one line per paragraph.
 */
export function renderTermsText(options = {}) {
  const chinese = String(options.locale ?? '').toLowerCase().startsWith('zh')
  const sections = chinese ? TERMS_SECTIONS_ZH : TERMS_SECTIONS_EN
  const lines = [
    chinese ? `免责条款与风险提示（版本 ${String(TERMS_VERSION)}）` : `Disclaimer and risk notice (version ${String(TERMS_VERSION)})`,
    '',
  ]
  for (const section of sections) {
    lines.push(chinese ? `【${section.title}】` : `[${section.title}]`)
    lines.push(section.body)
    lines.push('')
  }
  if (options.includeOperator !== false) lines.push(...renderOperatorLines(chinese))
  lines.push(
    chinese
      ? '这是产品风险提示，不构成法律意见。公网发布前须由运营方补齐主体、联系方式、适用法域与隐私政策，并由法律专业人士定稿。'
      : 'This is a product risk notice and not legal advice. Before a public deployment, the operator must fill in its entity, contact, jurisdiction and privacy policy and have the wording finalised by a qualified professional.',
  )
  return lines.join('\n')
}

/**
 * The operator disclosure lines, with placeholders where a deployment left blanks.
 * @param chinese - whether to render in Chinese.
 * @returns the lines.
 */
function renderOperatorLines(chinese) {
  const field = (value) => (String(value ?? '').length > 0 ? String(value) : TERMS_UNSPECIFIED)
  const labels = chinese
    ? { head: '中继运营方', entity: '主体', contact: '联系方式', jurisdiction: '适用法域', privacy: '隐私政策' }
    : { head: 'Relay operator', entity: 'Entity', contact: 'Contact', jurisdiction: 'Jurisdiction', privacy: 'Privacy policy' }
  return [
    labels.head,
    `  ${labels.entity}: ${field(TERMS_OPERATOR.entity)}`,
    `  ${labels.contact}: ${field(TERMS_OPERATOR.contact)}`,
    `  ${labels.jurisdiction}: ${field(TERMS_OPERATOR.jurisdiction)}`,
    `  ${labels.privacy}: ${field(TERMS_OPERATOR.privacyUrl)}`,
    '',
  ]
}

/**
 * Build one acceptance record.
 *
 * The record is deliberately tiny and non-secret: a version, a role, and a time.
 * It is what makes "this user accepted this wording" auditable without storing
 * anything about the user.
 *
 * @param options.role - `host` or `guest`.
 * @param options.now - the clock, injectable for tests.
 * @returns the record to persist.
 */
export function acceptanceRecord(options) {
  return {
    termsVersion: TERMS_VERSION,
    role: options.role === 'guest' ? 'guest' : 'host',
    acceptedAt: Number.isSafeInteger(options.now) ? options.now : Date.now(),
  }
}

/**
 * Whether a stored acceptance still covers the current wording.
 *
 * @param stored - the persisted record, if any.
 * @returns `{ accepted: true }` or `{ accepted: false, reason }`.
 */
export function acceptanceStatus(stored) {
  if (stored === undefined || stored === null || typeof stored !== 'object') {
    return { accepted: false, reason: 'no acceptance has been recorded on this machine' }
  }
  if (stored.termsVersion !== TERMS_VERSION) {
    return {
      accepted: false,
      reason: `the stored acceptance covers version ${String(stored.termsVersion)}; the current wording is version ${String(TERMS_VERSION)}`,
    }
  }
  return { accepted: true, acceptedAt: stored.acceptedAt, role: stored.role }
}
