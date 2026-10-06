# External software

The plugin and relay runtime use Node.js built-in modules and relative imports within this repository. No third-party JavaScript runtime dependency is bundled in this source distribution.

| Software | Use | License / source |
| --- | --- | --- |
| Node.js | Required JavaScript runtime | [Node.js license and bundled component notices](https://github.com/nodejs/node/blob/main/LICENSE) |
| DSH / DeepSeek Harness | Required host application and plugin API | Separately installed; consult the application's own license and distribution terms |
| `qrcode` 1.5.4 | Development-only independent QR encoder used by tests | [MIT](https://github.com/soldair/node-qrcode/blob/master/license); transitive dependency licenses remain in the installed packages |
| `cloudflared` | Optional Cloudflare Quick Tunnel executable, downloaded or selected at runtime by the `public` component | [Apache-2.0](https://github.com/cloudflare/cloudflared/blob/master/LICENSE); [upstream releases](https://github.com/cloudflare/cloudflared/releases) |
| `node:22-alpine` | Optional Docker base image | Consult the image's Node.js, Alpine and included component notices |

The development dependency is pinned in the root manifest and lockfile; `node_modules` is excluded from Git. No DSH installation, Node binary, cloudflared executable, credentials or container image is redistributed here. These separately obtained programs retain their own licenses.

The in-tree QR encoder is accompanied by independent reference comparisons and standard QR arithmetic checks. Tests import `qrcode` only when it is installed as a development dependency; the plugin does not import it at runtime.
