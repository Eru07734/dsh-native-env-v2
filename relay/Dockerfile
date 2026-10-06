# dsh-native-env-relay
#
# Zero dependencies, so the image is small and there is nothing to audit beyond the
# repository itself. The one subtlety is the LAYOUT: the relay imports the plugin's
# `ws.js` (RFC 6455 framing) and `relay-protocol.js` (the message contract) by
# RELATIVE PATH, which is what keeps one copy of the framing and one copy of the
# contract as the thing that is deployed and tested. `plugins/dsh-native-env-v2/lib/`
# is therefore part of the image, not a build artifact.

FROM node:22-alpine

# Fail loudly rather than silently skipping an install script: there are no
# dependencies, so any install activity at all is a surprise worth seeing.
ENV NODE_ENV=production

WORKDIR /app

# The relative import reaches up out of `relay/`, so both trees are copied.
COPY plugins/dsh-native-env-v2/lib/ /app/plugins/dsh-native-env-v2/lib/
COPY relay/ /app/relay/

# Bind everything: inside a container, 127.0.0.1 is unreachable from outside, and the
# operator's exposure decision belongs to the port mapping and the TLS terminator.
ENV DSH_RELAY_HOST=0.0.0.0 \
    DSH_RELAY_PORT=8931 \
    DSH_RELAY_LOG_LEVEL=info

# Nothing here needs to write to the filesystem, so it runs unprivileged. The image's
# own `node` user exists for exactly this.
USER node

EXPOSE 8931

# The health endpoint is unauthenticated and returns counts only, so it needs no
# credentials and leaks no invite identifiers.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.DSH_RELAY_PORT||8931)+'/healthz').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "/app/relay/main.js"]
