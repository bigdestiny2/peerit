# Minimal image running the @hyperswarm/dht-relay WebSocket relay. It is a BLIND
# byte pipe: a browser runs a real HyperDHT + Noise session THROUGH it, so it never
# sees plaintext, content, or keys — it only forwards encrypted frames between the
# browser and the public DHT.
#
# Pinned to 0.4.3 (the only published version; upstream flags it do-not-use-in-
# production). peerit treats the in-browser DHT path as best-effort with the /api
# relay as fallback, so a relay hiccup degrades gracefully rather than breaking the app.
FROM node:20-alpine
WORKDIR /app
RUN npm init -y >/dev/null 2>&1 && npm i @hyperswarm/dht-relay@0.4.3 --omit=dev
EXPOSE 49443
# --behind-proxy: trust X-Forwarded-For from Caddy (correct client IPs in logs).
# --host 0.0.0.0: reachable on the private compose network (Caddy proxies to it;
# the port is NOT published to the host — TLS is terminated by Caddy).
ENTRYPOINT ["node", "node_modules/@hyperswarm/dht-relay/bin.js", "--host", "0.0.0.0", "--port", "49443", "--behind-proxy"]
