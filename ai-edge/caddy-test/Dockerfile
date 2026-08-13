# Custom Caddy for the TEST stack: stock Caddy + the DuckDNS DNS provider.
# With the DNS provider it obtains real Let's Encrypt certificates via the
# DNS-01 challenge (a TXT record), so it needs NO inbound :80/:443 — which the
# production Caddy already holds on this host. The test front then serves HTTPS
# on a high port (8443) that production does not use.
FROM caddy:2-builder AS build
RUN xcaddy build --with github.com/caddy-dns/duckdns

FROM caddy:2
COPY --from=build /usr/bin/caddy /usr/bin/caddy
