# wallet-verifier — stateless Falcon-512 signature verification for the Edge.
# No secrets, no volumes, no egress; see docs/wallet-bound-aci.md §9.1.
#
# The build RUNS THE TEST SUITE, including the §10 vector gate: an image can
# only be produced from a tree whose tests/vectors/ contains a real signature
# from the wallet and whose miden-crypto pin verifies it. A verifier that never
# met the wallet's exact crypto fails closed on every bind — this makes that
# state unshippable rather than discoverable in production.
#
# OFFLINE build: the wallet's miden-crypto is on a private git host
# (git.softly.com) the builder cannot reach, so dependencies are VENDORED.
# BEFORE building, run on a host that has git.softly.com credentials:
#
#     cd wallet-verifier && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo vendor vendor
#
# which populates ./vendor (git-ignored). The build then compiles fully offline.

FROM rust:1-slim AS build
WORKDIR /src

# Vendored sources + the config that points cargo at them (image-only, so host
# builds are unaffected). Everything below is --offline.
COPY docker/vendor-config.toml ./.cargo/config.toml
COPY vendor ./vendor
COPY Cargo.toml Cargo.lock ./

# Dependency layer: compile the (large) miden-crypto tree once, cache it.
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --offline --locked \
    && rm -rf src

COPY src ./src
COPY tests/vectors ./tests/vectors
RUN touch src/main.rs \
    && cargo test --release --offline --locked \
    && cargo build --release --offline --locked

FROM debian:bookworm-slim
RUN useradd --system --no-create-home --shell /usr/sbin/nologin verifier
COPY --from=build /src/target/release/leviathan-wallet-verifier /usr/local/bin/leviathan-wallet-verifier
USER verifier
ENV WALLET_VERIFIER_BIND=0.0.0.0:8091
EXPOSE 8091
ENTRYPOINT ["/usr/local/bin/leviathan-wallet-verifier"]
