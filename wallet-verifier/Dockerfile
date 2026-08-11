# wallet-verifier — stateless Falcon-512 signature verification for the Edge.
# No secrets, no volumes, no egress; see docs/wallet-bound-aci.md §9.1.
#
# The build RUNS THE TEST SUITE, including the §10 vector gate: an image can
# only be produced from a tree whose tests/vectors/ contains signatures
# captured from the wallet's real @miden-sdk build and whose miden-crypto pin
# parses them. A verifier that never met the wallet's encoding fails closed on
# every bind — this makes that state unshippable rather than discoverable.

FROM rust:1.90-slim AS build
WORKDIR /src

# Dependency layer: compile the (large) miden-crypto tree once, cache it.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
COPY tests/vectors ./tests/vectors
RUN touch src/main.rs \
    && cargo test --release --locked \
    && cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --no-create-home --shell /usr/sbin/nologin verifier
COPY --from=build /src/target/release/leviathan-wallet-verifier /usr/local/bin/leviathan-wallet-verifier
USER verifier
ENV WALLET_VERIFIER_BIND=0.0.0.0:8091
EXPOSE 8091
ENTRYPOINT ["/usr/local/bin/leviathan-wallet-verifier"]
